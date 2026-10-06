//! Fixed-size cells exchanged between client and relay. Every frame, including
//! keepalives, is exactly 1024 bytes. Unused bytes are random.
use crate::crypto::pad_random;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const CELL: usize = 1024;
pub const BLOB: usize = 960;
pub const VERSION: u8 = 1;

pub type Mbox = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Pad,
    Put {
        mbox: Mbox,
        ttl: u32,
        hour: u64,
        nonce: u64,
        blob: Vec<u8>,
    },
    Fetch {
        mbox: Mbox,
        after: u64,
    },
    Take {
        mbox: Mbox,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub rid: u32,
    pub op: Op,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub seq: u64,
    pub hour: u64,
    pub nonce: u64,
    pub more: bool,
    pub blob: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Item(Item),
    Empty,
    Pow(u8),
    Full,
    Bad,
    Pad,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub rid: u32,
    pub status: Status,
}

fn finish(w: Writer) -> [u8; CELL] {
    let mut v = w.finish();
    debug_assert!(v.len() <= CELL);
    pad_random(&mut v, CELL);
    let mut out = [0u8; CELL];
    out.copy_from_slice(&v);
    out
}

impl Request {
    pub fn encode(&self) -> Result<[u8; CELL]> {
        let mut w = Writer::new();
        w.u8(VERSION);
        match &self.op {
            Op::Pad => {
                w.u8(0).u32(self.rid);
            }
            Op::Put {
                mbox,
                ttl,
                hour,
                nonce,
                blob,
            } => {
                if blob.len() != BLOB {
                    return Err(Error::Malformed);
                }
                w.u8(1)
                    .u32(self.rid)
                    .bytes(mbox)
                    .u32(*ttl)
                    .u64(*hour)
                    .u64(*nonce)
                    .bytes(blob);
            }
            Op::Fetch { mbox, after } => {
                w.u8(2).u32(self.rid).bytes(mbox).u64(*after);
            }
            Op::Take { mbox } => {
                w.u8(3).u32(self.rid).bytes(mbox);
            }
        }
        Ok(finish(w))
    }

    pub fn decode(c: &[u8; CELL]) -> Result<Request> {
        let mut r = Reader::new(c);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        let op = r.u8()?;
        let rid = r.u32()?;
        let op = match op {
            0 => Op::Pad,
            1 => Op::Put {
                mbox: r.arr()?,
                ttl: r.u32()?,
                hour: r.u64()?,
                nonce: r.u64()?,
                blob: r.take(BLOB)?.to_vec(),
            },
            2 => Op::Fetch {
                mbox: r.arr()?,
                after: r.u64()?,
            },
            3 => Op::Take { mbox: r.arr()? },
            _ => return Err(Error::Malformed),
        };
        Ok(Request { rid, op })
    }
}

impl Response {
    pub fn encode(&self) -> [u8; CELL] {
        let mut w = Writer::new();
        w.u8(VERSION).u8(0).u32(self.rid);
        match &self.status {
            Status::Ok => {
                w.u8(0);
            }
            Status::Item(it) => {
                w.u8(1)
                    .u64(it.seq)
                    .u64(it.hour)
                    .u64(it.nonce)
                    .u8(it.more as u8)
                    .bytes(&it.blob);
            }
            Status::Empty => {
                w.u8(2);
            }
            Status::Pow(n) => {
                w.u8(3).u8(*n);
            }
            Status::Full => {
                w.u8(4);
            }
            Status::Bad => {
                w.u8(5);
            }
            Status::Pad => {
                w.u8(6);
            }
        }
        finish(w)
    }

    pub fn decode(c: &[u8; CELL]) -> Result<Response> {
        let mut r = Reader::new(c);
        if r.u8()? != VERSION {
            return Err(Error::Malformed);
        }
        r.u8()?;
        let rid = r.u32()?;
        let status = match r.u8()? {
            0 => Status::Ok,
            1 => Status::Item(Item {
                seq: r.u64()?,
                hour: r.u64()?,
                nonce: r.u64()?,
                more: r.u8()? != 0,
                blob: r.take(BLOB)?.to_vec(),
            }),
            2 => Status::Empty,
            3 => Status::Pow(r.u8()?),
            4 => Status::Full,
            5 => Status::Bad,
            6 => Status::Pad,
            _ => return Err(Error::Malformed),
        };
        Ok(Response { rid, status })
    }
}

/// Build a blob of exactly [`BLOB`] bytes: content then random fill.
pub fn blob(content: &[u8]) -> Result<Vec<u8>> {
    if content.len() > BLOB {
        return Err(Error::TooLong);
    }
    let mut v = content.to_vec();
    pad_random(&mut v, BLOB);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            Just(Op::Pad),
            (
                any::<[u8; 32]>(),
                any::<u32>(),
                any::<u64>(),
                any::<u64>(),
                proptest::collection::vec(any::<u8>(), BLOB..=BLOB)
            )
                .prop_map(|(mbox, ttl, hour, nonce, blob)| Op::Put {
                    mbox,
                    ttl,
                    hour,
                    nonce,
                    blob
                }),
            (any::<[u8; 32]>(), any::<u64>()).prop_map(|(mbox, after)| Op::Fetch { mbox, after }),
            any::<[u8; 32]>().prop_map(|mbox| Op::Take { mbox }),
        ]
    }

    proptest! {
        /// Fixed-cell invariant: every request is exactly CELL bytes and round-trips.
        #[test]
        fn requests_fixed_size(rid in any::<u32>(), op in arb_op()) {
            let req = Request { rid, op };
            let c = req.encode().unwrap();
            prop_assert_eq!(c.len(), CELL);
            prop_assert_eq!(Request::decode(&c).unwrap(), req);
        }

        #[test]
        fn responses_fixed_size(rid in any::<u32>(), seq in any::<u64>(), n in any::<u8>(), blob in proptest::collection::vec(any::<u8>(), BLOB..=BLOB)) {
            for status in [Status::Ok, Status::Empty, Status::Pow(n), Status::Full, Status::Bad, Status::Pad,
                Status::Item(Item { seq, hour: seq ^ 1, nonce: seq ^ 2, more: n & 1 == 1, blob: blob.clone() })] {
                let resp = Response { rid, status };
                let c = resp.encode();
                prop_assert_eq!(c.len(), CELL);
                prop_assert_eq!(Response::decode(&c).unwrap(), resp);
            }
        }

        #[test]
        fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), CELL..=CELL)) {
            let mut c = [0u8; CELL];
            c.copy_from_slice(&bytes);
            let _ = Request::decode(&c);
            let _ = Response::decode(&c);
        }
    }

    #[test]
    fn padding_is_random() {
        let a = Request {
            rid: 1,
            op: Op::Pad,
        }
        .encode()
        .unwrap();
        let b = Request {
            rid: 1,
            op: Op::Pad,
        }
        .encode()
        .unwrap();
        assert_eq!(a[..6], b[..6]);
        assert_ne!(a[6..], b[6..]);
        assert_eq!(blob(b"x").unwrap().len(), BLOB);
        assert!(blob(&[0; BLOB + 1]).is_err());
    }
}
