//! Mailbox store kept in RAM only. Items are removed when their TTL expires.
//! Every put requires proof of work. The required difficulty rises with the put
//! rate on each mailbox.
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use eigen_core::cell::{Item, Mbox, Op, Status, BLOB};
use eigen_core::pow;

#[derive(Clone, Debug)]
pub struct Config {
    pub pow_base: u8,
    pub max_ttl: u32,
    pub per_mailbox: usize,
    pub max_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            pow_base: 12,
            max_ttl: 24 * 3600,
            per_mailbox: 256,
            max_items: 65536,
        }
    }
}

struct Stored {
    seq: u64,
    expiry: Instant,
    hour: u64,
    nonce: u64,
    blob: Vec<u8>,
}

#[derive(Default)]
struct Mailbox {
    items: VecDeque<Stored>,
    recent: VecDeque<Instant>,
}

pub struct Store {
    cfg: Config,
    boxes: HashMap<Mbox, Mailbox>,
    seen: HashMap<[u8; 32], Instant>,
    total: usize,
    seq: u64,
}

impl Store {
    pub fn new(cfg: Config) -> Store {
        Store {
            cfg,
            boxes: HashMap::new(),
            seen: HashMap::new(),
            total: 0,
            seq: 0,
        }
    }

    pub fn items(&self) -> usize {
        self.total
    }

    /// Required proof-of-work difficulty, in bits. It rises by 2 bits each time the
    /// put rate on the mailbox doubles.
    pub fn required(&self, mbox: &Mbox) -> u8 {
        let n = self.boxes.get(mbox).map(|m| m.recent.len()).unwrap_or(0) as u32;
        let extra = 2 * (32 - (1 + n / 16).leading_zeros() - 1);
        (self.cfg.pow_base as u32 + extra).min(30) as u8
    }

    pub fn handle(&mut self, op: Op) -> Status {
        self.handle_at(op, Instant::now(), pow::hour_now())
    }

    pub fn handle_at(&mut self, op: Op, now: Instant, hour_now: u64) -> Status {
        match op {
            Op::Pad => Status::Pad,
            Op::Put {
                mbox,
                ttl,
                hour,
                nonce,
                blob,
            } => {
                if blob.len() != BLOB || !(hour == hour_now || hour + 1 == hour_now) || ttl == 0 {
                    return Status::Bad;
                }
                if let Some(m) = self.boxes.get_mut(&mbox) {
                    while m
                        .recent
                        .front()
                        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
                    {
                        m.recent.pop_front();
                    }
                }
                let need = self.required(&mbox);
                let tag = pow::tag(hour, &mbox, &blob, nonce);
                if pow::leading_zeros(&tag) < need as u32 {
                    return Status::Pow(need);
                }
                if self.seen.contains_key(&tag) {
                    return Status::Ok; // Replay: report success and store nothing.
                }
                if self.total >= self.cfg.max_items {
                    return Status::Full;
                }
                let ttl = Duration::from_secs(ttl.min(self.cfg.max_ttl) as u64);
                self.seq += 1;
                let m = self.boxes.entry(mbox).or_default();
                m.recent.push_back(now);
                if m.items.len() >= self.cfg.per_mailbox {
                    m.items.pop_front();
                    self.total -= 1;
                }
                m.items.push_back(Stored {
                    seq: self.seq,
                    expiry: now + ttl,
                    hour,
                    nonce,
                    blob,
                });
                self.total += 1;
                self.seen.insert(tag, now + ttl);
                Status::Ok
            }
            Op::Fetch { mbox, after } => {
                let Some(m) = self.boxes.get(&mbox) else {
                    return Status::Empty;
                };
                let mut it = m.items.iter().filter(|s| s.seq > after && s.expiry > now);
                match it.next() {
                    Some(s) => Status::Item(Item {
                        seq: s.seq,
                        hour: s.hour,
                        nonce: s.nonce,
                        more: it.next().is_some(),
                        blob: s.blob.clone(),
                    }),
                    None => Status::Empty,
                }
            }
            Op::Take { mbox } => {
                let Some(m) = self.boxes.get_mut(&mbox) else {
                    return Status::Empty;
                };
                while let Some(s) = m.items.pop_front() {
                    self.total -= 1;
                    if s.expiry > now {
                        let more = !m.items.is_empty();
                        return Status::Item(Item {
                            seq: s.seq,
                            hour: s.hour,
                            nonce: s.nonce,
                            more,
                            blob: s.blob,
                        });
                    }
                }
                Status::Empty
            }
        }
    }

    /// Removes expired items. Their data is overwritten with zeros before the
    /// memory is released.
    pub fn sweep(&mut self) {
        self.sweep_at(Instant::now());
    }

    pub fn sweep_at(&mut self, now: Instant) {
        let mut removed = 0;
        self.boxes.retain(|_, m| {
            m.items.retain_mut(|s| {
                let keep = s.expiry > now;
                if !keep {
                    s.blob.iter_mut().for_each(|b| *b = 0);
                    removed += 1;
                }
                keep
            });
            m.recent
                .retain(|t| now.duration_since(*t) <= Duration::from_secs(60));
            !m.items.is_empty() || !m.recent.is_empty()
        });
        self.total -= removed;
        self.seen.retain(|_, e| *e > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(s: &mut Store, mbox: Mbox, ttl: u32, now: Instant) -> Status {
        let blob = eigen_core::cell::blob(b"x").unwrap();
        let hour = 100;
        let bits = s.required(&mbox);
        let nonce = pow::solve(hour, &mbox, &blob, bits);
        s.handle_at(
            Op::Put {
                mbox,
                ttl,
                hour,
                nonce,
                blob,
            },
            now,
            hour,
        )
    }

    #[test]
    fn put_fetch_take_and_expire() {
        let mut s = Store::new(Config {
            pow_base: 4,
            ..Config::default()
        });
        let t0 = Instant::now();
        let m = [1u8; 32];
        assert_eq!(put(&mut s, m, 60, t0), Status::Ok);
        assert_eq!(put(&mut s, m, 60, t0), Status::Ok);
        let Status::Item(a) = s.handle_at(Op::Fetch { mbox: m, after: 0 }, t0, 100) else {
            panic!()
        };
        assert!(a.more);
        let Status::Item(b) = s.handle_at(
            Op::Fetch {
                mbox: m,
                after: a.seq,
            },
            t0,
            100,
        ) else {
            panic!()
        };
        assert!(!b.more);
        assert_eq!(
            s.handle_at(
                Op::Fetch {
                    mbox: m,
                    after: b.seq
                },
                t0,
                100
            ),
            Status::Empty
        );
        assert!(matches!(
            s.handle_at(Op::Take { mbox: m }, t0, 100),
            Status::Item(_)
        ));
        assert_eq!(s.items(), 1);
        s.sweep_at(t0 + Duration::from_secs(61));
        assert_eq!(s.items(), 0);
        assert_eq!(
            s.handle_at(Op::Fetch { mbox: m, after: 0 }, t0, 100),
            Status::Empty
        );
    }

    #[test]
    fn pow_enforced_and_rises() {
        let mut s = Store::new(Config {
            pow_base: 8,
            ..Config::default()
        });
        let m = [2u8; 32];
        let blob = eigen_core::cell::blob(b"y").unwrap();
        let t0 = Instant::now();
        // Find a nonce that fails 8 bits.
        let mut nonce = 0;
        while pow::check(100, &m, &blob, nonce, 8) {
            nonce += 1;
        }
        assert_eq!(
            s.handle_at(
                Op::Put {
                    mbox: m,
                    ttl: 9,
                    hour: 100,
                    nonce,
                    blob: blob.clone()
                },
                t0,
                100
            ),
            Status::Pow(8)
        );
        // Stale hour is refused.
        assert_eq!(
            s.handle_at(
                Op::Put {
                    mbox: m,
                    ttl: 9,
                    hour: 90,
                    nonce,
                    blob
                },
                t0,
                100
            ),
            Status::Bad
        );
        for _ in 0..48 {
            put(&mut s, m, 60, t0);
        }
        assert!(s.required(&m) >= 12);
    }

    #[test]
    fn replay_not_stored_twice() {
        let mut s = Store::new(Config {
            pow_base: 4,
            ..Config::default()
        });
        let m = [3u8; 32];
        let blob = eigen_core::cell::blob(b"z").unwrap();
        let nonce = pow::solve(100, &m, &blob, 6);
        let t0 = Instant::now();
        for _ in 0..3 {
            s.handle_at(
                Op::Put {
                    mbox: m,
                    ttl: 9,
                    hour: 100,
                    nonce,
                    blob: blob.clone(),
                },
                t0,
                100,
            );
        }
        assert_eq!(s.items(), 1);
    }
}
