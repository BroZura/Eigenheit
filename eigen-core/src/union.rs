//! Unions: groups defined by a shared secret. Control messages are sealed under a key
//! derived from the secret. Content uses a sender-key chain per member. Each
//! message is signed with the sender's mask key, so no member can send messages
//! in another member's name.
use std::collections::HashMap;

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::cell::{blob, Mbox};
use crate::crypto::{aead_open, aead_seal, h, kdf32, mac, open_fixed, random, seal_fixed};
use crate::identity::{Mask, Who};
use crate::ratchet::MessageKey;
use crate::wire::{base32, unbase32, Reader, Writer};
use crate::{Error, Result};

pub const T_UNION: u8 = 0x10;
pub const UNION_TEXT_MAX: usize = 560;
const SEAL: usize = 880;
const MSG_PAD: usize = 576;
pub const SKEY_PER_MSG: usize = 12;
pub const MAX_SKIP: u32 = 256;
pub const INVITE_PREFIX: &str = "eigen://union/";
pub const DEFAULT_POW: u8 = 14;
pub const JOIN_EXTRA: u8 = 6;

pub struct UnionKeys {
    secret: Zeroizing<[u8; 32]>,
    pub uid: [u8; 32],
    ctrl: Zeroizing<[u8; 32]>,
    pub pow: u8,
}

impl UnionKeys {
    fn from_secret(secret: [u8; 32], pow: u8) -> UnionKeys {
        let ctrl = kdf32(&[0u8; 32], &secret, b"eigen/union-ctrl");
        UnionKeys {
            uid: h(&[b"eigen/uid", &secret]),
            secret: Zeroizing::new(secret),
            ctrl,
            pow,
        }
    }
    pub fn generate(pow: u8) -> UnionKeys {
        Self::from_secret(random(), pow)
    }
    /// Derive the union keys from a passphrase with Argon2id (64 MiB, t=3). The
    /// derivation is slow by design.
    pub fn from_passphrase(pass: &str) -> Result<UnionKeys> {
        let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| Error::Unknown)?;
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        a.hash_password_into(pass.trim().as_bytes(), b"eigen/union-pass/v1", &mut out)
            .map_err(|_| Error::Unknown)?;
        let k = Self::from_secret(out, DEFAULT_POW);
        out.zeroize();
        Ok(k)
    }
    pub fn invite(&self) -> String {
        let mut w = Writer::new();
        w.bytes(&self.secret[..]).u8(self.pow);
        let c = h(&[b"eigen/invite", &w.0]);
        w.bytes(&c[..3]);
        let s = format!("{INVITE_PREFIX}{}", base32(&w.0));
        w.0.zeroize();
        s
    }
    pub fn parse_invite(s: &str) -> Result<UnionKeys> {
        let body = s
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or(Error::Malformed)?;
        let mut raw = Zeroizing::new(unbase32(body)?);
        if raw.len() != 36 || h(&[b"eigen/invite", &raw[..33]])[..3] != raw[33..] {
            return Err(Error::Malformed);
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&raw[..32]);
        let pow = raw[32].clamp(8, 28);
        raw.zeroize();
        Ok(Self::from_secret(sec, pow))
    }
    /// Public identity of the union, derived from the union id. It reveals nothing about
    /// the secret.
    pub fn face(&self) -> Who {
        Who(self.uid)
    }
    /// Mailbox for a given hour. Without the secret, mailboxes of different hours cannot
    /// be linked.
    pub fn mbox(&self, hour: u64) -> Mbox {
        mac(&self.secret[..], &[b"eigen/umbox", &hour.to_be_bytes()])
    }
    pub fn seal(&self, mbox: &Mbox, inner: &[u8]) -> Result<Vec<u8>> {
        let mut v = vec![T_UNION];
        v.extend(seal_fixed(&self.ctrl, inner, SEAL, mbox)?);
        blob(&v)
    }
    pub fn open(&self, mbox: &Mbox, b: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if b.len() < 1 + SEAL + 40 || b[0] != T_UNION {
            return Err(Error::Malformed);
        }
        open_fixed(&self.ctrl, &b[1..1 + SEAL + 40], mbox)
    }
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
    pub fn from_saved(secret: [u8; 32], pow: u8) -> UnionKeys {
        Self::from_secret(secret, pow)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Join {
        mx: [u8; 32],
        /// Time of the announcement. Old JOINs replayed by the relay are ignored.
        at: u64,
    },
    Hello {
        mx: [u8; 32],
        ends_at: u64,
        term: u32,
        to: Who,
    },
    Skey {
        gen: u32,
        eph: [u8; 32],
        entries: Vec<([u8; 8], Vec<u8>)>,
    },
    Msg {
        gen: u32,
        idx: u32,
        ct: Vec<u8>,
    },
    Leave,
    Renew {
        term: u32,
    },
    Drop {
        target: Who,
        term: u32,
    },
    /// A fresh union secret for the remaining members (after a roster shrink).
    Rekey {
        epoch: u32,
        eph: [u8; 32],
        entries: Vec<([u8; 8], Vec<u8>)>,
    },
}

impl Body {
    fn kind(&self) -> u8 {
        match self {
            Body::Join { .. } => 1,
            Body::Hello { .. } => 2,
            Body::Skey { .. } => 3,
            Body::Msg { .. } => 4,
            Body::Leave => 5,
            Body::Renew { .. } => 6,
            Body::Drop { .. } => 7,
            Body::Rekey { .. } => 8,
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Body::Join { mx, at } => {
                w.bytes(mx).u64(*at).bytes(&random::<8>());
            }
            Body::Hello {
                mx,
                ends_at,
                term,
                to,
            } => {
                w.bytes(mx).u64(*ends_at).u32(*term).bytes(&to.0);
            }
            Body::Skey { gen, eph, entries }
            | Body::Rekey {
                epoch: gen,
                eph,
                entries,
            } => {
                w.u32(*gen).bytes(eph).u8(entries.len() as u8);
                for (t, c) in entries {
                    w.bytes(t).bytes(c);
                }
            }
            Body::Msg { gen, idx, ct } => {
                w.u32(*gen).u32(*idx).var(ct);
            }
            Body::Leave => {
                w.bytes(&random::<16>());
            }
            Body::Renew { term } => {
                w.u32(*term);
            }
            Body::Drop { target, term } => {
                w.bytes(&target.0).u32(*term);
            }
        }
        w.finish()
    }
    fn decode(kind: u8, b: &[u8]) -> Result<Body> {
        let mut r = Reader::new(b);
        Ok(match kind {
            1 => Body::Join {
                mx: r.arr()?,
                at: r.u64()?,
            },
            2 => Body::Hello {
                mx: r.arr()?,
                ends_at: r.u64()?,
                term: r.u32()?,
                to: Who(r.arr()?),
            },
            3 | 8 => {
                let gen = r.u32()?;
                let eph = r.arr()?;
                let n = r.u8()? as usize;
                let size = if kind == 3 { SKEY_CT } else { REKEY_CT };
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push((r.arr()?, r.take(size)?.to_vec()));
                }
                if kind == 3 {
                    Body::Skey { gen, eph, entries }
                } else {
                    Body::Rekey {
                        epoch: gen,
                        eph,
                        entries,
                    }
                }
            }
            4 => Body::Msg {
                gen: r.u32()?,
                idx: r.u32()?,
                ct: r.var()?.to_vec(),
            },
            5 => Body::Leave,
            6 => Body::Renew { term: r.u32()? },
            7 => Body::Drop {
                target: Who(r.arr()?),
                term: r.u32()?,
            },
            _ => return Err(Error::Malformed),
        })
    }
}

const SKEY_CT: usize = 36 + 16;
const REKEY_CT: usize = 32 + 16;

fn sig_input(uid: &[u8; 32], kind: u8, from: &Who, body: &[u8]) -> Vec<u8> {
    [&b"eigen/union"[..], uid, &[kind], &from.0, body].concat()
}

/// `kind ‖ from ‖ len ‖ body ‖ sig`
pub fn sign(mask: &Mask, uid: &[u8; 32], body: &Body) -> Vec<u8> {
    let (k, from, b) = (body.kind(), mask.who(), body.encode());
    let sig = mask.sign(&sig_input(uid, k, &from, &b));
    let mut w = Writer::new();
    w.u8(k).bytes(&from.0).var(&b).bytes(&sig);
    w.finish()
}

pub fn verify(uid: &[u8; 32], inner: &[u8]) -> Result<(Who, Body)> {
    let mut r = Reader::new(inner);
    let k = r.u8()?;
    let from = Who(r.arr()?);
    let b = r.var()?;
    let sig: [u8; 64] = r.arr()?;
    from.verify(&sig_input(uid, k, &from, b), &sig)?;
    Ok((from, Body::decode(k, b)?))
}

fn tag(who: &Who) -> [u8; 8] {
    let mut t = [0u8; 8];
    t.copy_from_slice(&h(&[b"eigen/skey-tag", &who.0])[..8]);
    t
}

fn entry_key(dh: &[u8; 32], uid: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    kdf32(&[0u8; 32], dh, &[&b"eigen/skey"[..], uid].concat())
}

/// The local sending chain in a union.
pub struct SenderChain {
    pub gen: u32,
    ck: [u8; 32],
    pub idx: u32,
}

impl Drop for SenderChain {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

fn step(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (mac(ck, &[b"ck"]), mac(ck, &[b"mk"]))
}

fn msg_ad(uid: &[u8; 32], from: &Who, gen: u32, idx: u32) -> Vec<u8> {
    [&uid[..], &from.0, &gen.to_be_bytes(), &idx.to_be_bytes()].concat()
}

impl SenderChain {
    pub fn fresh(gen: u32) -> SenderChain {
        SenderChain {
            gen,
            ck: random(),
            idx: 0,
        }
    }

    /// SKEY bodies that distribute the *current* chain position to `to` (who, member key).
    pub fn distribute(&self, uid: &[u8; 32], to: &[(Who, [u8; 32])]) -> Vec<Body> {
        to.chunks(SKEY_PER_MSG)
            .map(|chunk| {
                let eph = StaticSecret::random_from_rng(rand_core::OsRng);
                let mut pt = Zeroizing::new(Vec::with_capacity(36));
                pt.extend_from_slice(&self.ck);
                pt.extend_from_slice(&self.idx.to_be_bytes());
                let entries = chunk
                    .iter()
                    .map(|(who, mx)| {
                        let dh = eph.diffie_hellman(&PublicKey::from(*mx)).to_bytes();
                        // Fresh ephemeral per SKEY: each entry key is single-use, so a zero nonce is safe.
                        (
                            tag(who),
                            aead_seal(
                                &entry_key(&dh, uid),
                                &[0u8; 24],
                                &pt,
                                &self.gen.to_be_bytes(),
                            ),
                        )
                    })
                    .collect();
                Body::Skey {
                    gen: self.gen,
                    eph: PublicKey::from(&eph).to_bytes(),
                    entries,
                }
            })
            .collect()
    }

    pub fn encrypt(
        &mut self,
        uid: &[u8; 32],
        me: &Who,
        kind: u8,
        id: [u8; 8],
        text: &str,
    ) -> Result<Body> {
        if text.len() > UNION_TEXT_MAX {
            return Err(Error::TooLong);
        }
        let (next, mk) = step(&self.ck);
        self.ck = next;
        let idx = self.idx;
        self.idx += 1;
        let mut w = Writer::new();
        w.u8(kind).bytes(&id).var(text.as_bytes());
        let mut pt = Zeroizing::new(w.finish());
        pt.resize(MSG_PAD, 0);
        let ct = MessageKey::from_bytes(mk).seal(&pt, &msg_ad(uid, me, self.gen, idx));
        Ok(Body::Msg {
            gen: self.gen,
            idx,
            ct,
        })
    }
}

/// A sending chain received from another member.
pub struct RecvChain {
    pub gen: u32,
    /// The union id this chain was received under (it changes on rekey).
    uid: [u8; 32],
    ck: [u8; 32],
    idx: u32,
    skipped: HashMap<u32, [u8; 32]>,
}

impl Drop for RecvChain {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.skipped.values_mut().for_each(|v| v.zeroize());
    }
}

impl RecvChain {
    pub fn open_skey(
        uid: &[u8; 32],
        me: &Who,
        my_mx: &StaticSecret,
        gen: u32,
        eph: &[u8; 32],
        entries: &[([u8; 8], Vec<u8>)],
    ) -> Option<RecvChain> {
        let t = tag(me);
        let (_, ct) = entries.iter().find(|(et, _)| *et == t)?;
        let dh = my_mx.diffie_hellman(&PublicKey::from(*eph)).to_bytes();
        let pt = aead_open(&entry_key(&dh, uid), &[0u8; 24], ct, &gen.to_be_bytes()).ok()?;
        let mut r = Reader::new(&pt);
        Some(RecvChain {
            gen,
            uid: *uid,
            ck: r.arr().ok()?,
            idx: r.u32().ok()?,
            skipped: HashMap::new(),
        })
    }

    pub fn decrypt(&mut self, from: &Who, idx: u32, ct: &[u8]) -> Result<Said> {
        let uid = self.uid;
        let mk = if let Some(k) = self.skipped.remove(&idx) {
            k
        } else {
            if idx < self.idx {
                return Err(Error::Replay);
            }
            if idx - self.idx > MAX_SKIP {
                return Err(Error::Malformed);
            }
            let mut ck = self.ck;
            let mut i = self.idx;
            let mut skipped = Vec::new();
            let mk = loop {
                let (next, mk) = step(&ck);
                ck = next;
                if i == idx {
                    break mk;
                }
                skipped.push((i, mk));
                i += 1;
            };
            // Commit only after the key opens the message.
            let pt = MessageKey::from_bytes(mk).open(ct, &msg_ad(&uid, from, self.gen, idx))?;
            self.ck = ck;
            self.idx = idx + 1;
            self.skipped.extend(skipped);
            return parse_text(&pt);
        };
        let pt = MessageKey::from_bytes(mk).open(ct, &msg_ad(&uid, from, self.gen, idx))?;
        parse_text(&pt)
    }
}

/// Message kinds inside a union MSG (and DM payloads use the same numbers).
pub const SAY_TEXT: u8 = 1;
pub const SAY_ONCE: u8 = 3;
pub const SAY_UNSAY: u8 = 4;
pub const SAY_ACTION: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    pub kind: u8,
    pub id: [u8; 8],
    pub text: String,
}

fn parse_text(pt: &[u8]) -> Result<Said> {
    let mut r = Reader::new(pt);
    let kind = r.u8()?;
    let id = r.arr()?;
    let text = String::from_utf8(r.var()?.to_vec()).map_err(|_| Error::Malformed)?;
    Ok(Said { kind, id, text })
}

fn rekey_key(dh: &[u8; 32], uid: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    kdf32(&[0u8; 32], dh, &[&b"eigen/rekey"[..], uid].concat())
}

/// Hand a fresh union secret to the remaining members only.
pub fn rekey_bodies(
    uid: &[u8; 32],
    epoch: u32,
    secret: &[u8; 32],
    to: &[(Who, [u8; 32])],
) -> Vec<Body> {
    to.chunks(SKEY_PER_MSG)
        .map(|chunk| {
            let eph = StaticSecret::random_from_rng(rand_core::OsRng);
            let entries = chunk
                .iter()
                .map(|(who, mx)| {
                    let dh = eph.diffie_hellman(&PublicKey::from(*mx)).to_bytes();
                    (
                        tag(who),
                        aead_seal(
                            &rekey_key(&dh, uid),
                            &[0u8; 24],
                            secret,
                            &epoch.to_be_bytes(),
                        ),
                    )
                })
                .collect();
            Body::Rekey {
                epoch,
                eph: PublicKey::from(&eph).to_bytes(),
                entries,
            }
        })
        .collect()
}

pub fn open_rekey(
    uid: &[u8; 32],
    me: &Who,
    my_mx: &StaticSecret,
    epoch: u32,
    eph: &[u8; 32],
    entries: &[([u8; 8], Vec<u8>)],
) -> Option<Zeroizing<[u8; 32]>> {
    let t = tag(me);
    let (_, ct) = entries.iter().find(|(et, _)| *et == t)?;
    let dh = my_mx.diffie_hellman(&PublicKey::from(*eph)).to_bytes();
    let pt = aead_open(&rekey_key(&dh, uid), &[0u8; 24], ct, &epoch.to_be_bytes()).ok()?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(pt.get(..32)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip_and_mailboxes_rotate() {
        let k = UnionKeys::generate(16);
        let j = UnionKeys::parse_invite(&k.invite()).unwrap();
        assert_eq!(k.uid, j.uid);
        assert_eq!(j.pow, 16);
        assert_eq!(k.mbox(10), j.mbox(10));
        assert_ne!(k.mbox(10), k.mbox(11));
        assert_ne!(k.mbox(10), UnionKeys::generate(16).mbox(10));
    }

    #[test]
    fn sealed_and_signed() {
        let k = UnionKeys::generate(16);
        let alice = Mask::generate();
        let inner = sign(&alice, &k.uid, &Body::Renew { term: 3 });
        let m = k.mbox(1);
        let b = k.seal(&m, &inner).unwrap();
        assert_eq!(b.len(), crate::cell::BLOB);
        let (from, body) = verify(&k.uid, &k.open(&m, &b).unwrap()).unwrap();
        assert_eq!(from, alice.who());
        assert_eq!(body, Body::Renew { term: 3 });
        // Bound to the hour mailbox: a relay cannot move it.
        assert!(k.open(&k.mbox(2), &b).is_err());
        // Bound to the union: cannot be replayed into another.
        let other = UnionKeys::generate(16);
        assert!(verify(&other.uid, &inner).is_err());
    }

    #[test]
    fn sender_keys_and_rotation_on_leave() {
        let k = UnionKeys::generate(16);
        let (a, b, c) = (Mask::generate(), Mask::generate(), Mask::generate());
        let mx_b = StaticSecret::random_from_rng(rand_core::OsRng);
        let mx_c = StaticSecret::random_from_rng(rand_core::OsRng);
        let mut chain = SenderChain::fresh(1);
        let to = [
            (b.who(), PublicKey::from(&mx_b).to_bytes()),
            (c.who(), PublicKey::from(&mx_c).to_bytes()),
        ];
        let Body::Skey { gen, eph, entries } = chain.distribute(&k.uid, &to).remove(0) else {
            panic!()
        };
        let mut rb = RecvChain::open_skey(&k.uid, &b.who(), &mx_b, gen, &eph, &entries).unwrap();
        let mut rc = RecvChain::open_skey(&k.uid, &c.who(), &mx_c, gen, &eph, &entries).unwrap();
        let msgs: Vec<Body> = (0..3)
            .map(|i| {
                chain
                    .encrypt(&k.uid, &a.who(), SAY_TEXT, [0; 8], &format!("m{i}"))
                    .unwrap()
            })
            .collect();
        for (i, m) in msgs.iter().enumerate().rev() {
            let Body::Msg { idx, ct, .. } = m else {
                panic!()
            };
            assert_eq!(
                rb.decrypt(&a.who(), *idx, ct).unwrap().text,
                format!("m{i}")
            );
            assert_eq!(
                rc.decrypt(&a.who(), *idx, ct).unwrap().text,
                format!("m{i}")
            );
            assert!(rb.decrypt(&a.who(), *idx, ct).is_err(), "replay");
        }
        // c leaves: a rotates to a new generation distributed to b only.
        let mut chain2 = SenderChain::fresh(2);
        let Body::Skey { gen, eph, entries } = chain2.distribute(&k.uid, &to[..1]).remove(0) else {
            panic!()
        };
        assert!(
            RecvChain::open_skey(&k.uid, &c.who(), &mx_c, gen, &eph, &entries).is_none(),
            "c gets nothing"
        );
        let mut rb2 = RecvChain::open_skey(&k.uid, &b.who(), &mx_b, gen, &eph, &entries).unwrap();
        let Body::Msg { idx, ct, .. } = chain2
            .encrypt(&k.uid, &a.who(), SAY_TEXT, [0; 8], "after")
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(rb2.decrypt(&a.who(), idx, &ct).unwrap().text, "after");
        // c's old chain cannot open the new generation.
        assert!(rc.decrypt(&a.who(), idx, &ct).is_err());
    }

    #[test]
    fn rekey_reaches_only_the_named() {
        let k = UnionKeys::generate(16);
        let (b, c) = (Mask::generate(), Mask::generate());
        let mx_b = StaticSecret::random_from_rng(rand_core::OsRng);
        let mx_c = StaticSecret::random_from_rng(rand_core::OsRng);
        let fresh: [u8; 32] = random();
        let Body::Rekey {
            epoch,
            eph,
            entries,
        } = rekey_bodies(
            &k.uid,
            1,
            &fresh,
            &[(b.who(), PublicKey::from(&mx_b).to_bytes())],
        )
        .remove(0)
        else {
            panic!()
        };
        assert_eq!(
            *open_rekey(&k.uid, &b.who(), &mx_b, epoch, &eph, &entries).unwrap(),
            fresh
        );
        assert!(open_rekey(&k.uid, &c.who(), &mx_c, epoch, &eph, &entries).is_none());
        assert!(
            open_rekey(&k.uid, &b.who(), &mx_b, epoch + 1, &eph, &entries).is_none(),
            "bound to epoch"
        );
        // Round-trips through signing and sealing.
        let a = Mask::generate();
        let body = rekey_bodies(&k.uid, 2, &fresh, &[(b.who(), random())]).remove(0);
        let inner = sign(&a, &k.uid, &body);
        assert_eq!(verify(&k.uid, &inner).unwrap().1, body);
    }

    #[test]
    fn skey_chunks_fit() {
        let k = UnionKeys::generate(16);
        let a = Mask::generate();
        let to: Vec<(Who, [u8; 32])> = (0..30)
            .map(|_| (Mask::generate().who(), random()))
            .collect();
        let bodies = SenderChain::fresh(1).distribute(&k.uid, &to);
        assert_eq!(bodies.len(), 3);
        for b in bodies {
            let inner = sign(&a, &k.uid, &b);
            assert!(k.seal(&k.mbox(0), &inner).is_ok());
        }
        let long = SenderChain::fresh(1)
            .encrypt(
                &k.uid,
                &a.who(),
                SAY_TEXT,
                [0; 8],
                &"x".repeat(UNION_TEXT_MAX),
            )
            .unwrap();
        assert!(k.seal(&k.mbox(0), &sign(&a, &k.uid, &long)).is_ok());
    }
}
