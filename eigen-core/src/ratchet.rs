//! Double Ratchet (Signal specification, revision 4), on X25519 / HKDF-SHA256 /
//! HMAC-SHA256 / XChaCha20-Poly1305. Decryption is transactional: a message that
//! fails to open leaves the state untouched.
use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{aead_open, aead_seal, kdf};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const MAX_SKIP: u32 = 256;
pub const HEADER: usize = 40;
pub const TAG: usize = 16;

/// A single-use message key. Sealing consumes it; it cannot be used twice.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; 32]);

impl MessageKey {
    pub(crate) fn from_bytes(k: [u8; 32]) -> MessageKey {
        MessageKey(k)
    }
    fn expand(&self) -> Zeroizing<[u8; 56]> {
        let mut out = Zeroizing::new([0u8; 56]);
        kdf(&[0u8; 32], &self.0, b"eigen/mk", out.as_mut());
        out
    }
    fn split(self) -> ([u8; 32], [u8; 24]) {
        let e = self.expand();
        let mut k = [0u8; 32];
        let mut n = [0u8; 24];
        k.copy_from_slice(&e[..32]);
        n.copy_from_slice(&e[32..]);
        (k, n)
    }
    pub fn seal(self, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let (mut k, n) = self.split();
        let ct = aead_seal(&k, &n, pt, ad);
        k.zeroize();
        ct
    }
    pub fn open(self, ct: &[u8], ad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (mut k, n) = self.split();
        let pt = aead_open(&k, &n, ct, ad);
        k.zeroize();
        pt
    }
}

/// KDF_CK: (next chain key, message key).
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], MessageKey) {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("hmac key");
    m.update(&[0x02]);
    let next: [u8; 32] = m.finalize().into_bytes().into();
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(ck).expect("hmac key");
    m.update(&[0x01]);
    (next, MessageKey(m.finalize().into_bytes().into()))
}

/// KDF_RK: (new root key, chain key).
pub fn kdf_rk(rk: &[u8; 32], dh: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = Zeroizing::new([0u8; 64]);
    kdf(rk, dh, b"eigen/rk", out.as_mut());
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER] {
        let mut w = Writer::new();
        w.bytes(&self.dh).u32(self.pn).u32(self.n);
        let mut out = [0u8; HEADER];
        out.copy_from_slice(&w.0);
        out
    }
    pub fn decode(b: &[u8]) -> Result<Header> {
        let mut r = Reader::new(b);
        Ok(Header {
            dh: r.arr()?,
            pn: r.u32()?,
            n: r.u32()?,
        })
    }
}

#[derive(Clone)]
pub struct Ratchet {
    dhs: StaticSecret,
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
    ad: Vec<u8>,
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
        for v in self.skipped.values_mut() {
            v.zeroize();
        }
    }
}

impl Ratchet {
    /// Initiator: knows the responder's ratchet (signed pre-)key.
    pub fn init_alice(sk: &[u8; 32], bob_pub: [u8; 32], ad: Vec<u8>) -> Ratchet {
        let dhs = StaticSecret::random_from_rng(OsRng);
        let dh = dhs.diffie_hellman(&PublicKey::from(bob_pub));
        let (rk, ck) = kdf_rk(sk, dh.as_bytes());
        Ratchet {
            dhs,
            dhr: Some(bob_pub),
            rk,
            cks: Some(ck),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad,
        }
    }

    /// Responder: its signed prekey is the first ratchet key.
    pub fn init_bob(sk: &[u8; 32], spk: StaticSecret, ad: Vec<u8>) -> Ratchet {
        Ratchet {
            dhs: spk,
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
            ad,
        }
    }

    /// Public key of the current sending chain. It changes once per DH ratchet step.
    pub fn epoch(&self) -> [u8; 32] {
        PublicKey::from(&self.dhs).to_bytes()
    }

    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// Returns `header ‖ ciphertext` (40 + pt.len() + 16 bytes).
    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let ck = self.cks.ok_or(Error::Unknown)?;
        let (next, mk) = kdf_ck(&ck);
        self.cks = Some(next);
        let h = Header {
            dh: self.epoch(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns = self.ns.checked_add(1).ok_or(Error::Unknown)?;
        let hb = h.encode();
        let mut ad = self.ad.clone();
        ad.extend_from_slice(&hb);
        let mut out = hb.to_vec();
        out.extend_from_slice(&mk.seal(pt, &ad));
        Ok(out)
    }

    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if msg.len() < HEADER + TAG {
            return Err(Error::Malformed);
        }
        let mut next = self.clone();
        let pt = next.decrypt_inner(msg)?;
        *self = next;
        Ok(pt)
    }

    fn decrypt_inner(&mut self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let h = Header::decode(&msg[..HEADER])?;
        let ct = &msg[HEADER..];
        let mut ad = self.ad.clone();
        ad.extend_from_slice(&msg[..HEADER]);
        if let Some(mut k) = self.skipped.remove(&(h.dh, h.n)) {
            let mk = MessageKey(k);
            k.zeroize();
            return mk.open(ct, &ad);
        }
        if self.dhr != Some(h.dh) {
            self.skip(h.pn)?;
            self.dh_step(h.dh);
        }
        self.skip(h.n)?;
        let ck = self.ckr.ok_or(Error::Replay)?;
        let (next, mk) = kdf_ck(&ck);
        self.ckr = Some(next);
        self.nr += 1;
        mk.open(ct, &ad)
    }

    fn skip(&mut self, until: u32) -> Result<()> {
        if until < self.nr {
            // The index was already passed and no skipped key exists, so this is a replay.
            return if self.ckr.is_some() {
                Err(Error::Replay)
            } else {
                Ok(())
            };
        }
        if until - self.nr > MAX_SKIP
            || self.skipped.len() as u32 + (until - self.nr) > 4 * MAX_SKIP
        {
            return Err(Error::Malformed);
        }
        if let (Some(mut ck), Some(dhr)) = (self.ckr, self.dhr) {
            while self.nr < until {
                let (next, mk) = kdf_ck(&ck);
                self.skipped.insert((dhr, self.nr), mk.0);
                ck = next;
                self.nr += 1;
            }
            self.ckr = Some(ck);
        }
        Ok(())
    }

    fn dh_step(&mut self, dh: [u8; 32]) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(dh);
        let (rk, ckr) = kdf_rk(
            &self.rk,
            self.dhs.diffie_hellman(&PublicKey::from(dh)).as_bytes(),
        );
        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = StaticSecret::random_from_rng(OsRng);
        let (rk, cks) = kdf_rk(
            &self.rk,
            self.dhs.diffie_hellman(&PublicKey::from(dh)).as_bytes(),
        );
        self.rk = rk;
        self.cks = Some(cks);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random;
    use proptest::prelude::*;

    fn pair() -> (Ratchet, Ratchet) {
        let sk = random::<32>();
        let spk = StaticSecret::random_from_rng(OsRng);
        let bob_pub = PublicKey::from(&spk).to_bytes();
        (
            Ratchet::init_alice(&sk, bob_pub, b"ad".to_vec()),
            Ratchet::init_bob(&sk, spk, b"ad".to_vec()),
        )
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 test case A.1. Checks the KDF wiring.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let mut okm = [0u8; 42];
        kdf(&salt, &ikm, &info, &mut okm);
        assert_eq!(
            crate::wire::hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn chain_kdf_vector() {
        // Regression vector for KDF_CK / KDF_RK with fixed inputs.
        let (ck, mk) = kdf_ck(&[1u8; 32]);
        let (rk, ck2) = kdf_rk(&[2u8; 32], &[3u8; 32]);
        let v = crate::crypto::h(&[&ck, &mk.0, &rk, &ck2]);
        assert_eq!(&crate::wire::hex(&v)[..16], &CHAIN_VECTOR[..16]);
    }
    // Regression vector generated by this project. No official Double Ratchet vectors
    // exist for this choice of KDF.
    const CHAIN_VECTOR: &str = "5c264fb2b8dabf92";

    #[test]
    fn ping_pong() {
        let (mut a, mut b) = pair();
        assert!(!b.can_send());
        for i in 0..5 {
            let m = a.encrypt(format!("a{i}").as_bytes()).unwrap();
            assert_eq!(&b.decrypt(&m).unwrap()[..], format!("a{i}").as_bytes());
            let m = b.encrypt(format!("b{i}").as_bytes()).unwrap();
            assert_eq!(&a.decrypt(&m).unwrap()[..], format!("b{i}").as_bytes());
        }
    }

    #[test]
    fn replay_and_tamper_rejected_without_state_change() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();
        b.decrypt(&m1).unwrap();
        assert!(b.decrypt(&m1).is_err(), "replay");
        let mut bad = m2.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(b.decrypt(&bad).is_err());
        assert_eq!(&b.decrypt(&m2).unwrap()[..], b"two");
    }

    #[test]
    fn same_plaintext_never_same_ciphertext() {
        // Nonce reuse is impossible: each message key is derived once and consumed.
        let (mut a, _) = pair();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let m = a.encrypt(b"same").unwrap();
            assert!(seen.insert(m[HEADER..].to_vec()));
        }
    }

    #[test]
    fn forward_secrecy_old_keys_gone() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x").unwrap();
        let snapshot = b.clone();
        b.decrypt(&m).unwrap();
        // After decryption b holds no key that opens m again.
        assert!(b.decrypt(&m).is_err());
        drop(snapshot);
        // Post-compromise: after a round trip, the root key has moved on.
        let rk_before = b.rk;
        let r = b.encrypt(b"y").unwrap();
        a.decrypt(&r).unwrap();
        let m2 = a.encrypt(b"z").unwrap();
        b.decrypt(&m2).unwrap();
        assert_ne!(rk_before, b.rk);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        /// Any delivery order within MAX_SKIP opens every message exactly once.
        #[test]
        fn out_of_order(perm in Just((0..20usize).collect::<Vec<_>>()).prop_shuffle(), turns in 1..4usize) {
            let (mut a, mut b) = pair();
            for t in 0..turns {
                let msgs: Vec<Vec<u8>> = (0..20).map(|i| a.encrypt(format!("{t}/{i}").as_bytes()).unwrap()).collect();
                for &i in &perm {
                    let want = format!("{t}/{i}");
                    prop_assert_eq!(&b.decrypt(&msgs[i]).unwrap()[..], want.as_bytes());
                }
                for &i in &perm {
                    prop_assert!(b.decrypt(&msgs[i]).is_err());
                }
                let back = b.encrypt(b"ack").unwrap();
                prop_assert_eq!(&a.decrypt(&back).unwrap()[..], b"ack");
            }
        }
    }
}
