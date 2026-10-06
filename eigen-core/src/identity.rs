//! Masks: locally generated identities. I am my key.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{h, random};
use crate::wire::{base32, hex, unbase32, Reader, Writer};
use crate::words::{adjective, noun, GLYPHS};
use crate::{Error, Result};

pub const MAX_OPKS: usize = 16;

/// The public face of a key: name, glyph, colour, identicon. Derived, never chosen.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Who(pub [u8; 32]);

impl Who {
    fn digest(&self) -> [u8; 32] {
        h(&[b"eigen/name", &self.0])
    }
    pub fn name(&self) -> String {
        let d = self.digest();
        format!("{}-{}-{}", adjective(d[0]), noun(d[1]), hex(&d[2..4]))
    }
    pub fn glyph(&self) -> char {
        GLYPHS[self.digest()[4] as usize % GLYPHS.len()]
    }
    /// Stable colour index into the UI palette.
    pub fn color(&self) -> u8 {
        self.digest()[5]
    }
    /// 5×5 horizontally mirrored identicon, rows of booleans.
    pub fn identicon(&self) -> [[bool; 5]; 5] {
        let d = self.digest();
        let bits = u32::from_be_bytes([0, d[6], d[7], d[8]]);
        let mut g = [[false; 5]; 5];
        for (r, row) in g.iter_mut().enumerate() {
            for c in 0..3 {
                let on = bits >> (r * 3 + c) & 1 == 1;
                row[c] = on;
                row[4 - c] = on;
            }
        }
        g
    }
    /// Full native fingerprint, grouped for reading aloud.
    pub fn fingerprint(&self) -> String {
        let f = hex(&h(&[b"eigen/fpr", &self.0]));
        f.as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(" ")
    }
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| Error::Crypto)
    }
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        self.verifying_key()?
            .verify(msg, &Signature::from_bytes(sig))
            .map_err(|_| Error::Crypto)
    }
}

/// Short authentication string for two keys; symmetric in its arguments.
pub fn sas(a: &Who, b: &Who) -> String {
    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    let s = h(&[b"eigen/sas", &lo.0, &hi.0]);
    let words: Vec<&str> = (0..5)
        .map(|i| if i % 2 == 0 { adjective(s[i]) } else { noun(s[i]) })
        .collect();
    let num = u32::from_be_bytes([0, s[5], s[6], s[7]]) % 1_000_000;
    format!("{} · {:06}", words.join(" "), num)
}

/// A contact card: everything needed to start a DM with a mask.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Card {
    pub who: Who,
    pub intro: [u8; 16],
}

pub const CARD_PREFIX: &str = "eigen://mask/";

impl Card {
    pub fn encode(&self) -> String {
        let mut w = Writer::new();
        w.bytes(&self.who.0).bytes(&self.intro);
        let c = h(&[b"eigen/card", &w.0]);
        w.bytes(&c[..4]);
        format!("{CARD_PREFIX}{}", base32(&w.0))
    }
    pub fn parse(s: &str) -> Result<Card> {
        let body = s.trim().strip_prefix(CARD_PREFIX).ok_or(Error::Malformed)?;
        let raw = unbase32(body)?;
        if raw.len() != 52 || h(&[b"eigen/card", &raw[..48]])[..4] != raw[48..] {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(&raw);
        let who = Who(r.arr()?);
        who.verifying_key()?;
        Ok(Card { who, intro: r.arr()? })
    }
    pub fn bundle_mbox(&self) -> [u8; 32] {
        h(&[b"eigen/bundle", &self.intro])
    }
    pub fn opk_mbox(&self) -> [u8; 32] {
        h(&[b"eigen/opk", &self.intro])
    }
    pub fn intro_mbox(&self) -> [u8; 32] {
        h(&[b"eigen/intro", &self.intro])
    }
}

/// A mask: an identity I hold. Secret parts zeroize on drop.
pub struct Mask {
    pub sig: SigningKey,
    pub ik: StaticSecret,
    pub spk: StaticSecret,
    pub spk_id: u32,
    pub opks: Vec<(u32, StaticSecret)>,
    pub next_opk: u32,
    pub intro: [u8; 16],
}

impl Drop for Mask {
    fn drop(&mut self) {
        self.intro.zeroize();
    }
}

impl Mask {
    pub fn generate() -> Mask {
        let mut m = Mask {
            sig: SigningKey::generate(&mut OsRng),
            ik: StaticSecret::random_from_rng(OsRng),
            spk: StaticSecret::random_from_rng(OsRng),
            spk_id: u32::from_be_bytes(random()) & 0x7fff_ffff,
            opks: Vec::new(),
            next_opk: 1,
            intro: random(),
        };
        m.refill_opks();
        m
    }
    pub fn who(&self) -> Who {
        Who(self.sig.verifying_key().to_bytes())
    }
    pub fn name(&self) -> String {
        self.who().name()
    }
    pub fn ik_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.ik).to_bytes()
    }
    pub fn spk_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.spk).to_bytes()
    }
    pub fn card(&self) -> Card {
        Card { who: self.who(), intro: self.intro }
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sig.sign(msg).to_bytes()
    }
    /// Top up one-time prekeys; returns the newly minted (id, public) pairs.
    pub fn refill_opks(&mut self) -> Vec<(u32, [u8; 32])> {
        let mut fresh = Vec::new();
        while self.opks.len() < MAX_OPKS {
            let id = self.next_opk;
            self.next_opk += 1;
            let sk = StaticSecret::random_from_rng(OsRng);
            fresh.push((id, PublicKey::from(&sk).to_bytes()));
            self.opks.push((id, sk));
        }
        fresh
    }
    /// Mint a fresh generation of one-time prekeys, keeping at most two generations
    /// (older relay copies may still be taken until they expire).
    pub fn rotate_opks(&mut self) -> Vec<(u32, [u8; 32])> {
        let mut fresh = Vec::new();
        for _ in 0..MAX_OPKS {
            let id = self.next_opk;
            self.next_opk += 1;
            let sk = StaticSecret::random_from_rng(OsRng);
            fresh.push((id, PublicKey::from(&sk).to_bytes()));
            self.opks.push((id, sk));
        }
        let excess = self.opks.len().saturating_sub(2 * MAX_OPKS);
        self.opks.drain(..excess);
        fresh
    }

    /// One-time prekeys are consumed exactly once.
    pub fn take_opk(&mut self, id: u32) -> Option<StaticSecret> {
        let i = self.opks.iter().position(|(k, _)| *k == id)?;
        Some(self.opks.remove(i).1)
    }

    /// Serialise secrets (for the vault only).
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.bytes(&self.sig.to_bytes())
            .bytes(self.ik.as_bytes())
            .bytes(self.spk.as_bytes())
            .u32(self.spk_id)
            .bytes(&self.intro)
            .u32(self.next_opk);
        zeroize::Zeroizing::new(w.finish())
    }
    pub fn from_bytes(b: &[u8]) -> Result<Mask> {
        let mut r = Reader::new(b);
        let mut m = Mask {
            sig: SigningKey::from_bytes(&r.arr()?),
            ik: StaticSecret::from(r.arr::<32>()?),
            spk: StaticSecret::from(r.arr::<32>()?),
            spk_id: r.u32()?,
            intro: r.arr()?,
            next_opk: r.u32()?,
            opks: Vec::new(),
        };
        // One-time prekeys are never persisted: fresh ones after every start.
        m.refill_opks();
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable_and_shaped() {
        let m = Mask::generate();
        let n = m.name();
        assert_eq!(n, m.who().name());
        let parts: Vec<_> = n.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 4);
    }

    #[test]
    fn card_roundtrip_and_checksum() {
        let m = Mask::generate();
        let c = m.card().encode();
        assert_eq!(Card::parse(&c).unwrap(), m.card());
        let mut bad: Vec<char> = c.chars().collect();
        bad[30] = if bad[30] == 'a' { 'b' } else { 'a' };
        let bad: String = bad.into_iter().collect();
        assert!(Card::parse(&bad).is_err());
    }

    #[test]
    fn sas_symmetric() {
        let (a, b) = (Mask::generate().who(), Mask::generate().who());
        assert_eq!(sas(&a, &b), sas(&b, &a));
        assert_ne!(sas(&a, &b), sas(&a, &a));
    }

    #[test]
    fn masks_unlinkable_material() {
        let (a, b) = (Mask::generate(), Mask::generate());
        assert_ne!(a.who(), b.who());
        assert_ne!(a.intro, b.intro);
        assert_ne!(a.ik_pub(), b.ik_pub());
    }

    #[test]
    fn mask_serialisation() {
        let a = Mask::generate();
        let b = Mask::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a.who(), b.who());
        assert_eq!(a.spk_pub(), b.spk_pub());
        assert_eq!(a.intro, b.intro);
    }

    #[test]
    fn opk_single_use() {
        let mut m = Mask::generate();
        let id = m.opks[0].0;
        assert!(m.take_opk(id).is_some());
        assert!(m.take_opk(id).is_none());
    }
}
