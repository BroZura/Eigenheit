//! The optional vault: one file, no header, no magic, fixed bucket size, two equal
//! slots. Every byte is either a random salt/nonce, AEAD ciphertext, or random fill,
//! so the file is indistinguishable from random bytes without a passphrase.
//!
//! Layout: `salt:32 ‖ slot0 ‖ slot1`, `slot = nonce:24 ‖ AEAD(k, padded, salt ‖ i)`.
//! One slot holds the real vault; the other is random, or a decoy opened by a
//! duress passphrase. A decoy may carry `wipe_other`: opening it silently destroys
//! the other slot.
use std::fs::{self, OpenOptions};
use std::io::Write;

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{aead_open, aead_seal, fill_random, random};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const BUCKETS: [usize; 3] = [64 * 1024, 256 * 1024, 1024 * 1024];
const SALT: usize = 32;
const OVER: usize = 24 + 16;

#[derive(Default)]
pub struct VaultData {
    pub masks: Vec<Zeroizing<Vec<u8>>>,
    /// (union secret, pow, mask index)
    pub unions: Vec<(Zeroizing<[u8; 32]>, u8, u16)>,
    pub pins: Vec<[u8; 32]>,
    /// Keys I verified out of band (`/trust`).
    pub trusted: Vec<[u8; 32]>,
    pub active_mask: u16,
    pub wipe_other: bool,
}

impl VaultData {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1).u8(self.wipe_other as u8).u16(self.active_mask);
        w.u16(self.masks.len() as u16);
        for m in &self.masks {
            w.var(m);
        }
        w.u16(self.unions.len() as u16);
        for (s, p, m) in &self.unions {
            w.bytes(&s[..]).u8(*p).u16(*m);
        }
        w.u16(self.pins.len() as u16);
        for p in &self.pins {
            w.bytes(p);
        }
        w.u16(self.trusted.len() as u16);
        for t in &self.trusted {
            w.bytes(t);
        }
        Zeroizing::new(w.finish())
    }
    fn decode(b: &[u8]) -> Result<VaultData> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(Error::Malformed);
        }
        let mut d = VaultData {
            wipe_other: r.u8()? == 1,
            active_mask: r.u16()?,
            ..Default::default()
        };
        for _ in 0..r.u16()? {
            d.masks.push(Zeroizing::new(r.var()?.to_vec()));
        }
        for _ in 0..r.u16()? {
            d.unions.push((Zeroizing::new(r.arr()?), r.u8()?, r.u16()?));
        }
        for _ in 0..r.u16()? {
            d.pins.push(r.arr()?);
        }
        if r.remaining() >= 2 {
            for _ in 0..r.u16()? {
                d.trusted.push(r.arr()?);
            }
        }
        Ok(d)
    }
}

/// Argon2id, 64 MiB, 3 passes. Deliberately slow.
pub fn derive(pass: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| Error::Unknown)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut k = Zeroizing::new([0u8; 32]);
    a.hash_password_into(pass.as_bytes(), salt, k.as_mut())
        .map_err(|_| Error::Unknown)?;
    Ok(k)
}

fn slot_size(file_len: usize) -> Option<usize> {
    BUCKETS
        .iter()
        .copied()
        .find(|s| SALT + 2 * (s + OVER) == file_len)
}

fn seal_slot(
    key: &[u8; 32],
    salt: &[u8],
    i: usize,
    data: &VaultData,
    size: usize,
) -> Result<Vec<u8>> {
    let enc = data.encode();
    if enc.len() + 4 > size {
        return Err(Error::TooLong);
    }
    let mut pt = Zeroizing::new(vec![0u8; size]);
    pt[..4].copy_from_slice(&(enc.len() as u32).to_be_bytes());
    pt[4..4 + enc.len()].copy_from_slice(&enc);
    let nonce: [u8; 24] = random();
    let mut out = nonce.to_vec();
    out.extend(aead_seal(key, &nonce, &pt, &[salt, &[i as u8]].concat()));
    Ok(out)
}

fn write_all(path: &str, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| Error::Unknown)?;
    f.write_all(bytes).map_err(|_| Error::Unknown)?;
    f.set_len(bytes.len() as u64).map_err(|_| Error::Unknown)?;
    f.sync_all().map_err(|_| Error::Unknown)
}

/// An open vault: remembers its derived key so saving does not re-run Argon2.
pub struct Vault {
    pub path: String,
    salt: [u8; 32],
    slot: usize,
    key: Zeroizing<[u8; 32]>,
    size: usize,
}

impl Vault {
    /// Create a new vault. `decoy`: a second passphrase and the content it opens.
    pub fn create(
        path: &str,
        pass: &str,
        data: &VaultData,
        decoy: Option<(&str, &VaultData)>,
    ) -> Result<Vault> {
        let size = BUCKETS
            .iter()
            .copied()
            .find(|s| data.encode().len() + 4 <= *s)
            .ok_or(Error::TooLong)?;
        let salt: [u8; 32] = random();
        let key = derive(pass, &salt)?;
        // The real slot's position is random, so slot order says nothing.
        let slot = (random::<1>()[0] & 1) as usize;
        let mut slots = [vec![0u8; size + OVER], vec![0u8; size + OVER]];
        fill_random(&mut slots[1 - slot]);
        slots[slot] = seal_slot(&key, &salt, slot, data, size)?;
        if let Some((p2, d2)) = decoy {
            let k2 = derive(p2, &salt)?;
            slots[1 - slot] = seal_slot(&k2, &salt, 1 - slot, d2, size)?;
        }
        let mut file = salt.to_vec();
        file.extend(&slots[0]);
        file.extend(&slots[1]);
        write_all(path, &file)?;
        Ok(Vault {
            path: path.to_string(),
            salt,
            slot,
            key,
            size,
        })
    }

    /// Open with a passphrase. Wrong passphrase and "not a vault" are the same error.
    pub fn open(path: &str, pass: &str) -> Result<(Vault, VaultData)> {
        let mut file = fs::read(path).map_err(|_| Error::Crypto)?;
        let size = slot_size(file.len()).ok_or(Error::Crypto)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&file[..SALT]);
        let key = derive(pass, &salt)?;
        for i in 0..2 {
            let s = &file[SALT + i * (size + OVER)..SALT + (i + 1) * (size + OVER)];
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&s[..24]);
            if let Ok(pt) = aead_open(&key, &nonce, &s[24..], &[&salt[..], &[i as u8]].concat()) {
                let n = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]) as usize;
                let data = VaultData::decode(pt.get(4..4 + n).ok_or(Error::Malformed)?)?;
                if data.wipe_other {
                    // Duress: silently replace the other slot with fresh random bytes.
                    let o = 1 - i;
                    fill_random(
                        &mut file[SALT + o * (size + OVER)..SALT + (o + 1) * (size + OVER)],
                    );
                    write_all(path, &file)?;
                }
                file.zeroize();
                return Ok((
                    Vault {
                        path: path.to_string(),
                        salt,
                        slot: i,
                        key,
                        size,
                    },
                    data,
                ));
            }
        }
        file.zeroize();
        Err(Error::Crypto)
    }

    /// Re-encrypt my slot in place; the other slot is untouched.
    pub fn save(&self, data: &VaultData) -> Result<()> {
        let mut file = fs::read(&self.path).map_err(|_| Error::Unknown)?;
        if slot_size(file.len()) != Some(self.size) {
            return Err(Error::Malformed);
        }
        let sealed = seal_slot(&self.key, &self.salt, self.slot, data, self.size)?;
        let at = SALT + self.slot * (self.size + OVER);
        file[at..at + self.size + OVER].copy_from_slice(&sealed);
        write_all(&self.path, &file)
    }

    /// Overwrite the whole file with random bytes, sync, then unlink.
    /// Limits: SSD wear-levelling, journaling and snapshots may keep old blocks.
    pub fn burn(path: &str) -> bool {
        let Ok(meta) = fs::metadata(path) else {
            return false;
        };
        let mut junk = vec![0u8; meta.len() as usize];
        for _ in 0..2 {
            fill_random(&mut junk);
            let _ = write_all(path, &junk);
        }
        fs::remove_file(path).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!(
            "eigen-vault-test-{}-{name}",
            crate::wire::hex(&random::<6>())
        ));
        d.to_string_lossy().into_owned()
    }

    fn data(n: usize) -> VaultData {
        VaultData {
            masks: (0..n).map(|i| Zeroizing::new(vec![i as u8; 140])).collect(),
            pins: vec![[7u8; 32]],
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_save_and_wrong_pass() {
        let p = tmp("a");
        let v = Vault::create(&p, "mine", &data(2), None).unwrap();
        let (_, d) = Vault::open(&p, "mine").unwrap();
        assert_eq!(d.masks.len(), 2);
        v.save(&data(5)).unwrap();
        assert_eq!(Vault::open(&p, "mine").unwrap().1.masks.len(), 5);
        assert_eq!(Vault::open(&p, "yours").err(), Some(Error::Crypto));
        assert!(Vault::burn(&p));
        assert!(fs::metadata(&p).is_err());
    }

    #[test]
    fn looks_random_and_fixed_size() {
        let p = tmp("b");
        Vault::create(&p, "x", &data(1), None).unwrap();
        let f = fs::read(&p).unwrap();
        assert_eq!(f.len(), SALT + 2 * (BUCKETS[0] + OVER));
        // Byte histogram close to uniform, no long zero runs (padding is encrypted).
        let mut hist = [0usize; 256];
        f.iter().for_each(|b| hist[*b as usize] += 1);
        let exp = f.len() as f64 / 256.0;
        let chi: f64 = hist.iter().map(|h| (*h as f64 - exp).powi(2) / exp).sum();
        assert!(chi < 400.0, "chi² {chi}");
        assert!(!f.windows(16).any(|w| w.iter().all(|b| *b == 0)));
        Vault::burn(&p);
    }

    #[test]
    fn duress_decoy_and_wipe() {
        let p = tmp("c");
        let decoy = data(1);
        Vault::create(&p, "real", &data(3), Some(("calm", &decoy))).unwrap();
        assert_eq!(Vault::open(&p, "calm").unwrap().1.masks.len(), 1);
        assert_eq!(Vault::open(&p, "real").unwrap().1.masks.len(), 3);
        // Wipe mode: opening the duress slot destroys the real one, silently.
        let p2 = tmp("d");
        let wipe = VaultData {
            wipe_other: true,
            ..data(1)
        };
        Vault::create(&p2, "real", &data(3), Some(("calm", &wipe))).unwrap();
        let len = fs::metadata(&p2).unwrap().len();
        assert_eq!(Vault::open(&p2, "calm").unwrap().1.masks.len(), 1);
        assert_eq!(fs::metadata(&p2).unwrap().len(), len, "size unchanged");
        assert!(Vault::open(&p2, "real").is_err(), "real slot is gone");
        Vault::burn(&p);
        Vault::burn(&p2);
    }
}
