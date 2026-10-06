//! OpenPGP interop: export a mask's Ed25519 key as an armored v4 public key
//! (EdDSA-legacy, RFC 4880bis) with a self-certification, and import such keys.
//! Live sessions never use PGP: it has no forward secrecy.
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::identity::{Mask, Who};
use crate::wire::{hex, Writer};
use crate::{Error, Result};

const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
/// Constant creation time: a timestamp would be metadata. (2020-01-01T00:00:00Z)
const CREATED: u32 = 1_577_836_800;

fn key_body(pk: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(4)
        .u32(CREATED)
        .u8(22)
        .u8(ED25519_OID.len() as u8)
        .bytes(&ED25519_OID)
        .u16(263)
        .u8(0x40)
        .bytes(pk);
    w.finish()
}

fn fpr_raw(body: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
    h.finalize().into()
}

/// PGP v4 fingerprint, grouped like `gpg --fingerprint`.
pub fn fingerprint(who: &Who) -> String {
    let f = hex(&fpr_raw(&key_body(&who.0))).to_uppercase();
    f.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0 | tag];
    let n = body.len();
    if n < 192 {
        v.push(n as u8);
    } else {
        let m = n - 192;
        v.push(((m >> 8) + 192) as u8);
        v.push(m as u8);
    }
    v.extend_from_slice(body);
    v
}

fn mpi(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let bits = if b.is_empty() {
        0
    } else {
        (b.len() - 1) * 8 + (8 - b[0].leading_zeros() as usize)
    };
    let mut v = (bits as u16).to_be_bytes().to_vec();
    v.extend(b);
    v
}

fn sig_hash(body: &[u8], uid: &[u8], hashed: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x99]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
    h.update([0xB4]);
    h.update((uid.len() as u32).to_be_bytes());
    h.update(uid);
    h.update(hashed);
    h.update([0x04, 0xFF]);
    h.update((hashed.len() as u32).to_be_bytes());
    h.finalize().into()
}

fn hashed_part(fpr: &[u8; 20]) -> Vec<u8> {
    let mut sub = Writer::new();
    sub.u8(5).u8(2).u32(CREATED); // signature creation time
    sub.u8(2).u8(27).u8(0x03); // key flags: certify + sign
    sub.u8(22).u8(33).u8(4).bytes(fpr); // issuer fingerprint
    let mut w = Writer::new();
    w.u8(4).u8(0x13).u8(22).u8(8).var(&sub.0);
    w.finish()
}

pub fn export(m: &Mask) -> String {
    let who = m.who();
    let body = key_body(&who.0);
    let fpr = fpr_raw(&body);
    let uid = format!("{} (eigen mask)", who.name()).into_bytes();
    let hashed = hashed_part(&fpr);
    let digest = sig_hash(&body, &uid, &hashed);
    let sig = m.sig.sign(&digest).to_bytes();
    let mut sp = hashed.clone();
    let mut unhashed = Writer::new();
    unhashed.u8(9).u8(16).bytes(&fpr[12..]);
    sp.extend((unhashed.0.len() as u16).to_be_bytes());
    sp.extend(&unhashed.0);
    sp.extend(&digest[..2]);
    sp.extend(mpi(&sig[..32]));
    sp.extend(mpi(&sig[32..]));
    let mut bin = packet(6, &body);
    bin.extend(packet(13, &uid));
    bin.extend(packet(2, &sp));
    armor(&bin)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(d: &[u8]) -> String {
    let mut s = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = B64.iter().position(|x| *x == c).ok_or(Error::Malformed)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn crc24(d: &[u8]) -> u32 {
    let mut crc: u32 = 0xB704CE;
    for b in d {
        crc ^= (*b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4CFB;
            }
        }
    }
    crc & 0xFF_FFFF
}

fn armor(bin: &[u8]) -> String {
    let body = b64(bin);
    let mut s = String::from("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
    for line in body.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or(""));
        s.push('\n');
    }
    let c = crc24(bin).to_be_bytes();
    s.push('=');
    s.push_str(&b64(&c[1..]));
    s.push_str("\n-----END PGP PUBLIC KEY BLOCK-----\n");
    s
}

fn packets(mut d: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !d.is_empty() {
        let h = d[0];
        if h & 0x80 == 0 {
            return Err(Error::Malformed);
        }
        let (tag, len, skip) = if h & 0x40 != 0 {
            let tag = h & 0x3F;
            let l0 = *d.get(1).ok_or(Error::Malformed)? as usize;
            if l0 < 192 {
                (tag, l0, 2)
            } else if l0 < 224 {
                let l1 = *d.get(2).ok_or(Error::Malformed)? as usize;
                (tag, ((l0 - 192) << 8) + l1 + 192, 3)
            } else if l0 == 255 {
                let b = d.get(2..6).ok_or(Error::Malformed)?;
                (
                    tag,
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                    6,
                )
            } else {
                return Err(Error::Malformed);
            }
        } else {
            let tag = (h >> 2) & 0x0F;
            match h & 3 {
                0 => (tag, *d.get(1).ok_or(Error::Malformed)? as usize, 2),
                1 => {
                    let b = d.get(1..3).ok_or(Error::Malformed)?;
                    (tag, u16::from_be_bytes([b[0], b[1]]) as usize, 3)
                }
                2 => {
                    let b = d.get(1..5).ok_or(Error::Malformed)?;
                    (
                        tag,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                        5,
                    )
                }
                _ => return Err(Error::Malformed),
            }
        };
        let body = d.get(skip..skip + len).ok_or(Error::Malformed)?;
        out.push((tag, body));
        d = &d[skip + len..];
    }
    Ok(out)
}

/// Import an armored Ed25519 PGP public key. Verifies the self-certification when
/// one is present for the first user id.
pub fn import(armored: &str) -> Result<Who> {
    let inner: String = armored
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK"))
        .skip(1)
        .skip_while(|l| !l.trim().is_empty() && l.contains(':'))
        .take_while(|l| !l.starts_with('=') && !l.starts_with("-----END"))
        .collect();
    let bin = unb64(&inner)?;
    let pk = packets(&bin)?;
    let (_, body) = pk.iter().find(|(t, _)| *t == 6).ok_or(Error::Malformed)?;
    if body.len() != 6 + 1 + 9 + 2 + 33
        || body[0] != 4
        || body[5] != 22
        || body[7..16] != ED25519_OID
        || body[18] != 0x40
    {
        return Err(Error::Unknown);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[19..51]);
    let who = Who(key);
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| Error::Crypto)?;
    let uid = pk.iter().find(|(t, _)| *t == 13).map(|(_, b)| *b);
    let sig = pk.iter().find(|(t, _)| *t == 2).map(|(_, b)| *b);
    if let (Some(uid), Some(sig)) = (uid, sig) {
        if sig.len() > 6 && sig[0] == 4 && sig[2] == 22 && sig[3] == 8 {
            let hl = u16::from_be_bytes([sig[4], sig[5]]) as usize;
            let hashed = sig.get(..6 + hl).ok_or(Error::Malformed)?;
            let mut rest = &sig[6 + hl..];
            let ul = u16::from_be_bytes([
                *rest.first().ok_or(Error::Malformed)?,
                *rest.get(1).ok_or(Error::Malformed)?,
            ]) as usize;
            rest = rest.get(2 + ul + 2..).ok_or(Error::Malformed)?;
            let mut rs = [0u8; 64];
            for half in 0..2 {
                let bits = u16::from_be_bytes([
                    *rest.first().ok_or(Error::Malformed)?,
                    *rest.get(1).ok_or(Error::Malformed)?,
                ]) as usize;
                let n = bits.div_ceil(8);
                if n > 32 {
                    return Err(Error::Malformed);
                }
                let v = rest.get(2..2 + n).ok_or(Error::Malformed)?;
                rs[half * 32 + 32 - n..half * 32 + 32].copy_from_slice(v);
                rest = &rest[2 + n..];
            }
            let digest = sig_hash(body, uid, hashed);
            vk.verify(&digest, &Signature::from_bytes(&rs))
                .map_err(|_| Error::Crypto)?;
        }
    }
    Ok(who)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_import_roundtrip() {
        let m = Mask::generate();
        let a = export(&m);
        assert!(a.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert_eq!(import(&a).unwrap(), m.who());
        assert_eq!(fingerprint(&m.who()).len(), 49);
    }

    #[test]
    fn tampered_signature_rejected() {
        let m = Mask::generate();
        let a = export(&m);
        let bin = unb64(
            &a.lines()
                .skip(2)
                .take_while(|l| !l.starts_with('='))
                .collect::<String>(),
        )
        .unwrap();
        let mut bad = bin.clone();
        let n = bad.len();
        bad[n - 5] ^= 0x55;
        assert!(import(&armor(&bad)).is_err());
    }

    #[test]
    fn crc24_known() {
        // CRC-24 of the empty string is the init value.
        assert_eq!(crc24(b""), 0xB704CE);
        assert_eq!(
            unb64(&b64(b"any carnal pleas")).unwrap(),
            b"any carnal pleas"
        );
    }
}

#[cfg(test)]
mod gpg_interop {
    /// `cargo test -p eigen-core gpg_print -- --ignored --nocapture` prints a key for gpg.
    #[test]
    #[ignore]
    fn gpg_print() {
        let m = crate::identity::Mask::generate();
        println!("FPR {}", super::fingerprint(&m.who()).replace(' ', ""));
        print!("{}", super::export(&m));
    }
}
