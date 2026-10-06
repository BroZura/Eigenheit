//! Thin wrappers around audited cryptographic primitives. This module contains no
//! custom cryptography.
use blake2::digest::{consts::U32, Digest, KeyInit, Mac};
use blake2::{Blake2b, Blake2bMac};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub type Key = [u8; 32];

/// BLAKE2b-256 over the concatenation of `parts`.
pub fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Blake2b::<U32>::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// Keyed BLAKE2b-256.
pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Blake2bMac<U32> as KeyInit>::new_from_slice(key).expect("key length 1..=64");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF-SHA256.
pub fn kdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("hkdf output length");
}

pub fn kdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<Key> {
    let mut k = Zeroizing::new([0u8; 32]);
    kdf(salt, ikm, info, k.as_mut());
    k
}

pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill_random(&mut b);
    b
}

pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

/// Overhead of [`seal_fixed`]: nonce (24) + tag (16).
pub const SEAL_OVERHEAD: usize = 40;

/// Pads `pt` to exactly `size` bytes (u16 length prefix + zeros) and encrypts with a
/// fresh random 192-bit nonce. Output is always `size + 40` bytes, whatever `pt` was.
pub fn seal_fixed(key: &Key, pt: &[u8], size: usize, aad: &[u8]) -> Result<Vec<u8>> {
    if pt.len() + 2 > size {
        return Err(Error::TooLong);
    }
    let mut padded = Zeroizing::new(vec![0u8; size]);
    padded[..2].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    padded[2..2 + pt.len()].copy_from_slice(pt);
    let nonce: [u8; 24] = random();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &padded, aad })
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(size + SEAL_OVERHEAD);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal_fixed`]. Returns the unpadded plaintext.
pub fn open_fixed(key: &Key, data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < SEAL_OVERHEAD + 2 {
        return Err(Error::Malformed);
    }
    let (nonce, ct) = data.split_at(24);
    let pt = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| Error::Crypto)?,
    );
    let n = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    if n + 2 > pt.len() {
        return Err(Error::Malformed);
    }
    Ok(Zeroizing::new(pt[2..2 + n].to_vec()))
}

/// AEAD with an explicit nonce. Callers must ensure that each key is used only once
/// (ratchet message keys, sender-key entries). The key types enforce this because they
/// are consumed on use.
pub fn aead_seal(key: &Key, nonce: &[u8; 24], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
        .expect("xchacha encrypt cannot fail for in-memory buffers")
}

pub fn aead_open(key: &Key, nonce: &[u8; 24], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// Extend `buf` to `len` bytes with random data so that the padding cannot be recognized.
pub fn pad_random(buf: &mut Vec<u8>, len: usize) {
    let start = buf.len();
    if start < len {
        buf.resize(len, 0);
        fill_random(&mut buf[start..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_is_fixed_size_and_roundtrips() {
        let k = random::<32>();
        for n in [0usize, 1, 50, 198] {
            let pt = vec![7u8; n];
            let s = seal_fixed(&k, &pt, 200, b"ad").unwrap();
            assert_eq!(s.len(), 240);
            assert_eq!(&open_fixed(&k, &s, b"ad").unwrap()[..], &pt[..]);
            assert!(open_fixed(&k, &s, b"other").is_err());
        }
        assert_eq!(seal_fixed(&k, &[0; 199], 200, b""), Err(Error::TooLong));
    }

    #[test]
    fn random_nonces_differ() {
        let k = random::<32>();
        let a = seal_fixed(&k, b"x", 16, b"").unwrap();
        let b = seal_fixed(&k, b"x", 16, b"").unwrap();
        assert_ne!(a[..24], b[..24]);
    }
}
