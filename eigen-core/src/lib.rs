//! EIGENHEIT core: identity, cryptographic protocol, wire formats.
//! The only I/O here is the opt-in vault file (`vault.rs`).
#![forbid(unsafe_code)]

pub mod cell;
pub mod crypto;
pub mod dm;
pub mod identity;
pub mod pgp;
pub mod pow;
pub mod ratchet;
pub mod union;
pub mod vault;
pub mod wire;
pub mod words;
pub mod x3dh;

/// Every error is deliberately vague: details could leak through UI or logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Crypto,
    TooLong,
    Unknown,
    Replay,
    Pow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Error::Malformed => "malformed",
            Error::Crypto => "does not open",
            Error::TooLong => "too long — say less",
            Error::Unknown => "unknown",
            Error::Replay => "replayed",
            Error::Pow => "insufficient work",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Seconds since the Unix epoch. Used only for TTLs and PoW hours.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod zeroize_checks {
    //! Secrets must wipe themselves. Safe Rust cannot read freed memory, so these
    //! are compile-time guarantees plus explicit-wipe checks on our own types.
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn on_drop<T: ZeroizeOnDrop>() {}
    fn wipeable<T: Zeroize>() {}

    #[test]
    fn secret_types_zeroize() {
        on_drop::<ed25519_dalek::SigningKey>();
        // StaticSecret wipes via `#[zeroize(drop)]` (a Drop impl without the marker trait).
        assert!(std::mem::needs_drop::<x25519_dalek::StaticSecret>());
        on_drop::<crate::ratchet::MessageKey>();
        on_drop::<zeroize::Zeroizing<[u8; 32]>>();
        wipeable::<x25519_dalek::StaticSecret>();
    }

    #[test]
    fn explicit_wipe() {
        let mut k = crate::ratchet::MessageKey::from_bytes([0xAA; 32]);
        k.zeroize();
        let mut buf = zeroize::Zeroizing::new(vec![1u8; 64]);
        buf.zeroize();
        assert!(buf.iter().all(|b| *b == 0));
    }
}
