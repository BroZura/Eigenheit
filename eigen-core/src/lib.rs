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

/// Error messages are kept general so that no details leak through the UI or logs.
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
            Error::Malformed => "The data is invalid.",
            Error::Crypto => "The data could not be decrypted or verified.",
            Error::TooLong => "The message is too long.",
            Error::Unknown => "An unknown error occurred.",
            Error::Replay => "This message was already received.",
            Error::Pow => "The proof of work is insufficient.",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Seconds since the Unix epoch. Used only for TTLs and proof-of-work hours.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod zeroize_checks {
    //! Secret types must be zeroized when dropped. Safe Rust cannot read freed memory,
    //! so these tests check the trait bounds at compile time and test explicit wiping
    //! of the types defined in this crate.
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
