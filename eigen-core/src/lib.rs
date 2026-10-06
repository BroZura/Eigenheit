//! EIGENHEIT core: identity, cryptographic protocol, wire formats.
//! No I/O lives here. Everything is deterministic given the RNG.
#![forbid(unsafe_code)]

pub mod cell;
pub mod crypto;
pub mod dm;
pub mod identity;
pub mod pgp;
pub mod pow;
pub mod ratchet;
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
