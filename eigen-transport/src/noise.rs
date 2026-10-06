//! Noise_NK_25519_ChaChaPoly_BLAKE2s link between client and relay (via `snow`).
//! The client knows the relay's static key from its address (`host:port#key`);
//! the relay learns nothing about the client. Every 1024-byte cell becomes a
//! 1040-byte frame; frames are as fixed-size as the cells inside them.
use std::io;

use eigen_core::cell::CELL;
use snow::{Builder, StatelessTransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const TAG: usize = 16;
pub const FRAME: usize = CELL + TAG;
/// NK handshake messages with empty payloads: `e` (32) + tag (16).
const HS: usize = 48;

fn builder() -> io::Result<Builder<'static>> {
    let params = PATTERN
        .parse()
        .map_err(|_| io::Error::other("noise params"))?;
    Ok(Builder::new(params))
}

/// A relay's link key. Ephemeral by default: dies with the relay process.
pub struct RelayKey {
    private: Zeroizing<Vec<u8>>,
    pub public: [u8; 32],
}

impl RelayKey {
    pub fn generate() -> io::Result<RelayKey> {
        let kp = builder()?
            .generate_keypair()
            .map_err(|_| io::Error::other("keygen"))?;
        let mut public = [0u8; 32];
        public.copy_from_slice(&kp.public);
        Ok(RelayKey {
            private: Zeroizing::new(kp.private),
            public,
        })
    }
    /// What clients append to the relay address: `host:port#<this>`.
    pub fn encoded(&self) -> String {
        eigen_core::wire::base32(&self.public)
    }
}

pub fn parse_key(s: &str) -> Option<[u8; 32]> {
    let v = eigen_core::wire::unbase32(s).ok()?;
    v.try_into().ok()
}

/// An established link. Nonces are explicit counters, one per direction, so the
/// reading and writing halves can run independently.
pub struct Link {
    ts: StatelessTransportState,
}

impl Link {
    pub fn seal(&self, nonce: u64, cell: &[u8; CELL]) -> io::Result<[u8; FRAME]> {
        let mut out = [0u8; FRAME];
        let n = self
            .ts
            .write_message(nonce, cell, &mut out)
            .map_err(|_| io::Error::other("seal"))?;
        debug_assert_eq!(n, FRAME);
        Ok(out)
    }
    pub fn open(&self, nonce: u64, frame: &[u8; FRAME]) -> io::Result<[u8; CELL]> {
        let mut out = [0u8; FRAME];
        let n = self
            .ts
            .read_message(nonce, frame, &mut out)
            .map_err(|_| io::Error::other("open"))?;
        if n != CELL {
            return Err(io::Error::other("frame"));
        }
        let mut cell = [0u8; CELL];
        cell.copy_from_slice(&out[..CELL]);
        Ok(cell)
    }
}

/// Client side: I know the relay's key; it does not learn mine (there is none).
pub async fn initiate<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    relay: &[u8; 32],
) -> io::Result<Link> {
    let mut hs = builder()?
        .remote_public_key(relay)
        .map_err(|_| io::Error::other("key"))?
        .build_initiator()
        .map_err(|_| io::Error::other("noise"))?;
    let mut buf = [0u8; 128];
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| io::Error::other("noise"))?;
    s.write_all(&buf[..n]).await?;
    let mut msg = [0u8; HS];
    s.read_exact(&mut msg).await?;
    hs.read_message(&msg, &mut buf)
        .map_err(|_| io::Error::other("relay key mismatch"))?;
    Ok(Link {
        ts: hs
            .into_stateless_transport_mode()
            .map_err(|_| io::Error::other("noise"))?,
    })
}

/// Relay side.
pub async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    key: &RelayKey,
) -> io::Result<Link> {
    let mut hs = builder()?
        .local_private_key(&key.private)
        .map_err(|_| io::Error::other("key"))?
        .build_responder()
        .map_err(|_| io::Error::other("noise"))?;
    let mut msg = [0u8; HS];
    s.read_exact(&mut msg).await?;
    let mut buf = [0u8; 128];
    hs.read_message(&msg, &mut buf)
        .map_err(|_| io::Error::other("noise"))?;
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|_| io::Error::other("noise"))?;
    s.write_all(&buf[..n]).await?;
    Ok(Link {
        ts: hs
            .into_stateless_transport_mode()
            .map_err(|_| io::Error::other("noise"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_and_frames() {
        let key = RelayKey::generate().unwrap();
        let public = key.public;
        let (mut a, mut b) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move { respond(&mut b, &key).await.map(|l| (l, b)) });
        let client = initiate(&mut a, &public).await.unwrap();
        let (server, _b) = srv.await.unwrap().unwrap();
        let cell = [7u8; CELL];
        for n in 0..3 {
            let f = client.seal(n, &cell).unwrap();
            assert_eq!(f.len(), FRAME);
            assert_eq!(server.open(n, &f).unwrap(), cell);
            assert!(server.open(n + 1, &f).is_err(), "nonce bound");
        }
        assert_eq!(parse_key(&eigen_core::wire::base32(&public)), Some(public));
    }

    #[tokio::test]
    async fn wrong_relay_key_fails() {
        let key = RelayKey::generate().unwrap();
        let other = RelayKey::generate().unwrap().public;
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = respond(&mut b, &key).await;
        });
        assert!(
            initiate(&mut a, &other).await.is_err(),
            "impersonated relay detected"
        );
    }
}
