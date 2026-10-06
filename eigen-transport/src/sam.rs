//! I2P through the SAM v3 bridge of a local router (i2pd or Java I2P, default
//! 127.0.0.1:7656). Every session uses a TRANSIENT destination, so nothing is
//! stored. Each mask, direct message and union uses its own session with its own
//! tunnels, so they cannot be linked through I2P.
use std::io;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::read_line;

pub const DEFAULT_SAM: &str = "127.0.0.1:7656";

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

fn ok(line: &str) -> io::Result<()> {
    if field(line, "RESULT") == Some("OK") {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "I2P router refused the request: {}",
            field(line, "RESULT").unwrap_or("?")
        )))
    }
}

async fn cmd(s: &mut TcpStream, line: &str) -> io::Result<String> {
    s.write_all(line.as_bytes()).await?;
    s.write_all(b"\n").await?;
    read_line(s, 4096).await
}

async fn hello(sam: &str) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(sam).await?;
    let r = cmd(&mut s, "HELLO VERSION MIN=3.1 MAX=3.3").await?;
    ok(&r)?;
    Ok(s)
}

/// A streaming session with a transient destination. Dropping it closes the
/// control socket, and the router removes the destination.
pub struct Session {
    _control: TcpStream,
    pub id: String,
    /// Public destination of this session (I2P base64).
    pub dest: String,
    sam: String,
}

impl Session {
    pub async fn create(sam: &str) -> io::Result<Session> {
        let mut s = hello(sam).await?;
        let id = format!(
            "eigen{}",
            eigen_core::wire::hex(&eigen_core::crypto::random::<6>())
        );
        // Ed25519 destination, ECIES-X25519 lease sets, two inbound and two outbound tunnels.
        let r = cmd(
            &mut s,
            &format!("SESSION CREATE STYLE=STREAM ID={id} DESTINATION=TRANSIENT SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4 inbound.quantity=2 outbound.quantity=2"),
        )
        .await?;
        ok(&r)?;
        let r = cmd(&mut s, "NAMING LOOKUP NAME=ME").await?;
        ok(&r)?;
        let dest = field(&r, "VALUE")
            .ok_or_else(|| io::Error::other("SAM bridge returned no destination"))?
            .to_string();
        Ok(Session {
            _control: s,
            id,
            dest,
            sam: sam.to_string(),
        })
    }

    /// The `.b32.i2p` address of this session, in the form that clients use.
    pub fn b32(&self) -> io::Result<String> {
        b32(&self.dest)
    }

    pub async fn connect(&self, target: &str) -> io::Result<TcpStream> {
        let mut s = hello(&self.sam).await?;
        let dest = if target.ends_with(".i2p") {
            let r = cmd(&mut s, &format!("NAMING LOOKUP NAME={target}")).await?;
            ok(&r)?;
            field(&r, "VALUE")
                .ok_or_else(|| io::Error::other("Unknown I2P name"))?
                .to_string()
        } else {
            target.to_string()
        };
        let r = cmd(
            &mut s,
            &format!(
                "STREAM CONNECT ID={} DESTINATION={dest} SILENT=false",
                self.id
            ),
        )
        .await?;
        ok(&r)?;
        Ok(s)
    }

    /// Waits for one incoming stream. The line with the peer's destination is
    /// read and discarded. The relay does not store it.
    pub async fn accept(&self) -> io::Result<TcpStream> {
        let mut s = hello(&self.sam).await?;
        let r = cmd(
            &mut s,
            &format!("STREAM ACCEPT ID={} SILENT=false", self.id),
        )
        .await?;
        ok(&r)?;
        let _peer = read_line(&mut s, 4096).await?;
        Ok(s)
    }
}

/// Decodes I2P base64, which uses `-` and `~` for the values 62 and 63.
fn i2p_b64_decode(s: &str) -> io::Result<Vec<u8>> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = A
            .iter()
            .position(|x| *x == c)
            .ok_or_else(|| io::Error::other("Invalid I2P destination"))? as u32;
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

/// `<base32(sha256(destination))>.b32.i2p`
pub fn b32(dest: &str) -> io::Result<String> {
    let raw = i2p_b64_decode(dest)?;
    Ok(format!(
        "{}.b32.i2p",
        eigen_core::wire::base32(&Sha256::digest(&raw))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal fake SAM bridge for testing create, connect and accept.
    async fn fake_sam() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    loop {
                        let Ok(line) = read_line(&mut s, 4096).await else {
                            return;
                        };
                        let reply = if line.starts_with("HELLO") {
                            "HELLO REPLY RESULT=OK VERSION=3.3".to_string()
                        } else if line.starts_with("SESSION CREATE") {
                            assert!(line.contains("DESTINATION=TRANSIENT"));
                            "SESSION STATUS RESULT=OK DESTINATION=PRIVATE".to_string()
                        } else if line.starts_with("NAMING LOOKUP NAME=ME") {
                            "NAMING REPLY RESULT=OK NAME=ME VALUE=AAAA-~~~".to_string()
                        } else if line.starts_with("NAMING LOOKUP") {
                            "NAMING REPLY RESULT=OK NAME=x VALUE=BBBB".to_string()
                        } else if line.starts_with("STREAM CONNECT") {
                            assert!(line.contains("DESTINATION=BBBB"));
                            s.write_all(b"STREAM STATUS RESULT=OK\n").await.unwrap();
                            // Echo the stream.
                            let mut b = [0u8; 4];
                            s.read_exact(&mut b).await.unwrap();
                            s.write_all(&b).await.unwrap();
                            return;
                        } else if line.starts_with("STREAM ACCEPT") {
                            s.write_all(
                                b"STREAM STATUS RESULT=OK\nPEERDEST FROM_PORT=0 TO_PORT=0\nping",
                            )
                            .await
                            .unwrap();
                            return;
                        } else {
                            "ERROR RESULT=I2P_ERROR".to_string()
                        };
                        s.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn session_connect_accept() {
        let sam = fake_sam().await;
        let sess = Session::create(&sam).await.unwrap();
        assert_eq!(sess.dest, "AAAA-~~~");
        assert!(sess.b32().unwrap().ends_with(".b32.i2p"));
        let mut c = sess.connect("abc.b32.i2p").await.unwrap();
        c.write_all(b"cell").await.unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"cell");
        // Accept discards the peer's destination and returns the stream unchanged.
        let mut a = sess.accept().await.unwrap();
        let mut p = [0u8; 4];
        a.read_exact(&mut p).await.unwrap();
        assert_eq!(&p, b"ping");
    }

    #[test]
    fn b32_shape() {
        let b = b32("AAAA").unwrap();
        assert_eq!(b.len(), 52 + 8);
    }
}
