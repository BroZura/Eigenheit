//! Minimal SOCKS5 client (RFC 1928/1929) for a local tor daemon.
//! Username/password are random per mask/union: tor's IsolateSOCKSAuth then puts
//! each on its own circuit.
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn connect(socks: &str, host: &str, port: u16, isolation: &str) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks).await?;
    s.write_all(&[5, 1, 2]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r != [5, 2] {
        return Err(io::Error::other("socks: no user/pass auth"));
    }
    let user = isolation.as_bytes();
    let pass = b"eigen";
    if user.len() > 255 || host.len() > 255 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut a = vec![1, user.len() as u8];
    a.extend_from_slice(user);
    a.push(pass.len() as u8);
    a.extend_from_slice(pass);
    s.write_all(&a).await?;
    s.read_exact(&mut r).await?;
    if r[1] != 0 {
        return Err(io::Error::other("socks: auth refused"));
    }
    let mut c = vec![5, 1, 0, 3, host.len() as u8];
    c.extend_from_slice(host.as_bytes());
    c.extend_from_slice(&port.to_be_bytes());
    s.write_all(&c).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(io::Error::other("socks: connect refused"));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(io::Error::other("socks: bad reply")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

/// A relay address: `host:port`. Only `.onion` hosts are acceptable without consent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAddr {
    pub host: String,
    pub port: u16,
}

impl RelayAddr {
    pub fn parse(s: &str) -> Option<RelayAddr> {
        let (h, p) = s.trim().rsplit_once(':')?;
        Some(RelayAddr { host: h.trim_matches(['[', ']']).to_string(), port: p.parse().ok()? })
    }
    pub fn is_onion(&self) -> bool {
        self.host.ends_with(".onion")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addrs() {
        let a = RelayAddr::parse("abc.onion:7777").unwrap();
        assert!(a.is_onion());
        assert!(!RelayAddr::parse("127.0.0.1:7777").unwrap().is_onion());
        assert!(RelayAddr::parse("nope").is_none());
    }
}
