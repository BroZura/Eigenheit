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
    /// Relay link key (`#key`): the link is Noise-encrypted and the relay authenticated.
    pub key: Option<[u8; 32]>,
}

impl RelayAddr {
    /// `x.onion:PORT`, `x.b32.i2p[:PORT]`, `HOST:PORT#KEY` (Noise), `HOST:PORT` (plain).
    pub fn parse(s: &str) -> Option<RelayAddr> {
        let s = s.trim();
        let (s, key) = match s.split_once('#') {
            Some((a, k)) => (a, Some(eigen_transport::noise::parse_key(k)?)),
            None => (s, None),
        };
        if s.ends_with(".i2p") {
            return Some(RelayAddr {
                host: s.to_string(),
                port: 0,
                key,
            });
        }
        let (h, p) = s.rsplit_once(':')?;
        let host = h.trim_matches(['[', ']']).to_string();
        if let Some(h) = host.strip_suffix(":0").filter(|h| h.ends_with(".i2p")) {
            return Some(RelayAddr {
                host: h.to_string(),
                port: 0,
                key,
            });
        }
        Some(RelayAddr {
            host,
            port: p.parse().ok()?,
            key,
        })
    }
    pub fn is_onion(&self) -> bool {
        self.host.ends_with(".onion")
    }
    pub fn is_i2p(&self) -> bool {
        self.host.ends_with(".i2p")
    }
    /// Reached directly over IP (optionally through a VPN/WireGuard interface).
    pub fn is_clear(&self) -> bool {
        !self.is_onion() && !self.is_i2p()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks5_handshake_carries_isolation() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 1, 2]);
            s.write_all(&[5, 2]).await.unwrap();
            let mut h = [0u8; 2];
            s.read_exact(&mut h).await.unwrap();
            let mut user = vec![0u8; h[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[1, 0]).await.unwrap();
            let mut c = [0u8; 5];
            s.read_exact(&mut c).await.unwrap();
            let mut host = vec![0u8; c[4] as usize + 2];
            s.read_exact(&mut host).await.unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            s.write_all(b"ok").await.unwrap();
            (
                String::from_utf8(user).unwrap(),
                String::from_utf8(host[..host.len() - 2].to_vec()).unwrap(),
            )
        });
        let mut s = connect(&addr, "x.onion", 7777, "circuit-a").await.unwrap();
        let mut ok = [0u8; 2];
        s.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"ok");
        let (user, host) = srv.await.unwrap();
        assert_eq!(user, "circuit-a");
        assert_eq!(host, "x.onion");
    }

    #[test]
    fn parse_transport_forms() {
        let i = RelayAddr::parse("abcd.b32.i2p").unwrap();
        assert!(i.is_i2p() && !i.is_clear());
        let key = eigen_core::wire::base32(&[5u8; 32]);
        let n = RelayAddr::parse(&format!("10.0.0.1:7778#{key}")).unwrap();
        assert!(n.is_clear() && n.key == Some([5u8; 32]) && n.port == 7778);
        assert!(RelayAddr::parse("10.0.0.1:7778#notakey").is_none());
        assert!(RelayAddr::parse("1.2.3.4:7777").unwrap().key.is_none());
    }

    #[test]
    fn parse_addrs() {
        let a = RelayAddr::parse("abc.onion:7777").unwrap();
        assert!(a.is_onion());
        assert!(!RelayAddr::parse("127.0.0.1:7777").unwrap().is_onion());
        assert!(RelayAddr::parse("nope").is_none());
    }
}
