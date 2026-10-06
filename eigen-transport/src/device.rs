//! Connections bound to one network interface (a VPN or WireGuard tunnel), using
//! SO_BINDTODEVICE. If the tunnel is down, the connection fails. Traffic is never
//! sent over another route. Host names are refused in this mode, because
//! resolving them would send a DNS query outside the tunnel.
use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    WireGuard,
    Tunnel,
    Other,
}

/// Checks that the interface exists and returns its kind. Reads /sys/class/net (Linux).
pub fn inspect(name: &str) -> io::Result<Kind> {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let base = format!("/sys/class/net/{name}");
    std::fs::metadata(&base)?;
    let uevent = std::fs::read_to_string(format!("{base}/uevent")).unwrap_or_default();
    if uevent.lines().any(|l| l == "DEVTYPE=wireguard") {
        return Ok(Kind::WireGuard);
    }
    // ARPHRD_NONE (65534) is used by tun-style VPN interfaces.
    let ty = std::fs::read_to_string(format!("{base}/type")).unwrap_or_default();
    Ok(if ty.trim() == "65534" {
        Kind::Tunnel
    } else {
        Kind::Other
    })
}

/// Connects to `host`. If `device` is set, `host` must be an IP address and the
/// connection is bound to that interface.
pub async fn connect(host: &str, port: u16, device: Option<&str>) -> io::Result<TcpStream> {
    let Some(dev) = device else {
        return TcpStream::connect((host, port)).await;
    };
    let ip: IpAddr = host.trim_matches(['[', ']']).parse().map_err(|_| {
        io::Error::other(
            "An IP address is required when connections are bound to an interface, because a DNS lookup would leave the tunnel",
        )
    })?;
    let addr = SocketAddr::new(ip, port);
    let sock = if ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    bind(&sock, dev)?;
    sock.connect(addr).await
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind(sock: &TcpSocket, dev: &str) -> io::Result<()> {
    sock.bind_device(Some(dev.as_bytes()))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bind(_: &TcpSocket, _: &str) -> io::Result<()> {
    Err(io::Error::other(
        "Binding to a network interface requires Linux or Android",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bound_dial_works_and_fails_closed() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { while l.accept().await.is_ok() {} });
        assert!(connect("127.0.0.1", port, Some("lo")).await.is_ok());
        assert!(
            connect("127.0.0.1", port, Some("eigen-nope0"))
                .await
                .is_err(),
            "missing tunnel must fail"
        );
        assert!(
            connect("localhost", port, Some("lo")).await.is_err(),
            "host names must be refused when bound to an interface"
        );
        assert!(inspect("lo").is_ok());
        assert!(inspect("eigen-nope0").is_err());
        assert!(inspect("../etc").is_err());
    }
}
