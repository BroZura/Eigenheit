//! Ways to reach a relay without telling the network who I am or what I fetch.
//! - `noise`: an encrypted link (Noise NK) for relays reached over clear-net/VPN.
//! - `sam`: I2P streaming via the SAM v3 bridge of a local router.
//! - `device`: dial bound to one network interface (VPN/WireGuard), failing closed.
#![forbid(unsafe_code)]

pub mod device;
pub mod noise;
pub mod sam;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Read one `\n`-terminated line byte by byte, so nothing after it is consumed.
pub(crate) async fn read_line<S: AsyncRead + Unpin>(
    s: &mut S,
    max: usize,
) -> std::io::Result<String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b).await?;
        if b[0] == b'\n' {
            break;
        }
        if out.len() >= max {
            return Err(std::io::Error::other("line too long"));
        }
        out.push(b[0]);
    }
    String::from_utf8(out)
        .map(|l| l.trim_end_matches('\r').to_string())
        .map_err(|_| std::io::Error::other("not utf-8"))
}
