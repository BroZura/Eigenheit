//! Transports for connecting to a relay.
//! - `noise`: an encrypted link (Noise NK) for relays reached directly or over a VPN.
//! - `sam`: I2P streaming through the SAM v3 bridge of a local router.
//! - `device`: connections bound to one network interface (VPN or WireGuard).
//!   If the interface is not available, the connection fails.
#![forbid(unsafe_code)]

pub mod device;
pub mod noise;
pub mod sam;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Reads one `\n`-terminated line byte by byte, so that no data after the line is consumed.
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
            return Err(std::io::Error::other("Line is too long"));
        }
        out.push(b[0]);
    }
    String::from_utf8(out)
        .map(|l| l.trim_end_matches('\r').to_string())
        .map_err(|_| std::io::Error::other("Line is not valid UTF-8"))
}
