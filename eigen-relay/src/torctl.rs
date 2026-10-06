//! Tor control port client: just enough to publish an ephemeral onion service.
use std::io;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct Control {
    _stream: BufReader<TcpStream>,
}

/// Authenticate and run `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK`.
/// The private key is discarded by tor: the address dies with this process.
pub async fn add_onion(addr: &str, password: Option<&str>, port: u16) -> io::Result<(String, Control)> {
    let mut s = BufReader::new(TcpStream::connect(addr).await?);
    let proto = cmd(&mut s, "PROTOCOLINFO 1").await?;
    let auth = if let Some(pw) = password {
        format!("AUTHENTICATE \"{}\"", pw.replace('\\', "\\\\").replace('"', "\\\""))
    } else if proto.iter().any(|l| l.contains("METHODS=NULL") || l.contains("NULL")) && !proto.iter().any(|l| l.contains("COOKIE")) {
        "AUTHENTICATE".to_string()
    } else {
        let path = proto
            .iter()
            .find_map(|l| l.split("COOKIEFILE=\"").nth(1).and_then(|r| r.split('"').next()))
            .ok_or_else(|| io::Error::other("no auth"))?;
        let cookie = std::fs::read(path)?;
        format!("AUTHENTICATE {}", eigen_core::wire::hex(&cookie))
    };
    cmd(&mut s, &auth).await?;
    let lines = cmd(&mut s, &format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={port},127.0.0.1:{port}")).await?;
    let id = lines
        .iter()
        .find_map(|l| l.strip_prefix("250-ServiceID="))
        .ok_or_else(|| io::Error::other("no service id"))?;
    Ok((format!("{id}.onion"), Control { _stream: s }))
}

async fn cmd(s: &mut BufReader<TcpStream>, line: &str) -> io::Result<Vec<String>> {
    s.get_mut().write_all(format!("{line}\r\n").as_bytes()).await?;
    let mut out = Vec::new();
    loop {
        let mut l = String::new();
        if s.read_line(&mut l).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let l = l.trim_end().to_string();
        let done = l.len() >= 4 && &l[3..4] == " ";
        if !l.starts_with("250") {
            return Err(io::Error::other("refused"));
        }
        out.push(l);
        if done {
            return Ok(out);
        }
    }
}
