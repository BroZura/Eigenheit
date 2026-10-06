#![forbid(unsafe_code)]
//! eigen-relay [--listen ADDR] [--onion] [--control ADDR] [--tor-password PW]
//!             [--i2p] [--sam ADDR] [--public ADDR]
//!             [--pow-base N] [--max-ttl SECS] [--quiet] [--self-test]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use eigen_core::cell::{Op, Request, Response, Status, CELL};
use eigen_relay::{torctl, Config, Relay};
use eigen_transport::noise::RelayKey;

fn usage() -> ! {
    // Usage goes to stdout only when asked for; exit code says the rest.
    println!("eigen-relay [--listen 127.0.0.1:7777] [--onion] [--control 127.0.0.1:9051] [--tor-password PW]
            [--i2p] [--sam 127.0.0.1:7656] [--public 0.0.0.0:7778]
            [--pow-base 12] [--max-ttl 86400] [--quiet] [--self-test]

  --listen  plain cells on loopback (behind tor / for development)
  --onion   publish --listen as an ephemeral tor onion service
  --i2p     publish an ephemeral I2P destination via the SAM bridge
  --public  Noise-encrypted listener for clients on VPN/WireGuard; prints HOST:PORT#KEY");
    std::process::exit(2)
}

fn main() {
    // A panic message could carry identifiers. Say nothing.
    std::panic::set_hook(Box::new(|_| {}));
    let mut listen = "127.0.0.1:7777".to_string();
    let mut control = "127.0.0.1:9051".to_string();
    let mut password: Option<String> = None;
    let (mut onion, mut quiet, mut i2p) = (false, false, false);
    let mut public: Option<String> = None;
    let mut sam = eigen_transport::sam::DEFAULT_SAM.to_string();
    let mut cfg = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--listen" => listen = val(),
            "--control" => control = val(),
            "--tor-password" => password = Some(val()),
            "--onion" => onion = true,
            "--i2p" => i2p = true,
            "--sam" => sam = val(),
            "--public" => public = Some(val()),
            "--quiet" => quiet = true,
            "--pow-base" => cfg.pow_base = val().parse().unwrap_or_else(|_| usage()),
            "--max-ttl" => cfg.max_ttl = val().parse().unwrap_or_else(|_| usage()),
            "--self-test" => std::process::exit(self_test()),
            _ => usage(),
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|_| std::process::exit(1));
    rt.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::bind(&listen).await else {
            std::process::exit(1)
        };
        let Ok(local) = listener.local_addr() else {
            std::process::exit(1)
        };
        let relay = Relay::start(cfg);
        if !onion && !quiet {
            println!("eigen-relay at {local} (plain cells: behind tor, or development only)");
        }
        // Keep the control connection alive: the onion service dies with it.
        let _ctl = if onion {
            match torctl::add_onion(&control, password.as_deref(), local.port()).await {
                Ok((addr, ctl)) => {
                    if !quiet {
                        println!("eigen-relay at {addr}:{}", local.port());
                    }
                    Some(ctl)
                }
                Err(_) => {
                    println!("tor control port refused the onion service");
                    std::process::exit(1)
                }
            }
        } else {
            None
        };
        // I2P: a transient destination, forgotten by the router when I exit.
        if i2p {
            match eigen_transport::sam::Session::create(&sam).await {
                Ok(sess) => {
                    let b32 = sess.b32().unwrap_or_default();
                    if !quiet {
                        println!("eigen-relay at {b32}");
                    }
                    tokio::spawn(relay.clone().serve_i2p(std::sync::Arc::new(sess)));
                }
                Err(_) => {
                    println!("no i2p session from the SAM bridge at {sam} (router down, or it could not build tunnels)");
                    std::process::exit(1)
                }
            }
        }
        // Public listener for VPN/WireGuard clients: Noise-encrypted, ephemeral key.
        if let Some(addr) = &public {
            let (Ok(key), Ok(pl)) = (RelayKey::generate(), tokio::net::TcpListener::bind(addr).await) else {
                println!("cannot listen on {addr}");
                std::process::exit(1)
            };
            if !quiet {
                let at = pl.local_addr().map(|a| a.to_string()).unwrap_or_default();
                println!("eigen-relay at {at}#{} (noise; use the address clients can reach)", key.encoded());
            }
            tokio::spawn(relay.clone().serve_noise(pl, std::sync::Arc::new(key)));
        }
        let _ = std::io::stdout().flush();
        relay.serve_plain(listener).await;
    });
}

/// Prove that serving traffic produces no output and no file writes.
/// Spawns the relay as a child process, drives traffic, inspects the child.
fn self_test() -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    let mut child = match Command::new(exe)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--public",
            "127.0.0.1:0",
            "--pow-base",
            "4",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };
    let pid = child.id();
    let mut out = BufReader::new(child.stdout.take().expect("piped"));
    let mut first = String::new();
    let _ = out.read_line(&mut first);
    let addr = first.split_whitespace().nth(2).unwrap_or("").to_string();
    let mut second = String::new();
    let _ = out.read_line(&mut second);
    let noise_at = second.split_whitespace().nth(2).unwrap_or("").to_string();
    let mut fails: Vec<String> = Vec::new();
    match drive(&addr) {
        Ok(n) => println!("self-test: {n} plain cells exchanged"),
        Err(e) => fails.push(format!("traffic failed: {e}")),
    }
    match drive_noise(&noise_at) {
        Ok(n) => println!("self-test: {n} noise frames exchanged"),
        Err(e) => fails.push(format!("noise traffic failed: {e}")),
    }
    std::thread::sleep(Duration::from_millis(300));
    #[cfg(target_os = "linux")]
    {
        if let Ok(io) = std::fs::read_to_string(format!("/proc/{pid}/io")) {
            let wb = io
                .lines()
                .find_map(|l| l.strip_prefix("write_bytes: "))
                .unwrap_or("0")
                .trim()
                .to_string();
            if wb != "0" {
                fails.push(format!("child wrote {wb} bytes to storage"));
            }
        }
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
            for e in rd.flatten() {
                let t = std::fs::read_link(e.path())
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let ok = t.starts_with("socket:")
                    || t.starts_with("pipe:")
                    || t.starts_with("anon_inode:")
                    || t.starts_with("/dev/");
                if !ok {
                    fails.push(format!("child holds file {t}"));
                }
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let mut rest = String::new();
    let _ = out.read_to_string(&mut rest);
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    if !rest.is_empty() || !err.is_empty() {
        fails.push(format!(
            "child printed {} bytes after startup",
            rest.len() + err.len()
        ));
    }
    if fails.is_empty() {
        println!("self-test: no log lines, no disk writes, no files held — PASS");
        0
    } else {
        for f in fails {
            println!("self-test FAIL: {f}");
        }
        1
    }
}

fn drive(addr: &str) -> std::io::Result<usize> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut n = 0;
    let mut call = |s: &mut TcpStream, op: Op| -> std::io::Result<Status> {
        n += 1;
        let c = Request { rid: n as u32, op }
            .encode()
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
        s.write_all(&c)?;
        let mut r = [0u8; CELL];
        s.read_exact(&mut r)?;
        Response::decode(&r)
            .map(|r| r.status)
            .map_err(|_| std::io::ErrorKind::InvalidData.into())
    };
    for i in 0..64u8 {
        let mbox = eigen_core::crypto::h(&[&[i % 4]]);
        let blob =
            eigen_core::cell::blob(&[i; 100]).map_err(|_| std::io::ErrorKind::InvalidData)?;
        let hour = eigen_core::pow::hour_now();
        let nonce = eigen_core::pow::solve(hour, &mbox, &blob, 10);
        call(
            &mut s,
            Op::Put {
                mbox,
                ttl: 30,
                hour,
                nonce,
                blob: blob.clone(),
            },
        )?;
        call(
            &mut s,
            Op::Put {
                mbox,
                ttl: 30,
                hour,
                nonce: nonce ^ 1,
                blob,
            },
        )?; // likely bad PoW
        call(&mut s, Op::Fetch { mbox, after: 0 })?;
        call(&mut s, Op::Take { mbox })?;
        call(&mut s, Op::Pad)?;
    }
    // Garbage cells must be answered, not logged.
    s.write_all(&[0xff; CELL])?;
    let mut r = [0u8; CELL];
    s.read_exact(&mut r)?;
    Ok(n + 1)
}

fn drive_noise(spec: &str) -> std::io::Result<usize> {
    let (addr, key) = spec
        .split_once('#')
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    let key = eigen_transport::noise::parse_key(key).ok_or(std::io::ErrorKind::InvalidInput)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await?;
        let link = eigen_transport::noise::initiate(&mut s, &key).await?;
        let mut n = 0u64;
        for i in 0..32u8 {
            let mbox = eigen_core::crypto::h(&[&[i % 4, 9]]);
            let blob =
                eigen_core::cell::blob(&[i; 64]).map_err(|_| std::io::ErrorKind::InvalidData)?;
            let hour = eigen_core::pow::hour_now();
            let nonce = eigen_core::pow::solve(hour, &mbox, &blob, 10);
            for op in [
                Op::Put {
                    mbox,
                    ttl: 30,
                    hour,
                    nonce,
                    blob,
                },
                Op::Fetch { mbox, after: 0 },
                Op::Pad,
            ] {
                let c = Request { rid: n as u32, op }
                    .encode()
                    .map_err(|_| std::io::ErrorKind::InvalidData)?;
                s.write_all(&link.seal(n, &c)?).await?;
                let mut f = [0u8; eigen_transport::noise::FRAME];
                s.read_exact(&mut f).await?;
                Response::decode(&link.open(n, &f)?)
                    .map_err(|_| std::io::ErrorKind::InvalidData)?;
                n += 1;
            }
        }
        Ok(n as usize)
    })
}
