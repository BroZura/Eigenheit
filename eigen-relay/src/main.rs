#![forbid(unsafe_code)]
//! The EIGENHEIT relay server.
//!
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
    usage_exit(2)
}

fn usage_exit(code: i32) -> ! {
    // Prints the usage text and exits with code 2.
    println!(
        "Usage: eigen-relay [--listen ADDR] [--onion] [--control ADDR] [--tor-password PW]
                   [--i2p] [--sam ADDR] [--public ADDR]
                   [--pow-base N] [--max-ttl SECS] [--quiet] [--self-test]

Options:
  --listen ADDR      Address for unencrypted connections. Use it only on a
                     loopback address behind a Tor onion service, or for
                     development. Default: 127.0.0.1:7777.
  --onion            Publish the --listen address as a Tor onion service.
                     The onion address is new at every start and stops
                     working when the relay exits.
  --control ADDR     Address of the Tor control port. Default: 127.0.0.1:9051.
  --tor-password PW  Password for the Tor control port. If it is not given,
                     cookie authentication is used. If Tor requires no
                     authentication, none is used.
  --i2p              Publish an I2P destination through the SAM bridge. The
                     I2P address is new at every start and stops working
                     when the relay exits.
  --sam ADDR         Address of the I2P SAM bridge. Default: 127.0.0.1:7656.
  --public ADDR      Address for Noise-encrypted connections from clients on
                     a VPN or WireGuard network. The relay prints the address
                     for clients in the form IP:PORT#KEY. The key is new at
                     every start.
  --pow-base N       Base proof-of-work difficulty, in bits. Default: 12.
  --max-ttl SECS     Maximum time that a message is stored, in seconds.
                     Default: 86400.
  --quiet            Do not print the relay addresses at start-up.
  --self-test        Start a test relay, send traffic to it and check that
                     it prints nothing after start-up. On Linux, also check
                     that it writes nothing to disk and has no open files.
                     Then exit.

All data is kept in RAM only. Nothing is written to disk."
    );
    std::process::exit(code)
}

fn main() {
    // Panic messages could contain identifying data, so they are suppressed.
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
            "--help" | "-h" => usage_exit(0),
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
            println!("eigen-relay at {local} (unencrypted, for use behind Tor or for development only)");
        }
        // Tor removes the onion service when the control connection closes,
        // so the connection is kept open.
        let _ctl = if onion {
            match torctl::add_onion(&control, password.as_deref(), local.port()).await {
                Ok((addr, ctl)) => {
                    if !quiet {
                        println!("eigen-relay at {addr}:{}", local.port());
                    }
                    Some(ctl)
                }
                Err(_) => {
                    println!("Could not create the onion service through the Tor control port at {control}.");
                    std::process::exit(1)
                }
            }
        } else {
            None
        };
        // I2P uses a transient destination. The router removes it when the relay exits.
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
                    println!("Could not create an I2P session through the SAM bridge at {sam}. Check that the I2P router is running and can build tunnels.");
                    std::process::exit(1)
                }
            }
        }
        // Public listener for VPN and WireGuard clients. Connections use Noise
        // encryption with a key that is new at every start.
        if let Some(addr) = &public {
            let (Ok(key), Ok(pl)) = (RelayKey::generate(), tokio::net::TcpListener::bind(addr).await) else {
                println!("Could not listen on {addr}.");
                std::process::exit(1)
            };
            if !quiet {
                let at = pl.local_addr().map(|a| a.to_string()).unwrap_or_default();
                println!("eigen-relay at {at}#{} (encrypted; clients must use an address of this host that they can reach)", key.encoded());
            }
            tokio::spawn(relay.clone().serve_noise(pl, std::sync::Arc::new(key)));
        }
        let _ = std::io::stdout().flush();
        relay.serve_plain(listener).await;
    });
}

/// Checks that serving traffic produces no output and no disk writes.
/// Starts the relay as a child process, sends traffic to it and inspects the
/// child process.
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
        Ok(n) => println!("Self-test: {n} unencrypted cells exchanged."),
        Err(e) => fails.push(format!("unencrypted traffic error: {e}")),
    }
    match drive_noise(&noise_at) {
        Ok(n) => println!("Self-test: {n} encrypted frames exchanged."),
        Err(e) => fails.push(format!("encrypted traffic error: {e}")),
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
                fails.push(format!("the relay wrote {wb} bytes to disk"));
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
                    fails.push(format!("the relay has the file {t} open"));
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
            "the relay printed {} bytes after start-up",
            rest.len() + err.len()
        ));
    }
    if fails.is_empty() {
        println!("Self-test PASS: the relay printed nothing, wrote nothing to disk and had no files open while serving.");
        0
    } else {
        for f in fails {
            println!("Self-test FAIL: {f}.");
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
        )?; // Probably fails the proof-of-work check.
        call(&mut s, Op::Fetch { mbox, after: 0 })?;
        call(&mut s, Op::Take { mbox })?;
        call(&mut s, Op::Pad)?;
    }
    // An invalid cell must receive a response and must not produce output.
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
