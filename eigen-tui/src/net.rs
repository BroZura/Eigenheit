//! A link to one relay: fixed cells, one request → one response, optional
//! constant-rate cover traffic and random delivery delay.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use eigen_core::cell::{Mbox, Op, Request, Response, Status, CELL};
use eigen_core::crypto::random_u64;
use eigen_core::pow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::tor::{self, RelayAddr};

#[derive(Clone, Debug)]
pub struct LinkCfg {
    pub relay: RelayAddr,
    /// SOCKS5 proxy (tor). `None` = direct TCP (only with consent).
    pub socks: Option<String>,
    /// Circuit isolation tag; one per mask/union.
    pub isolation: String,
    /// Cover traffic: one cell every `cover_ms` ± 30 %, always.
    pub cover: Arc<AtomicBool>,
    pub cover_ms: u64,
    /// Without cover: PUTs wait a random 0..max_delay_ms before release.
    pub max_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    Down,
    Refused,
}

struct Job {
    op: Op,
    reply: oneshot::Sender<Status>,
}

/// Link state: 0 = connecting, 1 = up, 2 = down.
#[derive(Clone)]
pub struct Link {
    tx: mpsc::UnboundedSender<Job>,
    pub state: Arc<AtomicU8>,
}

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Status>>>>;

fn jitter(base: u64) -> Duration {
    let spread = base * 3 / 10;
    let off = if spread == 0 { 0 } else { random_u64() % (2 * spread + 1) };
    Duration::from_millis(base - spread + off)
}

impl Link {
    pub fn spawn(cfg: LinkCfg) -> Link {
        let (tx, rx) = mpsc::unbounded_channel();
        let state = Arc::new(AtomicU8::new(0));
        tokio::spawn(run(cfg, rx, state.clone()));
        Link { tx, state }
    }

    pub fn is_up(&self) -> bool {
        self.state.load(Ordering::Relaxed) == 1
    }

    pub async fn call(&self, op: Op) -> Result<Status, LinkError> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Job { op, reply }).map_err(|_| LinkError::Down)?;
        rx.await.map_err(|_| LinkError::Down)
    }

    /// PUT with proof of work (at least `min_bits`), retrying when the relay asks for more.
    pub async fn put(&self, mbox: Mbox, ttl: u32, blob: Vec<u8>, min_bits: u8) -> Result<(), LinkError> {
        let mut bits = min_bits;
        for _ in 0..4 {
            let hour = pow::hour_now();
            let b = blob.clone();
            let nonce = tokio::task::spawn_blocking(move || pow::solve(hour, &mbox, &b, bits))
                .await
                .map_err(|_| LinkError::Down)?;
            match self.call(Op::Put { mbox, ttl, hour, nonce, blob: blob.clone() }).await? {
                Status::Ok => return Ok(()),
                Status::Pow(need) if need > bits && need <= 30 => bits = need,
                _ => return Err(LinkError::Refused),
            }
        }
        Err(LinkError::Refused)
    }

    /// All items in a mailbox after `after`, one cell at a time.
    pub async fn fetch_all(&self, mbox: Mbox, mut after: u64, limit: usize) -> Result<Vec<eigen_core::cell::Item>, LinkError> {
        let mut out = Vec::new();
        while out.len() < limit {
            match self.call(Op::Fetch { mbox, after }).await? {
                Status::Item(it) => {
                    after = it.seq;
                    let more = it.more;
                    out.push(it);
                    if !more {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(out)
    }

    pub async fn take(&self, mbox: Mbox) -> Result<Option<eigen_core::cell::Item>, LinkError> {
        match self.call(Op::Take { mbox }).await? {
            Status::Item(it) => Ok(Some(it)),
            _ => Ok(None),
        }
    }
}

async fn connect(cfg: &LinkCfg) -> std::io::Result<TcpStream> {
    let s = match &cfg.socks {
        Some(socks) => tor::connect(socks, &cfg.relay.host, cfg.relay.port, &cfg.isolation).await?,
        None => TcpStream::connect((cfg.relay.host.as_str(), cfg.relay.port)).await?,
    };
    let _ = s.set_nodelay(true);
    Ok(s)
}

async fn run(cfg: LinkCfg, mut rx: mpsc::UnboundedReceiver<Job>, state: Arc<AtomicU8>) {
    let mut backoff = 1u64;
    let mut held: Option<Job> = None;
    loop {
        state.store(0, Ordering::Relaxed);
        let sock = match tokio::time::timeout(Duration::from_secs(60), connect(&cfg)).await {
            Ok(Ok(s)) => s,
            _ => {
                state.store(2, Ordering::Relaxed);
                // Fail queued work rather than let it pile up silently.
                if let Some(j) = held.take() {
                    drop(j.reply);
                }
                while let Ok(j) = rx.try_recv() {
                    drop(j.reply);
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
                continue;
            }
        };
        backoff = 1;
        state.store(1, Ordering::Relaxed);
        let (mut rd, mut wr) = sock.into_split();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let p2 = pending.clone();
        let mut reader = tokio::spawn(async move {
            let mut cell = [0u8; CELL];
            loop {
                if rd.read_exact(&mut cell).await.is_err() {
                    return;
                }
                if let Ok(r) = Response::decode(&cell) {
                    if let Some(tx) = p2.lock().await.remove(&r.rid) {
                        let _ = tx.send(r.status);
                    }
                }
            }
        });
        let mut rid: u32 = random_u64() as u32;
        let mut tick = tokio::time::interval(jitter(cfg.cover_ms.max(50)));
        loop {
            let cover = cfg.cover.load(Ordering::Relaxed);
            let job = if let Some(j) = held.take() {
                Some(j)
            } else if cover {
                tokio::select! {
                    _ = tick.tick() => {
                        tick.reset_after(jitter(cfg.cover_ms.max(50)));
                        // Exactly one cell per tick: real work if queued, else padding.
                        rx.try_recv().ok()
                    }
                    _ = &mut reader => break,
                }
            } else {
                tokio::select! {
                    j = rx.recv() => match j { Some(j) => Some(j), None => return },
                    _ = tokio::time::sleep(Duration::from_secs(120)) => None, // keepalive pad
                    _ = &mut reader => break,
                }
            };
            if !cover {
                if let Some(Job { op: Op::Put { .. }, .. }) = &job {
                    if cfg.max_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(random_u64() % cfg.max_delay_ms)).await;
                    }
                }
            }
            rid = rid.wrapping_add(1);
            let (op, reply) = match job {
                Some(j) => (j.op, Some(j.reply)),
                None => (Op::Pad, None),
            };
            let Ok(cell) = (Request { rid, op: op.clone() }).encode() else { continue };
            if let Some(r) = reply {
                pending.lock().await.insert(rid, r);
            }
            if wr.write_all(&cell).await.is_err() {
                // Re-queue the job that did not make it.
                if let Some(r) = pending.lock().await.remove(&rid) {
                    held = Some(Job { op, reply: r });
                }
                break;
            }
        }
        reader.abort();
        pending.lock().await.clear();
        state.store(2, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
pub mod testutil {
    use super::*;

    pub async fn relay() -> RelayAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(eigen_relay::serve(l, eigen_relay::Config { pow_base: 4, ..Default::default() }));
        RelayAddr { host: "127.0.0.1".into(), port }
    }

    pub fn cfg(relay: RelayAddr, cover: bool) -> LinkCfg {
        LinkCfg { relay, socks: None, isolation: "t".into(), cover: Arc::new(AtomicBool::new(cover)), cover_ms: 20, max_delay_ms: 5 }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[tokio::test]
    async fn put_fetch_take_over_tcp() {
        for cover in [false, true] {
            let link = Link::spawn(cfg(relay().await, cover));
            let m = [9u8; 32];
            for i in 0..3u8 {
                link.put(m, 60, eigen_core::cell::blob(&[i]).unwrap(), 6).await.unwrap();
            }
            let all = link.fetch_all(m, 0, 10).await.unwrap();
            assert_eq!(all.len(), 3);
            assert_eq!(all[2].blob[0], 2);
            assert!(link.take(m).await.unwrap().is_some());
            assert_eq!(link.fetch_all(m, 0, 10).await.unwrap().len(), 2);
        }
    }
}
