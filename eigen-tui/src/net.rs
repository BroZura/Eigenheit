//! A link to one relay. It sends fixed-size cells, one response per request,
//! with optional constant-rate cover traffic and a random delivery delay.
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
use eigen_transport::{device, noise, sam};

#[derive(Clone, Debug)]
pub struct LinkCfg {
    pub relay: RelayAddr,
    /// SOCKS5 proxy address for Tor. It is set only for `.onion` relays.
    pub socks: Option<String>,
    /// Circuit isolation tag. Each mask, direct message and union has its own tag.
    pub isolation: String,
    /// Cover traffic. When it is on, one cell is sent every `cover_ms` ± 30 %.
    pub cover: Arc<AtomicBool>,
    pub cover_ms: u64,
    /// When cover traffic is off, each PUT waits a random 0..max_delay_ms before it is sent.
    pub max_delay_ms: u64,
    /// I2P SAM bridge, for `.i2p` relays. Each link gets its own transient destination.
    pub sam: Option<String>,
    /// VPN or WireGuard interface that every direct connection is bound to.
    /// If the interface is not available, the connection fails.
    pub device: Option<String>,
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
    let off = if spread == 0 {
        0
    } else {
        random_u64() % (2 * spread + 1)
    };
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
        self.tx
            .send(Job { op, reply })
            .map_err(|_| LinkError::Down)?;
        rx.await.map_err(|_| LinkError::Down)
    }

    /// PUT with proof of work (at least `min_bits`), retrying when the relay asks for more.
    pub async fn put(
        &self,
        mbox: Mbox,
        ttl: u32,
        blob: Vec<u8>,
        min_bits: u8,
    ) -> Result<(), LinkError> {
        let mut bits = min_bits;
        for _ in 0..4 {
            let hour = pow::hour_now();
            let b = blob.clone();
            let nonce = tokio::task::spawn_blocking(move || pow::solve(hour, &mbox, &b, bits))
                .await
                .map_err(|_| LinkError::Down)?;
            match self
                .call(Op::Put {
                    mbox,
                    ttl,
                    hour,
                    nonce,
                    blob: blob.clone(),
                })
                .await?
            {
                Status::Ok => return Ok(()),
                Status::Pow(need) if need > bits && need <= 30 => bits = need,
                _ => return Err(LinkError::Refused),
            }
        }
        Err(LinkError::Refused)
    }

    /// All items in a mailbox after `after`, one cell at a time.
    pub async fn fetch_all(
        &self,
        mbox: Mbox,
        mut after: u64,
        limit: usize,
    ) -> Result<Vec<eigen_core::cell::Item>, LinkError> {
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

struct Conn {
    sock: TcpStream,
    noise: Option<Arc<noise::Link>>,
    /// The I2P session must outlive the stream it carries.
    _sam: Option<sam::Session>,
}

async fn connect(cfg: &LinkCfg) -> std::io::Result<Conn> {
    let r = &cfg.relay;
    let (mut sock, session) = if r.is_onion() {
        let socks = cfg
            .socks
            .as_deref()
            .ok_or_else(|| std::io::Error::other("An onion relay requires a Tor SOCKS proxy"))?;
        (
            tor::connect(socks, &r.host, r.port, &cfg.isolation).await?,
            None,
        )
    } else if r.is_i2p() {
        let bridge = cfg
            .sam
            .as_deref()
            .ok_or_else(|| std::io::Error::other("An I2P relay requires a SAM bridge"))?;
        let s = sam::Session::create(bridge).await?;
        (s.connect(&r.host).await?, Some(s))
    } else {
        (
            device::connect(&r.host, r.port, cfg.device.as_deref()).await?,
            None,
        )
    };
    let _ = sock.set_nodelay(true);
    let noise = match &r.key {
        Some(k) => Some(Arc::new(noise::initiate(&mut sock, k).await?)),
        None => None,
    };
    Ok(Conn {
        sock,
        noise,
        _sam: session,
    })
}

async fn run(cfg: LinkCfg, mut rx: mpsc::UnboundedReceiver<Job>, state: Arc<AtomicU8>) {
    let mut backoff = 1u64;
    let mut held: Option<Job> = None;
    loop {
        state.store(0, Ordering::Relaxed);
        // I2P tunnels can take a while to build.
        let wait = if cfg.relay.is_i2p() { 180 } else { 60 };
        let conn = match tokio::time::timeout(Duration::from_secs(wait), connect(&cfg)).await {
            Ok(Ok(s)) => s,
            _ => {
                state.store(2, Ordering::Relaxed);
                // Fail all queued jobs so that their callers receive an error.
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
        let Conn { sock, noise, _sam } = conn;
        let (mut rd, mut wr) = sock.into_split();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let p2 = pending.clone();
        let rnoise = noise.clone();
        let mut reader = tokio::spawn(async move {
            let mut cell = [0u8; CELL];
            let mut frame = [0u8; noise::FRAME];
            let mut rn = 0u64;
            loop {
                match &rnoise {
                    Some(l) => {
                        if rd.read_exact(&mut frame).await.is_err() {
                            return;
                        }
                        match l.open(rn, &frame) {
                            Ok(c) => cell = c,
                            Err(_) => return,
                        }
                        rn += 1;
                    }
                    None => {
                        if rd.read_exact(&mut cell).await.is_err() {
                            return;
                        }
                    }
                }
                if let Ok(r) = Response::decode(&cell) {
                    if let Some(tx) = p2.lock().await.remove(&r.rid) {
                        let _ = tx.send(r.status);
                    }
                }
            }
        });
        let mut rid: u32 = random_u64() as u32;
        let mut quit = false;
        let mut wn = 0u64;
        let mut tick = tokio::time::interval(jitter(cfg.cover_ms.max(50)));
        loop {
            let cover = cfg.cover.load(Ordering::Relaxed);
            let job = if let Some(j) = held.take() {
                Some(j)
            } else if cover {
                tokio::select! {
                    _ = tick.tick() => {
                        tick.reset_after(jitter(cfg.cover_ms.max(50)));
                        // Send exactly one cell per tick: a queued job if there is one, otherwise padding.
                        match rx.try_recv() {
                            Ok(j) => Some(j),
                            Err(mpsc::error::TryRecvError::Empty) => None,
                            Err(mpsc::error::TryRecvError::Disconnected) => { quit = true; break }
                        }
                    }
                    _ = &mut reader => break,
                }
            } else {
                tokio::select! {
                    j = rx.recv() => match j { Some(j) => Some(j), None => { quit = true; break } },
                    _ = tokio::time::sleep(Duration::from_secs(120)) => None, // keepalive pad
                    _ = &mut reader => break,
                }
            };
            if !cover {
                if let Some(Job {
                    op: Op::Put { .. }, ..
                }) = &job
                {
                    if cfg.max_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(random_u64() % cfg.max_delay_ms))
                            .await;
                    }
                }
            }
            rid = rid.wrapping_add(1);
            let (op, reply) = match job {
                Some(j) => (j.op, Some(j.reply)),
                None => (Op::Pad, None),
            };
            let Ok(cell) = (Request {
                rid,
                op: op.clone(),
            })
            .encode() else {
                continue;
            };
            if let Some(r) = reply {
                pending.lock().await.insert(rid, r);
            }
            let sent = match &noise {
                Some(l) => match l.seal(wn, &cell) {
                    Ok(f) => {
                        wn += 1;
                        wr.write_all(&f).await
                    }
                    Err(e) => Err(e),
                },
                None => wr.write_all(&cell).await,
            };
            if sent.is_err() {
                // Queue the unsent job again.
                if let Some(r) = pending.lock().await.remove(&rid) {
                    held = Some(Job { op, reply: r });
                }
                break;
            }
        }
        reader.abort();
        pending.lock().await.clear();
        if quit {
            return;
        }
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
        tokio::spawn(eigen_relay::serve(
            l,
            eigen_relay::Config {
                pow_base: 4,
                ..Default::default()
            },
        ));
        RelayAddr {
            host: "127.0.0.1".into(),
            port,
            key: None,
        }
    }

    pub fn cfg(relay: RelayAddr, cover: bool) -> LinkCfg {
        LinkCfg {
            relay,
            socks: None,
            isolation: "t".into(),
            cover: Arc::new(AtomicBool::new(cover)),
            cover_ms: 20,
            max_delay_ms: 5,
            sam: None,
            device: None,
        }
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
                link.put(m, 60, eigen_core::cell::blob(&[i]).unwrap(), 6)
                    .await
                    .unwrap();
            }
            let all = link.fetch_all(m, 0, 10).await.unwrap();
            assert_eq!(all.len(), 3);
            assert_eq!(all[2].blob[0], 2);
            assert!(link.take(m).await.unwrap().is_some());
            assert_eq!(link.fetch_all(m, 0, 10).await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn cover_traffic_is_constant_while_idle() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = counter.clone();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut cell = [0u8; CELL];
            while s.read_exact(&mut cell).await.is_ok() {
                c2.fetch_add(1, Ordering::Relaxed);
                let r = Request::decode(&cell).unwrap();
                assert_eq!(r.op, Op::Pad, "idle link sends only padding");
                s.write_all(
                    &Response {
                        rid: r.rid,
                        status: Status::Pad,
                    }
                    .encode(),
                )
                .await
                .unwrap();
            }
        });
        let mut c = cfg(
            RelayAddr {
                host: "127.0.0.1".into(),
                port,
                key: None,
            },
            true,
        );
        c.cover_ms = 50;
        let _link = Link::spawn(c);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let start = counter.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let n = counter.load(Ordering::Relaxed) - start;
        assert!((12..=30).contains(&n), "{n} cells in 1s at 50ms ±30%");
    }

    /// A VPN/WireGuard-style route: Noise-encrypted link, socket bound to an
    /// interface (`lo` stands in for `wg0` here).
    #[tokio::test]
    async fn noise_link_bound_to_interface() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let key = eigen_transport::noise::RelayKey::generate().unwrap();
        let public = key.public;
        let relay = eigen_relay::Relay::start(eigen_relay::Config {
            pow_base: 4,
            ..Default::default()
        });
        tokio::spawn(relay.serve_noise(l, Arc::new(key)));
        let mut c = cfg(
            RelayAddr {
                host: "127.0.0.1".into(),
                port,
                key: Some(public),
            },
            false,
        );
        c.device = Some("lo".into());
        let link = Link::spawn(c);
        let m = [3u8; 32];
        link.put(
            m,
            60,
            eigen_core::cell::blob(b"through the tunnel").unwrap(),
            6,
        )
        .await
        .unwrap();
        let all = link.fetch_all(m, 0, 10).await.unwrap();
        assert_eq!(&all[0].blob[..18], b"through the tunnel");
        // With a wrong key the link does not come up, so the relay cannot be impersonated.
        let mut bad = cfg(
            RelayAddr {
                host: "127.0.0.1".into(),
                port,
                key: Some([9u8; 32]),
            },
            false,
        );
        bad.device = Some("lo".into());
        let bad = Link::spawn(bad);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), bad.call(Op::Pad))
                .await
                .map(|r| r.is_err())
                .unwrap_or(true)
        );
    }
}
