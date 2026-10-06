//! EIGENHEIT relay. Holds short-lived, fixed-size ciphertext under opaque mailbox
//! ids. Knows no users, rooms, names or wall-clock times. Writes nothing to disk,
//! logs nothing — not even errors.
#![forbid(unsafe_code)]

pub mod store;
pub mod torctl;

use std::sync::Arc;
use std::time::Duration;

use eigen_core::cell::{Request, Response, Status, CELL};
use eigen_transport::noise::{self, RelayKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};

pub use store::{Config, Store};

const MAX_CONNS: usize = 1024;
const IDLE: Duration = Duration::from_secs(600);

/// The relay's shared state, with its TTL sweeper running.
#[derive(Clone)]
pub struct Relay {
    store: Arc<Mutex<Store>>,
    slots: Arc<Semaphore>,
}

impl Relay {
    pub fn start(cfg: Config) -> Relay {
        let store = Arc::new(Mutex::new(Store::new(cfg)));
        let sweeper = store.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(5));
            loop {
                t.tick().await;
                sweeper.lock().await.sweep();
            }
        });
        Relay {
            store,
            slots: Arc::new(Semaphore::new(MAX_CONNS)),
        }
    }

    fn spawn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        sock: S,
        key: Option<Arc<RelayKey>>,
    ) {
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return;
        };
        let store = self.store.clone();
        tokio::spawn(async move {
            let _ = conn(sock, store, key).await;
            drop(permit);
        });
    }

    /// Plain cells. For the loopback listener behind an onion service.
    pub async fn serve_plain(self, listener: TcpListener) {
        self.serve_tcp(listener, None).await
    }

    /// Noise-encrypted cells. For a public (clear-net / VPN / WireGuard) listener.
    pub async fn serve_noise(self, listener: TcpListener, key: Arc<RelayKey>) {
        self.serve_tcp(listener, Some(key)).await
    }

    async fn serve_tcp(self, listener: TcpListener, key: Option<Arc<RelayKey>>) {
        loop {
            let Ok((sock, _addr)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            // The peer address is dropped right here and never stored.
            let _ = sock.set_nodelay(true);
            self.spawn(sock, key.clone());
        }
    }

    /// Accept streams from an I2P SAM session, forever.
    pub async fn serve_i2p(self, session: Arc<eigen_transport::sam::Session>) {
        loop {
            match session.accept().await {
                Ok(sock) => self.spawn(sock, None),
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }
}

/// Serve plain cells forever on `listener`. Errors are swallowed: a dropped connection says nothing.
pub async fn serve(listener: TcpListener, cfg: Config) {
    Relay::start(cfg).serve_plain(listener).await
}

async fn conn<S: AsyncRead + AsyncWrite + Unpin>(
    mut sock: S,
    store: Arc<Mutex<Store>>,
    key: Option<Arc<RelayKey>>,
) -> std::io::Result<()> {
    let link = match key {
        Some(k) => Some(
            tokio::time::timeout(Duration::from_secs(30), noise::respond(&mut sock, &k)).await??,
        ),
        None => None,
    };
    let (mut rn, mut wn) = (0u64, 0u64);
    let mut cell = [0u8; CELL];
    let mut frame = [0u8; noise::FRAME];
    loop {
        match &link {
            Some(l) => {
                tokio::time::timeout(IDLE, sock.read_exact(&mut frame)).await??;
                cell = l.open(rn, &frame)?;
                rn += 1;
            }
            None => {
                tokio::time::timeout(IDLE, sock.read_exact(&mut cell)).await??;
            }
        }
        let resp = match Request::decode(&cell) {
            Ok(req) => {
                let rid = req.rid;
                let status = store.lock().await.handle(req.op);
                Response { rid, status }
            }
            Err(_) => Response {
                rid: 0,
                status: Status::Bad,
            },
        };
        let out = resp.encode();
        match &link {
            Some(l) => {
                sock.write_all(&l.seal(wn, &out)?).await?;
                wn += 1;
            }
            None => sock.write_all(&out).await?,
        }
    }
}
