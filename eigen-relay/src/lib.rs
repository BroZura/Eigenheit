//! EIGENHEIT relay. Holds short-lived, fixed-size ciphertext under opaque mailbox
//! ids. Knows no users, rooms, names or wall-clock times. Writes nothing to disk,
//! logs nothing — not even errors.
#![forbid(unsafe_code)]

pub mod store;
pub mod torctl;

use std::sync::Arc;
use std::time::Duration;

use eigen_core::cell::{Request, Response, Status, CELL};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

pub use store::{Config, Store};

const MAX_CONNS: usize = 1024;
const IDLE: Duration = Duration::from_secs(600);

/// Serve forever on `listener`. Errors are swallowed: a dropped connection says nothing.
pub async fn serve(listener: TcpListener, cfg: Config) {
    let store = Arc::new(Mutex::new(Store::new(cfg)));
    let sweeper = store.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(5));
        loop {
            t.tick().await;
            sweeper.lock().await.sweep();
        }
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let Ok((sock, _addr)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        // The peer address is dropped right here and never stored.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _ = conn(sock, store).await;
            drop(permit);
        });
    }
}

async fn conn(mut sock: TcpStream, store: Arc<Mutex<Store>>) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    let mut cell = [0u8; CELL];
    loop {
        tokio::time::timeout(IDLE, sock.read_exact(&mut cell)).await??;
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
        sock.write_all(&resp.encode()).await?;
    }
}
