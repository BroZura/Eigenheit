//! Hashcash-style proof of work, bound to (hour, mailbox, blob).
use crate::crypto::h;

pub fn hour_now() -> u64 {
    crate::now() / 3600
}

fn digest(hour: u64, mbox: &[u8; 32], blob_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
    h(&[
        b"eigen/pow/v1",
        &hour.to_be_bytes(),
        mbox,
        blob_hash,
        &nonce.to_be_bytes(),
    ])
}

pub fn leading_zeros(d: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in d {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// The relay also uses this digest as a replay tag.
pub fn tag(hour: u64, mbox: &[u8; 32], blob: &[u8], nonce: u64) -> [u8; 32] {
    digest(hour, mbox, &h(&[blob]), nonce)
}

pub fn work(hour: u64, mbox: &[u8; 32], blob: &[u8], nonce: u64) -> u32 {
    leading_zeros(&tag(hour, mbox, blob, nonce))
}

pub fn check(hour: u64, mbox: &[u8; 32], blob: &[u8], nonce: u64, bits: u8) -> bool {
    work(hour, mbox, blob, nonce) >= bits as u32
}

/// Search for a valid nonce. The search starts at a random value so that parallel
/// solvers do not repeat the same work.
pub fn solve(hour: u64, mbox: &[u8; 32], blob: &[u8], bits: u8) -> u64 {
    let bh = h(&[blob]);
    let mut nonce = crate::crypto::random_u64();
    loop {
        if leading_zeros(&digest(hour, mbox, &bh, nonce)) >= bits as u32 {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_and_check() {
        let mbox = [7u8; 32];
        let blob = vec![1u8; 960];
        let n = solve(5, &mbox, &blob, 12);
        assert!(check(5, &mbox, &blob, n, 12));
        // Bound to hour, mailbox and blob.
        let tries = [
            check(6, &mbox, &blob, n, 12),
            check(5, &[8; 32], &blob, n, 12),
            check(5, &mbox, &[2u8; 960], n, 12),
        ];
        assert!(
            tries.iter().filter(|t| **t).count() <= 1,
            "PoW should not transfer"
        );
    }

    #[test]
    fn zeros() {
        let mut d = [0u8; 32];
        d[1] = 0x10;
        assert_eq!(leading_zeros(&d), 11);
    }
}
