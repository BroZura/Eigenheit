//! X3DH (Signal specification) with Ed25519-signed X25519 prekeys.
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{kdf, kdf32};
use crate::identity::{Card, Mask, Who};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub const NO_OPK: u32 = u32::MAX;

/// A mask's published prekey bundle (signed by its Ed25519 key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub ik: [u8; 32],
    pub spk_id: u32,
    pub spk: [u8; 32],
    pub sig: [u8; 64],
}

fn bundle_msg(ik: &[u8; 32], spk_id: u32, spk: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"eigen/bundle").bytes(ik).u32(spk_id).bytes(spk);
    w.finish()
}

impl Bundle {
    pub fn of(m: &Mask) -> Bundle {
        let (ik, spk) = (m.ik_pub(), m.spk_pub());
        Bundle {
            ik,
            spk_id: m.spk_id,
            spk,
            sig: m.sign(&bundle_msg(&ik, m.spk_id, &spk)),
        }
    }
    pub fn verify(&self, who: &Who) -> Result<()> {
        who.verify(&bundle_msg(&self.ik, self.spk_id, &self.spk), &self.sig)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.ik)
            .u32(self.spk_id)
            .bytes(&self.spk)
            .bytes(&self.sig);
        w.finish()
    }
    pub fn decode(b: &[u8]) -> Result<Bundle> {
        let mut r = Reader::new(b);
        Ok(Bundle {
            ik: r.arr()?,
            spk_id: r.u32()?,
            spk: r.arr()?,
            sig: r.arr()?,
        })
    }
}

/// Associated data binding both identities: `edA ‖ IKa ‖ edB ‖ IKb`.
pub fn assoc(a_ed: &Who, a_ik: &[u8; 32], b_ed: &Who, b_ik: &[u8; 32]) -> Vec<u8> {
    [&a_ed.0[..], a_ik, &b_ed.0, b_ik].concat()
}

fn derive(dhs: &[&[u8; 32]]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(vec![0xffu8; 32]);
    for d in dhs {
        ikm.extend_from_slice(*d);
    }
    let mut sk = Zeroizing::new([0u8; 32]);
    kdf(&[0u8; 32], &ikm, b"eigen/x3dh", sk.as_mut());
    sk
}

pub struct Initiated {
    pub ek_pub: [u8; 32],
    pub sk: Zeroizing<[u8; 32]>,
    pub ad: Vec<u8>,
    /// Key for the sealed-sender envelope.
    pub seal_key: Zeroizing<[u8; 32]>,
    pub opk_id: u32,
}

/// Alice's side. `opk` is one of Bob's one-time prekeys if the relay still had one.
pub fn initiate(
    alice: &Mask,
    bob: &Card,
    bundle: &Bundle,
    opk: Option<(u32, [u8; 32])>,
) -> Result<Initiated> {
    bundle.verify(&bob.who)?;
    let ek = StaticSecret::random_from_rng(rand_core::OsRng);
    let spk = PublicKey::from(bundle.spk);
    let dh1 = alice.ik.diffie_hellman(&spk).to_bytes();
    let dh2 = ek.diffie_hellman(&PublicKey::from(bundle.ik)).to_bytes();
    let dh3 = ek.diffie_hellman(&spk).to_bytes();
    let dh4 = opk.map(|(_, k)| ek.diffie_hellman(&PublicKey::from(k)).to_bytes());
    let mut parts = vec![&dh1, &dh2, &dh3];
    if let Some(d) = dh4.as_ref() {
        parts.push(d);
    }
    let sk = derive(&parts);
    let seal_key = kdf32(&[0u8; 32], &dh3, b"eigen/seal");
    Ok(Initiated {
        ek_pub: PublicKey::from(&ek).to_bytes(),
        sk,
        ad: assoc(&alice.who(), &alice.ik_pub(), &bob.who, &bundle.ik),
        seal_key,
        opk_id: opk.map(|(i, _)| i).unwrap_or(NO_OPK),
    })
}

/// Bob opens the sealed envelope key before he knows who wrote to him.
pub fn seal_key_for(bob: &Mask, ek_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let dh3 = bob.spk.diffie_hellman(&PublicKey::from(*ek_pub)).to_bytes();
    kdf32(&[0u8; 32], &dh3, b"eigen/seal")
}

/// Bob's side, after learning Alice's identity from the envelope.
pub fn respond(
    bob: &mut Mask,
    alice_ed: &Who,
    alice_ik: &[u8; 32],
    ek_pub: &[u8; 32],
    spk_id: u32,
    opk_id: u32,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    if spk_id != bob.spk_id {
        return Err(Error::Unknown);
    }
    let ek = PublicKey::from(*ek_pub);
    let dh1 = bob
        .spk
        .diffie_hellman(&PublicKey::from(*alice_ik))
        .to_bytes();
    let dh2 = bob.ik.diffie_hellman(&ek).to_bytes();
    let dh3 = bob.spk.diffie_hellman(&ek).to_bytes();
    let dh4 = if opk_id == NO_OPK {
        None
    } else {
        // One-time: removed from memory on use. A replay finds nothing.
        Some(
            bob.take_opk(opk_id)
                .ok_or(Error::Replay)?
                .diffie_hellman(&ek)
                .to_bytes(),
        )
    };
    let mut parts = vec![&dh1, &dh2, &dh3];
    if let Some(d) = dh4.as_ref() {
        parts.push(d);
    }
    Ok((
        derive(&parts),
        assoc(alice_ed, alice_ik, &bob.who(), &bob.ik_pub()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agree_with_and_without_opk() {
        for with in [true, false] {
            let a = Mask::generate();
            let mut b = Mask::generate();
            let bundle = Bundle::of(&b);
            let opk = with.then(|| {
                let (id, sk) = &b.opks[0];
                (*id, PublicKey::from(sk).to_bytes())
            });
            let i = initiate(&a, &b.card(), &bundle, opk).unwrap();
            assert_eq!(*seal_key_for(&b, &i.ek_pub), *i.seal_key);
            let (sk, ad) = respond(
                &mut b,
                &a.who(),
                &a.ik_pub(),
                &i.ek_pub,
                bundle.spk_id,
                i.opk_id,
            )
            .unwrap();
            assert_eq!(*sk, *i.sk);
            assert_eq!(ad, i.ad);
            if with {
                assert!(
                    respond(
                        &mut b,
                        &a.who(),
                        &a.ik_pub(),
                        &i.ek_pub,
                        bundle.spk_id,
                        i.opk_id
                    )
                    .is_err(),
                    "OPK is single-use"
                );
            }
        }
    }

    #[test]
    fn forged_bundle_rejected() {
        let a = Mask::generate();
        let b = Mask::generate();
        let mut bundle = Bundle::of(&b);
        bundle.spk = Mask::generate().spk_pub();
        assert!(initiate(&a, &b.card(), &bundle, None).is_err());
    }
}
