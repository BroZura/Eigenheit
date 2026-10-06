//! DMs: sealed-sender X3DH introduction, Double Ratchet sessions, rotating mailboxes,
//! fixed-size blobs. The relay sees a mailbox id and 960 random-looking bytes.
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::cell::{blob, Mbox};
use crate::crypto::{h, kdf32, open_fixed, random, seal_fixed};
use crate::identity::{Card, Mask, Who};
use crate::ratchet::Ratchet;
use crate::wire::{Reader, Writer};
use crate::x3dh::{self, Bundle};
use crate::{Error, Result};

pub const PAYLOAD: usize = 512;
pub const DM_TEXT_MAX: usize = 460;
const RMSG: usize = 40 + PAYLOAD + 16;
const INTRO_SEAL: usize = 720;
const DM_SEAL: usize = 600;
pub const GRACE: u64 = 900;
pub const DEFAULT_TTL: u32 = 3600;

pub const T_INTRO: u8 = 0x01;
pub const T_DM: u8 = 0x02;
pub const T_BUNDLE: u8 = 0x20;
pub const T_OPK: u8 = 0x21;

pub const K_TEXT: u8 = 1;
pub const K_HELLO: u8 = 2;

pub fn mbox_id(secret: &[u8; 32]) -> Mbox {
    h(&[b"eigen/mbox", secret])
}

fn mbox_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    kdf32(&[0u8; 32], secret, b"eigen/mbox-key")
}

fn bundle_key(intro: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    kdf32(&[0u8; 32], intro, b"eigen/bundle-key")
}

/// Blob carrying my signed prekey bundle (posted to `card.bundle_mbox()`).
pub fn bundle_blob(m: &Mask) -> Result<Vec<u8>> {
    let mut v = vec![T_BUNDLE];
    v.extend(seal_fixed(
        &bundle_key(&m.intro),
        &Bundle::of(m).encode(),
        256,
        b"bundle",
    )?);
    blob(&v)
}

pub fn open_bundle(card: &Card, b: &[u8]) -> Result<Bundle> {
    if b.first() != Some(&T_BUNDLE) {
        return Err(Error::Malformed);
    }
    let pt = open_fixed(&bundle_key(&card.intro), &b[1..1 + 256 + 40], b"bundle")?;
    let bundle = Bundle::decode(&pt)?;
    bundle.verify(&card.who)?;
    Ok(bundle)
}

/// Blob carrying one one-time prekey (posted to `card.opk_mbox()`).
pub fn opk_blob(m: &Mask, id: u32, public: &[u8; 32]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u32(id).bytes(public);
    let mut v = vec![T_OPK];
    v.extend(seal_fixed(&bundle_key(&m.intro), &w.0, 64, b"opk")?);
    blob(&v)
}

pub fn open_opk(card: &Card, b: &[u8]) -> Result<(u32, [u8; 32])> {
    if b.first() != Some(&T_OPK) {
        return Err(Error::Malformed);
    }
    let pt = open_fixed(&bundle_key(&card.intro), &b[1..1 + 64 + 40], b"opk")?;
    let mut r = Reader::new(&pt);
    Ok((r.u32()?, r.arr()?))
}

/// What arrives, after all layers are off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub kind: u8,
    pub ttl: u32,
    pub text: String,
}

fn encode_payload(kind: u8, ttl: u32, reply: &[u8; 32], text: &str) -> Result<Zeroizing<Vec<u8>>> {
    if text.len() > DM_TEXT_MAX {
        return Err(Error::TooLong);
    }
    let mut w = Writer::new();
    w.u8(kind).u32(ttl).bytes(reply).var(text.as_bytes());
    let mut v = Zeroizing::new(w.finish());
    v.resize(PAYLOAD, 0);
    Ok(v)
}

fn decode_payload(b: &[u8]) -> Result<(Incoming, [u8; 32])> {
    let mut r = Reader::new(b);
    let kind = r.u8()?;
    let ttl = r.u32()?;
    let reply = r.arr()?;
    let text = String::from_utf8(r.var()?.to_vec()).map_err(|_| Error::Malformed)?;
    Ok((
        Incoming {
            kind,
            ttl: ttl.clamp(10, 7 * 86400),
            text,
        },
        reply,
    ))
}

pub struct MySecret {
    pub secret: [u8; 32],
    pub retired: Option<u64>,
}

impl Drop for MySecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

struct IntroHeader {
    ek: [u8; 32],
    spk_id: u32,
    opk_id: u32,
    mbox: Mbox,
    seal_key: Zeroizing<[u8; 32]>,
    bind: [u8; 64],
}

pub struct Session {
    pub peer: Who,
    /// Session id: the initiator's ephemeral key.
    pub ek: [u8; 32],
    ratchet: Ratchet,
    intro: Option<IntroHeader>,
    peer_mbox: Option<[u8; 32]>,
    pub mine: Vec<MySecret>,
    last_epoch: [u8; 32],
    pub ttl: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.peer_mbox.zeroize();
    }
}

fn bind_msg(ik: &[u8; 32], ek: &[u8; 32]) -> Vec<u8> {
    [&b"eigen/bind"[..], ik, ek].concat()
}

impl Session {
    /// Start a DM with `card`, given its bundle and possibly a one-time prekey.
    pub fn start(
        me: &Mask,
        card: &Card,
        bundle: &Bundle,
        opk: Option<(u32, [u8; 32])>,
    ) -> Result<Session> {
        let i = x3dh::initiate(me, card, bundle, opk)?;
        let bind = me.sign(&bind_msg(&me.ik_pub(), &i.ek_pub));
        Ok(Session {
            peer: card.who,
            ek: i.ek_pub,
            ratchet: Ratchet::init_alice(&i.sk, bundle.spk, i.ad),
            intro: Some(IntroHeader {
                ek: i.ek_pub,
                spk_id: bundle.spk_id,
                opk_id: i.opk_id,
                mbox: card.intro_mbox(),
                seal_key: i.seal_key,
                bind,
            }),
            peer_mbox: None,
            mine: Vec::new(),
            last_epoch: [0; 32],
            ttl: DEFAULT_TTL,
        })
    }

    pub fn is_initiating(&self) -> bool {
        self.intro.is_some()
    }

    /// Encrypt a message. Returns (target mailbox, ttl, blob).
    pub fn seal(&mut self, me: &Mask, kind: u8, text: &str) -> Result<(Mbox, u32, Vec<u8>)> {
        let epoch = self.ratchet.epoch();
        if epoch != self.last_epoch || self.mine.is_empty() {
            // New sending chain → new receive mailbox for the replies.
            let t = crate::now();
            for m in self.mine.iter_mut().filter(|m| m.retired.is_none()) {
                m.retired = Some(t);
            }
            self.mine.push(MySecret {
                secret: random(),
                retired: None,
            });
            self.last_epoch = epoch;
        }
        let reply = self.mine.last().map(|m| m.secret).unwrap_or_default();
        let payload = encode_payload(kind, self.ttl, &reply, text)?;
        let rmsg = self.ratchet.encrypt(&payload)?;
        if let Some(ih) = &self.intro {
            let mut head = Writer::new();
            head.u8(T_INTRO).bytes(&ih.ek).u32(ih.spk_id).u32(ih.opk_id);
            let mut inner = Zeroizing::new(Vec::with_capacity(700));
            inner.extend_from_slice(&me.who().0);
            inner.extend_from_slice(&me.ik_pub());
            inner.extend_from_slice(&ih.bind);
            inner.extend_from_slice(&rmsg);
            let sealed = seal_fixed(&ih.seal_key, &inner, INTRO_SEAL, &head.0)?;
            let mut v = head.finish();
            v.extend(sealed);
            return Ok((ih.mbox, self.ttl, blob(&v)?));
        }
        let peer = self.peer_mbox.ok_or(Error::Unknown)?;
        let id = mbox_id(&peer);
        let mut v = vec![T_DM];
        v.extend(seal_fixed(&mbox_key(&peer), &rmsg, DM_SEAL, &id)?);
        Ok((id, self.ttl, blob(&v)?))
    }

    fn accept(&mut self, rmsg: &[u8]) -> Result<Incoming> {
        let pt = self.ratchet.decrypt(rmsg)?;
        let (inc, reply) = decode_payload(&pt)?;
        self.peer_mbox = Some(reply);
        Ok(inc)
    }

    /// A DM blob that arrived at one of my mailboxes.
    pub fn open(&mut self, mbox: &Mbox, b: &[u8]) -> Result<Incoming> {
        let secret = self
            .mine
            .iter()
            .find(|m| mbox_id(&m.secret) == *mbox)
            .map(|m| m.secret)
            .ok_or(Error::Unknown)?;
        if b.first() != Some(&T_DM) {
            return Err(Error::Malformed);
        }
        let rmsg = open_fixed(&mbox_key(&secret), &b[1..1 + DM_SEAL + 40], mbox)?;
        let inc = self.accept(&rmsg)?;
        // The peer answered: from now on, write to their mailbox, not their intro.
        self.intro = None;
        Ok(inc)
    }

    /// Mailboxes to poll: the current one and those still within grace.
    pub fn mailboxes(&mut self) -> Vec<Mbox> {
        let t = crate::now();
        self.mine.retain(|m| {
            m.retired
                .map(|r| t.saturating_sub(r) < GRACE)
                .unwrap_or(true)
        });
        self.mine.iter().map(|m| mbox_id(&m.secret)).collect()
    }
}

/// Result of opening a blob in my intro mailbox.
pub enum Intro {
    New(Box<Session>, Incoming),
    /// Belongs to an existing session (`ek`); hand `rmsg` to it.
    Existing([u8; 32], Zeroizing<Vec<u8>>),
}

impl Session {
    pub fn open_existing_intro(&mut self, rmsg: &[u8]) -> Result<Incoming> {
        self.accept(rmsg)
    }
}

/// Open a sealed-sender introduction addressed to me.
pub fn open_intro(me: &mut Mask, b: &[u8], known: impl Fn(&[u8; 32]) -> bool) -> Result<Intro> {
    if b.len() < 41 + INTRO_SEAL + 40 || b[0] != T_INTRO {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(&b[1..41]);
    let ek: [u8; 32] = r.arr()?;
    let spk_id = r.u32()?;
    let opk_id = r.u32()?;
    if spk_id != me.spk_id {
        return Err(Error::Unknown);
    }
    let inner = open_fixed(
        &x3dh::seal_key_for(me, &ek),
        &b[41..41 + INTRO_SEAL + 40],
        &b[..41],
    )?;
    let mut r = Reader::new(&inner);
    let alice = Who(r.arr()?);
    let alice_ik: [u8; 32] = r.arr()?;
    let bind: [u8; 64] = r.arr()?;
    let rmsg = Zeroizing::new(r.take(RMSG)?.to_vec());
    alice.verify(&bind_msg(&alice_ik, &ek), &bind)?;
    if known(&ek) {
        return Ok(Intro::Existing(ek, rmsg));
    }
    let (sk, ad) = x3dh::respond(me, &alice, &alice_ik, &ek, spk_id, opk_id)?;
    let mut s = Session {
        peer: alice,
        ek,
        ratchet: Ratchet::init_bob(&sk, me.spk.clone(), ad),
        intro: None,
        peer_mbox: None,
        mine: Vec::new(),
        last_epoch: PublicKey::from(&me.spk).to_bytes(),
        ttl: DEFAULT_TTL,
    };
    let inc = s.accept(&rmsg)?;
    s.ttl = inc.ttl;
    Ok(Intro::New(Box::new(s), inc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::BLOB;

    fn handshake() -> (Mask, Mask, Session, Session) {
        let alice = Mask::generate();
        let mut bob = Mask::generate();
        let card = bob.card();
        let bundle = open_bundle(&card, &bundle_blob(&bob).unwrap()).unwrap();
        let (id, pk) = (bob.opks[0].0, PublicKey::from(&bob.opks[0].1).to_bytes());
        let opk = open_opk(&card, &opk_blob(&bob, id, &pk).unwrap()).unwrap();
        let mut sa = Session::start(&alice, &card, &bundle, Some(opk)).unwrap();
        let (mbox, _, b1) = sa.seal(&alice, K_TEXT, "hello bob").unwrap();
        assert_eq!(mbox, card.intro_mbox());
        assert_eq!(b1.len(), BLOB);
        let Intro::New(sb, inc) = open_intro(&mut bob, &b1, |_| false).unwrap() else {
            panic!()
        };
        assert_eq!(inc.text, "hello bob");
        assert_eq!(sb.peer, alice.who());
        (alice, bob, sa, *sb)
    }

    #[test]
    fn full_dm_flow_with_rotation() {
        let (alice, mut bob, mut sa, mut sb) = handshake();
        // Alice writes again before Bob answers: still via intro, same session.
        let (_, _, b2) = sa.seal(&alice, K_TEXT, "still there?").unwrap();
        let Intro::Existing(ek, rmsg) = open_intro(&mut bob, &b2, |e| *e == sb.ek).unwrap() else {
            panic!()
        };
        assert_eq!(ek, sb.ek);
        assert_eq!(sb.open_existing_intro(&rmsg).unwrap().text, "still there?");
        // Bob answers to Alice's announced mailbox.
        let (m, _, r1) = sb.seal(&bob, K_TEXT, "here").unwrap();
        assert!(sa.mailboxes().contains(&m));
        assert_eq!(sa.open(&m, &r1).unwrap().text, "here");
        assert!(!sa.is_initiating());
        let first_alice_mbox = sa.mailboxes()[0];
        // Alice's next message starts a new chain → a new mailbox.
        let (m2, _, a3) = sa.seal(&alice, K_TEXT, "good").unwrap();
        assert!(sb.mailboxes().contains(&m2));
        assert_eq!(sb.open(&m2, &a3).unwrap().text, "good");
        assert_eq!(sa.mailboxes().len(), 2, "old mailbox kept for grace");
        assert_ne!(sa.mailboxes()[1], first_alice_mbox);
        // Replays fail.
        assert!(sb.open(&m2, &a3).is_err());
    }

    #[test]
    fn relay_sees_no_sender() {
        let (alice, _bob, mut sa, _sb) = handshake();
        let (_, _, b) = sa.seal(&alice, K_TEXT, "x").unwrap();
        let hay = b
            .windows(32)
            .any(|w| w == alice.who().0 || w == alice.ik_pub());
        assert!(!hay, "sender identity must not appear in clear");
    }

    #[test]
    fn too_long_refused() {
        let (alice, _b, mut sa, _sb) = handshake();
        assert_eq!(
            sa.seal(&alice, K_TEXT, &"x".repeat(DM_TEXT_MAX + 1)).err(),
            Some(Error::TooLong)
        );
    }

    #[test]
    fn stranger_cannot_open_intro() {
        let (alice, _bob, mut sa, _) = handshake();
        let (_, _, b) = sa.seal(&alice, K_TEXT, "x").unwrap();
        let mut eve = Mask::generate();
        assert!(open_intro(&mut eve, &b, |_| false).is_err());
    }
}
