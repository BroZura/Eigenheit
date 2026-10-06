//! The engine owns all secrets and protocol state. It runs on the UI task (single
//! owner, no locks); network I/O happens in spawned tasks that report back as events.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use eigen_core::cell::{Item, Mbox};
use eigen_core::crypto::{h, random, random_u64};
use eigen_core::dm::{self, Intro, Session, K_HELLO, K_TEXT};
use eigen_core::identity::{sas, Card, Mask, Who, CARD_PREFIX};
use eigen_core::x3dh::Bundle;
use eigen_core::{now, pgp};
use tokio::sync::mpsc::UnboundedSender;

use crate::app::{Action, App, Line, LineKind, MaskInfo, TorState, View, ViewKind};
use crate::net::{Link, LinkCfg};
use crate::tor::RelayAddr;

pub const DM_POW: u8 = 12;
const POLL_SECS: u64 = 3;
const RESCAN_SECS: u64 = 60;
const BUNDLE_EVERY: u64 = 1800;
const OPK_EVERY: u64 = 20 * 3600;

/// A verified bundle and maybe a one-time prekey.
pub type Fetched = (Bundle, Option<(u32, [u8; 32])>);

pub enum NetEvent {
    Fetched { relay: usize, mbox: Mbox, items: Vec<Item> },
    Bundle { view: u64, got: Option<Fetched> },
    Sent { view: u64, ok: bool },
}

#[derive(Clone)]
pub struct NetCfg {
    pub relays: Vec<RelayAddr>,
    pub socks: Option<String>,
    pub cover: Arc<AtomicBool>,
    pub cover_ms: u64,
    pub delay_ms: u64,
}

/// Links per isolation context: each mask, each dm and each union gets its own
/// connections (and, over tor, its own circuits).
pub struct Net {
    pub cfg: NetCfg,
    links: HashMap<u64, Vec<Link>>,
}

impl Net {
    pub fn new(cfg: NetCfg) -> Net {
        Net { cfg, links: HashMap::new() }
    }
    pub fn links(&mut self, ctx: u64) -> Vec<Link> {
        let cfg = self.cfg.clone();
        self.links
            .entry(ctx)
            .or_insert_with(|| {
                cfg.relays
                    .iter()
                    .map(|r| {
                        Link::spawn(LinkCfg {
                            relay: r.clone(),
                            socks: cfg.socks.clone(),
                            isolation: eigen_core::wire::hex(&random::<12>()),
                            cover: cfg.cover.clone(),
                            cover_ms: cfg.cover_ms,
                            max_delay_ms: cfg.delay_ms,
                        })
                    })
                    .collect()
            })
            .clone()
    }
    pub fn drop_ctx(&mut self, ctx: u64) {
        self.links.remove(&ctx);
    }
    pub fn clear(&mut self) {
        self.links.clear();
    }
    pub fn any_up(&self) -> bool {
        self.links.values().flatten().any(|l| l.is_up())
    }
}

pub struct MaskState {
    pub mask: Mask,
    pub ctx: u64,
    next_bundle: u64,
    next_opks: u64,
}

pub struct DmState {
    pub mask: usize,
    pub peer: Who,
    pub card: Option<Card>,
    pub session: Option<Session>,
    pub pending: Vec<String>,
    pub ctx: u64,
    retry_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Intro(usize),
    Dm(u64),
    Union(u64),
}

struct Poll {
    ctx: u64,
    route: Route,
    next: u64,
    rescan: u64,
}

pub struct Engine {
    pub net: Net,
    tx: UnboundedSender<NetEvent>,
    pub masks: Vec<MaskState>,
    pub dms: HashMap<u64, DmState>,
    pub unions: HashMap<u64, crate::unions::UnionState>,
    pins: HashMap<String, Who>,
    seen: HashMap<[u8; 32], u64>,
    cursors: HashMap<(usize, Mbox), u64>,
    polls: HashMap<Mbox, Poll>,
    inflight: HashMap<(usize, Mbox), u64>,
    pub poll_secs: u64,
}

fn line(from: Who, text: String, kind: LineKind, ttl: u64) -> Line {
    Line { from: Some(from), text, kind, at: now(), expires: Some(now() + ttl) }
}

impl Engine {
    pub fn new(net: Net, tx: UnboundedSender<NetEvent>) -> Engine {
        Engine {
            net,
            tx,
            masks: Vec::new(),
            dms: HashMap::new(),
            unions: HashMap::new(),
            pins: HashMap::new(),
            seen: HashMap::new(),
            cursors: HashMap::new(),
            polls: HashMap::new(),
            inflight: HashMap::new(),
            poll_secs: POLL_SECS,
        }
    }

    pub fn add_mask(&mut self, mask: Mask, app: &mut App) -> usize {
        let who = mask.who();
        self.masks.push(MaskState { mask, ctx: random_u64(), next_bundle: 0, next_opks: 0 });
        app.masks.push(MaskInfo { who });
        self.pin(who, app);
        self.masks.len() - 1
    }

    /// TOFU on names: a second key wearing a name I've already seen is loud.
    pub fn pin(&mut self, who: Who, app: &mut App) {
        let name = who.name();
        match self.pins.get(&name) {
            Some(k) if *k != who => {
                let id = app.view().id;
                app.warn(id, format!("KEY CHANGE: someone presents the name {name} with a different key. Not the one I saw before. /verify before trusting anything."));
            }
            Some(_) => {}
            None => {
                self.pins.insert(name, who);
            }
        }
    }

    pub fn put(&mut self, ctx: u64, view: u64, mbox: Mbox, ttl: u32, blob: Vec<u8>, bits: u8) {
        let links = self.net.links(ctx);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut ok = false;
            for l in links {
                ok |= l.put(mbox, ttl.max(10), blob.clone(), bits).await.is_ok();
            }
            let _ = tx.send(NetEvent::Sent { view, ok });
        });
    }

    fn watch(&mut self, mbox: Mbox, ctx: u64, route: Route) {
        self.polls.entry(mbox).or_insert(Poll { ctx, route, next: 0, rescan: now() + RESCAN_SECS });
    }

    fn unwatch_ctx(&mut self, ctx: u64) {
        self.polls.retain(|_, p| p.ctx != ctx);
    }

    /// Called about once a second.
    pub fn tick(&mut self, app: &mut App) {
        let t = now();
        app.tor = if self.net.cfg.relays.is_empty() {
            TorState::Off
        } else if !self.net.any_up() {
            TorState::Connecting
        } else if self.net.cfg.socks.is_some() {
            TorState::Up
        } else {
            TorState::ClearNet
        };
        // Publish bundles and one-time prekeys.
        for i in 0..self.masks.len() {
            let ms = &mut self.masks[i];
            let ctx = ms.ctx;
            let card = ms.mask.card();
            let mut puts = Vec::new();
            if t >= ms.next_bundle {
                ms.next_bundle = t + BUNDLE_EVERY;
                if let Ok(b) = dm::bundle_blob(&ms.mask) {
                    puts.push((card.bundle_mbox(), 2 * 3600, b));
                }
            }
            if t >= ms.next_opks {
                ms.next_opks = t + OPK_EVERY;
                for (id, pk) in ms.mask.rotate_opks() {
                    if let Ok(b) = dm::opk_blob(&ms.mask, id, &pk) {
                        puts.push((card.opk_mbox(), 24 * 3600, b));
                    }
                }
            }
            for (m, ttl, b) in puts {
                self.put(ctx, 0, m, ttl, b, DM_POW);
            }
            self.watch(card.intro_mbox(), ctx, Route::Intro(i));
        }
        // DM mailboxes rotate; refresh the watch list.
        let mut want = Vec::new();
        for (vid, d) in self.dms.iter_mut() {
            if let Some(s) = d.session.as_mut() {
                for m in s.mailboxes() {
                    want.push((m, d.ctx, Route::Dm(*vid)));
                }
            }
        }
        self.polls.retain(|_, p| !matches!(p.route, Route::Dm(_)));
        for (m, c, r) in want {
            self.watch(m, c, r);
        }
        crate::unions::tick(self, app);
        // Retry bundle fetches.
        let retry: Vec<u64> = self.dms.iter().filter(|(_, d)| d.retry_at.is_some_and(|r| r <= t)).map(|(v, _)| *v).collect();
        for v in retry {
            self.fetch_bundle(v);
        }
        self.poll(t);
        self.seen.retain(|_, e| *e > t);
    }

    fn poll(&mut self, t: u64) {
        let due: Vec<(Mbox, u64)> = self
            .polls
            .iter_mut()
            .filter(|(_, p)| p.next <= t)
            .map(|(m, p)| {
                p.next = if self.poll_secs == 0 { t } else { t + self.poll_secs + random_u64() % 2 };
                if p.rescan <= t {
                    p.rescan = t + RESCAN_SECS;
                    (*m, 1)
                } else {
                    (*m, 0)
                }
            })
            .collect();
        for (mbox, rescan) in due {
            let ctx = self.polls[&mbox].ctx;
            for (ri, link) in self.net.links(ctx).into_iter().enumerate() {
                if self.inflight.get(&(ri, mbox)).is_some_and(|s| *s + 30 > t) {
                    continue;
                }
                self.inflight.insert((ri, mbox), t);
                let after = if rescan == 1 { 0 } else { *self.cursors.get(&(ri, mbox)).unwrap_or(&0) };
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    let items = link.fetch_all(mbox, after, 64).await.unwrap_or_default();
                    let _ = tx.send(NetEvent::Fetched { relay: ri, mbox, items });
                });
            }
        }
    }

    pub fn on_net(&mut self, e: NetEvent, app: &mut App) {
        match e {
            NetEvent::Fetched { relay, mbox, items } => {
                self.inflight.remove(&(relay, mbox));
                if let Some(last) = items.last() {
                    let c = self.cursors.entry((relay, mbox)).or_insert(0);
                    *c = (*c).max(last.seq);
                }
                let Some(route) = self.polls.get(&mbox).map(|p| p.route) else { return };
                for it in items {
                    let tag = h(&[&it.blob]);
                    if self.seen.contains_key(&tag) {
                        continue;
                    }
                    self.seen.insert(tag, now() + 2 * 86400);
                    match route {
                        Route::Intro(i) => self.on_intro(i, &it.blob, app),
                        Route::Dm(v) => self.on_dm(v, &mbox, &it.blob, app),
                        Route::Union(v) => crate::unions::on_blob(self, v, &mbox, &it, app),
                    }
                }
            }
            NetEvent::Bundle { view, got } => self.on_bundle(view, got, app),
            NetEvent::Sent { view, ok } => {
                if !ok && view != 0 {
                    app.warn(view, "no relay took that. it was not delivered.");
                }
            }
        }
    }

    fn on_intro(&mut self, mi: usize, blob: &[u8], app: &mut App) {
        let known: Vec<[u8; 32]> = self.dms.values().filter(|d| d.mask == mi).filter_map(|d| d.session.as_ref().map(|s| s.ek)).collect();
        let used_before = self.masks[mi].mask.opks.len();
        let Ok(r) = dm::open_intro(&mut self.masks[mi].mask, blob, |ek| known.contains(ek)) else { return };
        match r {
            Intro::Existing(ek, rmsg) => {
                let Some((vid, d)) = self.dms.iter_mut().find(|(_, d)| d.session.as_ref().is_some_and(|s| s.ek == ek)) else { return };
                let vid = *vid;
                if let Ok(inc) = d.session.as_mut().map(|s| s.open_existing_intro(&rmsg)).unwrap_or(Err(eigen_core::Error::Unknown)) {
                    let peer = d.peer;
                    self.show(vid, peer, inc, app);
                }
            }
            Intro::New(session, inc) => {
                if self.masks[mi].mask.opks.len() < used_before {
                    let ms = &mut self.masks[mi];
                    let card = ms.mask.card();
                    let ctx = ms.ctx;
                    let fresh = ms.mask.refill_opks();
                    let blobs: Vec<_> = fresh.iter().filter_map(|(id, pk)| dm::opk_blob(&ms.mask, *id, pk).ok()).collect();
                    for b in blobs {
                        self.put(ctx, 0, card.opk_mbox(), 24 * 3600, b, DM_POW);
                    }
                }
                let peer = session.peer;
                self.pin(peer, app);
                let existing = self.dms.iter().find(|(_, d)| d.mask == mi && d.peer == peer).map(|(v, _)| *v);
                let vid = match existing {
                    Some(v) => {
                        app.notice(v, "they began a new session. the old keys are gone.");
                        v
                    }
                    None => {
                        let vid = app.fresh_id();
                        let mut view = View::new(vid, ViewKind::Dm, peer.name(), mi);
                        view.who = Some(peer);
                        view.ttl = inc.ttl as u64;
                        app.add_view(view);
                        app.notice(vid, format!("{} reached me. forward secret; their words live {}.", peer.name(), crate::app::fmt_duration(inc.ttl as u64)));
                        vid
                    }
                };
                if let Some(old) = self.dms.get(&vid) {
                    self.net.drop_ctx(old.ctx);
                }
                self.dms.insert(vid, DmState { mask: mi, peer, card: None, session: Some(*session), pending: Vec::new(), ctx: random_u64(), retry_at: None });
                self.show(vid, peer, inc, app);
            }
        }
    }

    fn on_dm(&mut self, vid: u64, mbox: &Mbox, blob: &[u8], app: &mut App) {
        let Some(d) = self.dms.get_mut(&vid) else { return };
        let Some(s) = d.session.as_mut() else { return };
        let was_init = s.is_initiating();
        if let Ok(inc) = s.open(mbox, blob) {
            let peer = d.peer;
            if was_init {
                app.notice(vid, "they answered. the handshake is complete.");
            }
            self.show(vid, peer, inc, app);
        }
    }

    fn show(&mut self, vid: u64, peer: Who, inc: dm::Incoming, app: &mut App) {
        if inc.kind == K_TEXT && !inc.text.is_empty() {
            app.push(vid, line(peer, inc.text, LineKind::Msg, inc.ttl as u64));
        } else if inc.kind == K_HELLO {
            app.notice(vid, format!("{} opened a dm.", peer.name()));
        }
    }

    fn fetch_bundle(&mut self, vid: u64) {
        let Some(d) = self.dms.get_mut(&vid) else { return };
        let Some(card) = d.card else { return };
        d.retry_at = None;
        let links = self.net.links(d.ctx);
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut got = None;
            for l in links {
                let Ok(items) = l.fetch_all(card.bundle_mbox(), 0, 256).await else { continue };
                if let Some(b) = items.iter().rev().find_map(|it| dm::open_bundle(&card, &it.blob).ok()) {
                    let mut opk = None;
                    for _ in 0..4 {
                        match l.take(card.opk_mbox()).await {
                            Ok(Some(it)) => {
                                if let Ok(o) = dm::open_opk(&card, &it.blob) {
                                    opk = Some(o);
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    got = Some((b, opk));
                    break;
                }
            }
            let _ = tx.send(NetEvent::Bundle { view: vid, got });
        });
    }

    fn on_bundle(&mut self, vid: u64, got: Option<Fetched>, app: &mut App) {
        let Some(d) = self.dms.get_mut(&vid) else { return };
        if d.session.is_some() {
            return;
        }
        let Some((bundle, opk)) = got else {
            d.retry_at = Some(now() + 10);
            app.notice(vid, "their keys are not on my relays (yet). trying again.");
            return;
        };
        let Some(card) = d.card else { return };
        let mi = d.mask;
        match Session::start(&self.masks[mi].mask, &card, &bundle, opk) {
            Ok(s) => {
                d.session = Some(s);
                app.notice(vid, if opk.is_some() { "keys agreed (with one-time prekey)." } else { "keys agreed (no one-time prekey left: weaker against replay)." });
                let pending = std::mem::take(&mut d.pending);
                self.send_dm(vid, K_HELLO, String::new(), app);
                for p in pending {
                    self.send_dm(vid, K_TEXT, p, app);
                }
            }
            Err(_) => app.warn(vid, "their bundle does not verify against their card. not proceeding."),
        }
    }

    fn send_dm(&mut self, vid: u64, kind: u8, text: String, app: &mut App) {
        let Some(d) = self.dms.get_mut(&vid) else { return };
        let Some(s) = d.session.as_mut() else {
            d.pending.push(text);
            app.notice(vid, "queued until their keys arrive.");
            return;
        };
        match s.seal(&self.masks[d.mask].mask, kind, &text) {
            Ok((mbox, ttl, blob)) => {
                let me = self.masks[d.mask].mask.who();
                let ctx = d.ctx;
                if kind == K_TEXT {
                    app.push(vid, line(me, text, LineKind::Mine, ttl as u64));
                }
                self.put(ctx, vid, mbox, ttl, blob, DM_POW);
            }
            Err(e) => app.warn(vid, e.to_string()),
        }
    }

    pub fn act(&mut self, a: Action, app: &mut App) {
        match a {
            Action::NewMask => {
                let i = self.add_mask(Mask::generate(), app);
                app.active_mask = i;
                app.here_notice(format!("I wear a fresh mask: {}. nothing links it to the others.", app.masks[i].who.name()));
            }
            Action::SwitchMask(i) => {
                app.active_mask = i;
                app.here_notice(format!("I am {} now. new unions and dms wear this mask.", app.masks[i].who.name()));
            }
            Action::Dm(arg) => self.open_dm(&arg, app),
            Action::Say(vid, text) => match app.views.iter().find(|v| v.id == vid).map(|v| v.kind) {
                Some(ViewKind::Dm) => self.send_dm(vid, K_TEXT, text, app),
                Some(ViewKind::Union) => crate::unions::say(self, vid, text, app),
                _ => {}
            },
            Action::Leave(vid) => {
                if let Some(d) = self.dms.remove(&vid) {
                    self.net.drop_ctx(d.ctx);
                } else {
                    crate::unions::leave(self, vid, app);
                }
                app.remove_view(vid);
                app.here_notice("gone. nothing of it remains here.");
            }
            Action::Ttl(vid, secs) => {
                if let Some(s) = self.dms.get_mut(&vid).and_then(|d| d.session.as_mut()) {
                    s.ttl = secs as u32;
                } else if crate::unions::set_ttl(self, vid, secs) {
                    app.notice(vid, "the union ends no later than that for me, and each term lasts that long.");
                }
                if let Some(v) = app.view_mut(vid) {
                    v.ttl = secs;
                }
                app.notice(vid, format!("my words here now live {}.", crate::app::fmt_duration(secs)));
            }
            Action::Verify(vid, name) => self.verify(vid, name, app),
            Action::Cover(on) => {
                self.net.cfg.cover.store(on, Ordering::Relaxed);
                app.cover = on;
                app.here_notice(if on { "cover traffic on: one cell per beat, whether I speak or not." } else { "cover traffic off: my silences are visible again." });
            }
            Action::Export(arg) => self.export(arg, app),
            Action::Import(arg) => self.import(&arg, app),
            Action::NewUnion { passphrase } => crate::unions::create(self, passphrase, app),
            Action::Join(arg) => crate::unions::join(self, &arg, app),
            Action::Renew(vid) => crate::unions::renew(self, vid, app),
            Action::Drop(vid, name) => crate::unions::drop_vote(self, vid, &name, app),
            Action::Burn | Action::Quit => {}
        }
    }

    fn open_dm(&mut self, arg: &str, app: &mut App) {
        let card = match Card::parse(arg) {
            Ok(c) => c,
            Err(_) => return app.here_notice(format!("a dm needs a card: {CARD_PREFIX}…  (/card shows mine)")),
        };
        let mi = app.active_mask;
        if self.masks.iter().any(|m| m.mask.who() == card.who) {
            return app.here_notice("that card is one of my own masks.");
        }
        self.pin(card.who, app);
        if let Some((v, _)) = self.dms.iter().find(|(_, d)| d.mask == mi && d.peer == card.who) {
            let v = *v;
            return app.focus(v);
        }
        let vid = app.fresh_id();
        let mut view = View::new(vid, ViewKind::Dm, card.who.name(), mi);
        view.who = Some(card.who);
        view.ttl = dm::DEFAULT_TTL as u64;
        app.add_view(view);
        app.focus(vid);
        app.notice(vid, format!("reaching {} as {}…", card.who.name(), app.masks[mi].who.name()));
        self.dms.insert(vid, DmState { mask: mi, peer: card.who, card: Some(card), session: None, pending: Vec::new(), ctx: random_u64(), retry_at: None });
        self.fetch_bundle(vid);
    }

    fn verify(&mut self, vid: u64, name: Option<String>, app: &mut App) {
        let view = app.views.iter().find(|v| v.id == vid);
        let mi = view.map(|v| v.mask).unwrap_or(app.active_mask);
        let me = self.masks.get(mi).map(|m| m.mask.who());
        let target = match (&name, self.dms.get(&vid)) {
            (None, Some(d)) => Some(d.peer),
            (Some(n), _) => self
                .pins
                .get(n)
                .copied()
                .or_else(|| crate::unions::member_named(self, vid, n)),
            (None, None) => me,
        };
        let (Some(t), Some(me)) = (target, me) else { return app.notice(vid, "verify whom? /verify <name>") };
        app.notice(vid, format!("{} {}", t.glyph(), t.name()));
        for row in t.identicon() {
            let s: String = row.iter().map(|b| if *b { "██" } else { "  " }).collect();
            app.notice(vid, format!("    {s}"));
        }
        app.notice(vid, format!("fingerprint  {}", t.fingerprint()));
        app.notice(vid, format!("pgp          {}", pgp::fingerprint(&t)));
        if t != me {
            app.notice(vid, format!("SAS  {}", sas(&me, &t)));
            app.notice(vid, "compare the SAS out of band. same words on both screens → nobody stands between us.");
        }
    }

    fn export(&mut self, arg: Option<String>, app: &mut App) {
        let Some(ms) = self.masks.get(app.active_mask) else { return };
        let card = ms.mask.card().encode();
        match arg.as_deref() {
            Some("card") => {
                app.here_notice("my card (whoever holds it can reach this mask):");
                app.here_notice(card);
            }
            Some(path) => {
                let armor = pgp::export(&ms.mask);
                match std::fs::write(path, armor) {
                    Ok(_) => app.here_notice(format!("public key written to {path} — I chose to touch the disk.")),
                    Err(_) => app.here_notice("could not write there."),
                }
            }
            None => {
                let armor = pgp::export(&ms.mask);
                app.here_notice(format!("pgp {}", pgp::fingerprint(&ms.mask.who())));
                for l in armor.lines() {
                    app.here_notice(l.to_string());
                }
                app.here_notice(card);
            }
        }
    }

    fn import(&mut self, arg: &str, app: &mut App) {
        let who = if arg.starts_with(CARD_PREFIX) {
            Card::parse(arg).map(|c| c.who).ok()
        } else {
            std::fs::read_to_string(arg).ok().and_then(|a| pgp::import(&a).ok())
        };
        match who {
            Some(w) => {
                self.pin(w, app);
                app.here_notice(format!("pinned {} {} · pgp {}", w.glyph(), w.name(), pgp::fingerprint(&w)));
            }
            None => app.here_notice("not a card or an ed25519 pgp public key I can verify."),
        }
    }

    /// Drop every secret this process holds. Memory is zeroized on drop.
    pub fn burn(&mut self) {
        self.dms.clear();
        self.unions.clear();
        self.masks.clear();
        self.pins.clear();
        self.seen.clear();
        self.polls.clear();
        self.cursors.clear();
        self.net.clear();
    }

    pub fn active_ctx_drop(&mut self, ctx: u64) {
        self.unwatch_ctx(ctx);
        self.net.drop_ctx(ctx);
    }

    pub fn watch_union(&mut self, mbox: Mbox, ctx: u64, vid: u64) {
        self.watch(mbox, ctx, Route::Union(vid));
    }

    pub fn unwatch_union_except(&mut self, vid: u64, keep: &[Mbox]) {
        self.polls.retain(|m, p| p.route != Route::Union(vid) || keep.contains(m));
    }
}

#[cfg(test)]
pub mod harness {
    use super::*;
    use crate::net::testutil;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

    pub struct Peer {
        pub e: Engine,
        pub app: App,
        rx: UnboundedReceiver<NetEvent>,
    }

    impl Peer {
        pub fn new(relay: RelayAddr) -> Peer {
            let (tx, rx) = unbounded_channel();
            let net = Net::new(NetCfg { relays: vec![relay], socks: None, cover: Arc::new(AtomicBool::new(false)), cover_ms: 20, delay_ms: 0 });
            let mut e = Engine::new(net, tx);
            e.poll_secs = 0;
            let mut app = App::new(false);
            app.mode = crate::app::Mode::Normal;
            e.add_mask(Mask::generate(), &mut app);
            Peer { e, app, rx }
        }
        pub fn me(&self) -> Who {
            self.app.masks[self.app.active_mask].who
        }
        pub fn card(&self) -> String {
            self.e.masks[self.app.active_mask].mask.card().encode()
        }
        pub fn cmd(&mut self, line: &str) {
            self.app.input = line.to_string();
            self.app.submit();
            for a in std::mem::take(&mut self.app.outbox) {
                self.e.act(a, &mut self.app);
            }
        }
        fn step(&mut self) {
            self.e.tick(&mut self.app);
            for a in std::mem::take(&mut self.app.outbox) {
                self.e.act(a, &mut self.app);
            }
            while let Ok(ev) = self.rx.try_recv() {
                self.e.on_net(ev, &mut self.app);
            }
        }
        pub fn texts(&self, kind: ViewKind) -> Vec<String> {
            self.app.views.iter().filter(|v| v.kind == kind).flat_map(|v| v.lines.iter().map(|l| l.text.clone())).collect()
        }
        pub fn has(&self, kind: ViewKind, needle: &str) -> bool {
            self.texts(kind).iter().any(|t| t.contains(needle))
        }
        pub fn focus_kind(&mut self, kind: ViewKind) {
            if let Some(v) = self.app.views.iter().find(|v| v.kind == kind).map(|v| v.id) {
                self.app.focus(v);
            }
        }
    }

    pub async fn relay() -> RelayAddr {
        testutil::relay().await
    }

    pub async fn until(peers: &mut [&mut Peer], secs: u64, cond: impl Fn(&[&mut Peer]) -> bool) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            for p in peers.iter_mut() {
                p.step();
            }
            if cond(peers) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::harness::*;
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_masks_dm_end_to_end() {
        let r = relay().await;
        let mut a = Peer::new(r.clone());
        let mut b = Peer::new(r);
        // Let both publish bundles.
        until(&mut [&mut a, &mut b], 1, |_| false).await;
        let card = b.card();
        a.cmd(&format!("/dm {card}"));
        a.cmd("mine, not yours");
        let ok = until(&mut [&mut a, &mut b], 20, |p| p[1].has(ViewKind::Dm, "mine, not yours")).await;
        assert!(ok, "bob never heard alice: {:?}", b.texts(ViewKind::Dm));
        let bob_view = b.app.views.iter().find(|v| v.kind == ViewKind::Dm).unwrap();
        assert_eq!(bob_view.who, Some(a.me()));
        b.focus_kind(ViewKind::Dm);
        b.cmd("not theirs");
        let ok = until(&mut [&mut a, &mut b], 20, |p| p[0].has(ViewKind::Dm, "not theirs")).await;
        assert!(ok, "alice never heard bob: {:?}", a.texts(ViewKind::Dm));
        a.cmd("again");
        assert!(until(&mut [&mut a, &mut b], 20, |p| p[1].has(ViewKind::Dm, "again")).await);
        // SAS matches on both ends.
        a.cmd("/verify");
        b.cmd("/verify");
        let sa: Vec<String> = a.texts(ViewKind::Dm).into_iter().filter(|t| t.starts_with("SAS")).collect();
        let sb: Vec<String> = b.texts(ViewKind::Dm).into_iter().filter(|t| t.starts_with("SAS")).collect();
        assert_eq!(sa, sb);
        assert!(!sa.is_empty());
        // Leaving leaves nothing.
        a.cmd("/leave");
        assert!(a.e.dms.is_empty());
        assert!(a.app.views.iter().all(|v| v.kind != ViewKind::Dm));
    }
}
