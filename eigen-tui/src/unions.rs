//! Unions in the engine: roster, sender-key distribution, terms, renewal,
//! drop votes and rekeying. No participant holds authority; each client applies
//! the same rules.
use std::collections::{HashMap, HashSet};

use eigen_core::cell::{Item, Mbox};
use eigen_core::crypto::{h, random, random_u64};
use eigen_core::identity::Who;
use eigen_core::union::{
    self, Body, RecvChain, SenderChain, UnionKeys, DEFAULT_POW, INVITE_PREFIX, JOIN_EXTRA,
};
use eigen_core::{now, pow};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::app::{fmt_duration, App, View, ViewKind};
use crate::engine::Engine;

pub const TERM: u64 = 24 * 3600;
const HELLO_WINDOW: u64 = 30;
const CTRL_TTL: u32 = 3600;
/// How long old union keys keep being read after a rekey.
const REKEY_GRACE: u64 = 300;
/// If the expected rekeyer stays silent this long, anyone remaining rekeys.
const REKEY_FALLBACK: u64 = 15;

pub struct Member {
    pub mx: Option<[u8; 32]>,
    pub chain: Option<RecvChain>,
    pub renewed_for: u32,
}

impl Member {
    fn new() -> Member {
        Member {
            mx: None,
            chain: None,
            renewed_for: 0,
        }
    }
}

pub struct UnionState {
    pub keys: UnionKeys,
    pub mask: usize,
    pub ctx: u64,
    my_mx: StaticSecret,
    chain: SenderChain,
    sent_to: HashSet<Who>,
    pub members: HashMap<Who, Member>,
    pub term: u32,
    pub ends_at: u64,
    pub term_len: u64,
    pub msg_ttl: u32,
    pub renewed: bool,
    votes: HashMap<Who, HashSet<Who>>,
    dropped: HashSet<Who>,
    /// Left this term: stale messages from them must not bring them back.
    gone: HashSet<Who>,
    /// Messages that arrived before their sender's key (puts race on the relay).
    held: Vec<(Who, u32, u32, Vec<u8>, u64)>,
    hello_until: u64,
    /// When I entered: earlier JOINs are history, not arrivals.
    joined_at: u64,
    hour: u64,
    /// Rekey epoch and the hash of the secret I adopted for it (lowest hash wins).
    pub epoch: u32,
    cand: [u8; 32],
    rekey_due: Option<u64>,
    /// Previous keys, still read until the grace period ends.
    old: Vec<(UnionKeys, u64)>,
    /// The face the union had when I entered; stays stable across rekeys.
    pub face: Who,
}

impl UnionState {
    fn mx_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.my_mx).to_bytes()
    }
    fn mailboxes(&self, hour: u64) -> Vec<Mbox> {
        let t = now();
        std::iter::once(&self.keys)
            .chain(
                self.old
                    .iter()
                    .filter(|(_, until)| *until > t)
                    .map(|(k, _)| k),
            )
            .flat_map(|k| [k.mbox(hour), k.mbox(hour.saturating_sub(1))])
            .collect()
    }
}

fn me(e: &Engine, vid: u64) -> Option<Who> {
    let u = e.unions.get(&vid)?;
    e.masks.get(u.mask).map(|m| m.mask.who())
}

fn send(e: &mut Engine, vid: u64, body: Body) {
    let Some(u) = e.unions.get(&vid) else { return };
    let Some(ms) = e.masks.get(u.mask) else {
        return;
    };
    let inner = union::sign(&ms.mask, &u.keys.uid, &body);
    let mbox = u.keys.mbox(pow::hour_now());
    let bits = u.keys.pow
        + if matches!(body, Body::Join { .. }) {
            JOIN_EXTRA
        } else {
            0
        };
    let ttl = match body {
        Body::Msg { .. } => u
            .msg_ttl
            .min(u.ends_at.saturating_sub(now()).max(10) as u32),
        _ => CTRL_TTL,
    };
    let ctx = u.ctx;
    if let Ok(blob) = u.keys.seal(&mbox, &inner) {
        e.put(ctx, vid, mbox, ttl, blob, bits);
    }
}

fn watch_all(e: &mut Engine, vid: u64) {
    let Some(u) = e.unions.get(&vid) else { return };
    let boxes = u.mailboxes(pow::hour_now());
    let ctx = u.ctx;
    e.unwatch_union_except(vid, &boxes);
    for m in boxes {
        e.watch_union(m, ctx, vid);
    }
}

/// Give my current chain to every known participant who doesn't have it yet.
fn sync_keys(e: &mut Engine, vid: u64) {
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    let to: Vec<(Who, [u8; 32])> = u
        .members
        .iter()
        .filter(|(w, m)| m.mx.is_some() && !u.sent_to.contains(*w) && !u.dropped.contains(*w))
        .map(|(w, m)| (*w, m.mx.unwrap_or_default()))
        .collect();
    if to.is_empty() {
        return;
    }
    u.sent_to.extend(to.iter().map(|(w, _)| *w));
    for b in u.chain.distribute(&u.keys.uid, &to) {
        send(e, vid, b);
    }
}

fn rotate_chain(e: &mut Engine, vid: u64) {
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    u.chain = SenderChain::fresh(u.chain.gen.wrapping_add(1));
    u.sent_to.clear();
    sync_keys(e, vid);
}

/// The roster shrank: new sender keys now, and a new union secret so those who
/// left cannot even watch the mailboxes. The participant with the lowest key
/// rekeys first (a deterministic convention, not a privilege); anyone else does
/// if it stays silent.
fn shrink(e: &mut Engine, vid: u64, app: &mut App) {
    rotate_chain(e, vid);
    let Some(me) = me(e, vid) else { return };
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    if u.members.is_empty() {
        // Alone: a fresh secret still cuts off whoever left.
        return issue_rekey(e, vid, app);
    }
    if u.members.keys().all(|w| me < *w) {
        issue_rekey(e, vid, app);
    } else {
        u.rekey_due = Some(now() + REKEY_FALLBACK);
    }
}

fn issue_rekey(e: &mut Engine, vid: u64, app: &mut App) {
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    let secret: Zeroizing<[u8; 32]> = Zeroizing::new(random());
    let epoch = u.epoch + 1;
    let to: Vec<(Who, [u8; 32])> = u
        .members
        .iter()
        .filter_map(|(w, m)| m.mx.map(|mx| (*w, mx)))
        .collect();
    let bodies = union::rekey_bodies(&u.keys.uid, epoch, &secret, &to);
    for b in bodies {
        send(e, vid, b);
    }
    adopt(e, vid, &secret, epoch, Some(app));
}

fn adopt(e: &mut Engine, vid: u64, secret: &[u8; 32], epoch: u32, app: Option<&mut App>) {
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    let fresh = UnionKeys::from_saved(*secret, u.keys.pow);
    let old = std::mem::replace(&mut u.keys, fresh);
    u.old.push((old, now() + REKEY_GRACE));
    u.epoch = epoch;
    u.cand = h(&[b"eigen/rekey-cand", secret]);
    u.rekey_due = None;
    let old_uids: Vec<[u8; 32]> = e.unions[&vid].old.iter().map(|(k, _)| k.uid).collect();
    if old_uids.iter().any(|o| e.kept.remove(o)) {
        e.kept.insert(e.unions[&vid].keys.uid);
        e.dirty = true;
    }
    watch_all(e, vid);
    rotate_chain(e, vid);
    if let Some(app) = app {
        app.notice(vid, "the union took a new secret. whoever left cannot follow, not even to count our words. old invites are void (/invite).");
    }
}

fn start(e: &mut Engine, keys: UnionKeys, announce: bool, app: &mut App) {
    let mi = app.active_mask;
    if let Some((v, _)) = e
        .unions
        .iter()
        .find(|(_, u)| u.keys.uid == keys.uid && u.mask == mi)
    {
        let v = *v;
        return app.focus(v);
    }
    let vid = app.fresh_id();
    let face = keys.face();
    let mut view = View::new(vid, ViewKind::Union, format!("union {}", face.name()), mi);
    view.who = Some(face);
    let t = now();
    view.ends_at = Some(t + TERM);
    view.ttl = 3600;
    app.add_view(view);
    app.focus(vid);
    let st = UnionState {
        mask: mi,
        ctx: random_u64(),
        my_mx: StaticSecret::random_from_rng(rand_core::OsRng),
        chain: SenderChain::fresh(1),
        sent_to: HashSet::new(),
        members: HashMap::new(),
        term: 0,
        ends_at: t + TERM,
        term_len: TERM,
        msg_ttl: 3600,
        renewed: false,
        votes: HashMap::new(),
        dropped: HashSet::new(),
        gone: HashSet::new(),
        held: Vec::new(),
        hello_until: t + HELLO_WINDOW,
        joined_at: t,
        hour: pow::hour_now(),
        epoch: 0,
        cand: [0xff; 32],
        rekey_due: None,
        old: Vec::new(),
        face,
        keys,
    };
    let mx = st.mx_pub();
    e.unions.insert(vid, st);
    watch_all(e, vid);
    app.notice(
        vid,
        format!(
            "I am here as {}. the union ends in {} unless I /renew.",
            app.masks[mi].who.name(),
            fmt_duration(TERM)
        ),
    );
    if announce {
        app.notice(vid, "announcing myself (proof of work)…");
        send(e, vid, Body::Join { mx, at: now() });
    }
}

pub fn rejoin(e: &mut Engine, keys: UnionKeys, app: &mut App) {
    start(e, keys, true, app);
}

pub fn create(e: &mut Engine, passphrase: Option<String>, app: &mut App) {
    match passphrase {
        Some(p) => join(e, &p, app),
        None => {
            let keys = UnionKeys::generate(DEFAULT_POW);
            let invite = keys.invite();
            start(e, keys, false, app);
            let vid = app.view().id;
            app.notice(vid, "a union of one. whoever holds this invite may enter — pass it only to those I choose:");
            app.notice(vid, invite);
        }
    }
}

pub fn join(e: &mut Engine, arg: &str, app: &mut App) {
    let keys = if arg.starts_with(INVITE_PREFIX) {
        UnionKeys::parse_invite(arg)
    } else {
        app.here_notice("stretching the passphrase (argon2id, 64 MiB)…");
        UnionKeys::from_passphrase(arg)
    };
    match keys {
        Ok(k) => start(e, k, true, app),
        Err(_) => app.here_notice("that invite does not parse."),
    }
}

pub fn who(e: &mut Engine, vid: u64, app: &mut App) {
    let Some(me) = me(e, vid) else { return };
    let Some(u) = e.unions.get(&vid) else { return };
    let next = u.term + 1;
    let mut rows = vec![format!(
        "{} {} (me){}",
        me.glyph(),
        me.name(),
        if u.renewed { " · stays" } else { "" }
    )];
    let mut others: Vec<(&Who, &Member)> = u.members.iter().collect();
    others.sort_by_key(|(w, _)| w.name());
    for (w, m) in others {
        rows.push(format!(
            "{} {}{}{}{}",
            w.glyph(),
            w.name(),
            if app.trusted.contains(w) { " ✓" } else { "" },
            if m.renewed_for >= next {
                " · stays"
            } else {
                ""
            },
            if m.chain.is_none() {
                " · no key from them yet"
            } else {
                ""
            },
        ));
    }
    app.notice(
        vid,
        format!(
            "{} here, as far as I can see (no one can see more):",
            rows.len()
        ),
    );
    for r in rows {
        app.notice(vid, format!("  {r}"));
    }
}

pub fn say(e: &mut Engine, vid: u64, kind: u8, id: [u8; 8], text: String, app: &mut App) {
    let Some(me) = me(e, vid) else { return };
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    match u.chain.encrypt(&u.keys.uid, &me, kind, id, &text) {
        Ok(body) => {
            let ttl = u.msg_ttl as u64;
            if u.members.is_empty() && kind != crate::app::SAY_UNSAY {
                app.notice(vid, "nobody else is here yet; I speak to the walls.");
            }
            app.receive(vid, me, kind, id, text, ttl, true);
            send(e, vid, body);
        }
        Err(err) => app.warn(vid, err.to_string()),
    }
}

fn forget(e: &mut Engine, u: &UnionState) {
    let mut changed = e.kept.remove(&u.keys.uid);
    for (k, _) in &u.old {
        changed |= e.kept.remove(&k.uid);
    }
    if changed {
        e.dirty = true;
    }
}

fn dissolve(e: &mut Engine, vid: u64, app: &mut App, why: &str) {
    if let Some(u) = e.unions.remove(&vid) {
        forget(e, &u);
        let name = u.face.name();
        e.active_ctx_drop(u.ctx);
        app.remove_view(vid);
        app.notice(0, format!("union {name}: {why}"));
    }
}

pub fn leave(e: &mut Engine, vid: u64, _app: &mut App) {
    if e.unions.contains_key(&vid) {
        // Tell the others so they rotate away from me; then forget everything.
        send(e, vid, Body::Leave);
        if let Some(u) = e.unions.remove(&vid) {
            forget(e, &u);
            e.active_ctx_drop(u.ctx);
        }
    }
}

pub fn renew(e: &mut Engine, vid: u64, app: &mut App) {
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    if u.renewed {
        return app.notice(vid, "I already said I stay.");
    }
    u.renewed = true;
    let term = u.term + 1;
    let others = u.members.values().filter(|m| m.renewed_for >= term).count();
    if let Some(v) = app.view_mut(vid) {
        v.renewed = true;
    }
    app.notice(
        vid,
        format!("I stay for the next term. {others} other(s) have said the same so far."),
    );
    send(e, vid, Body::Renew { term });
}

pub fn member_named(e: &Engine, vid: u64, name: &str) -> Option<Who> {
    e.unions
        .get(&vid)?
        .members
        .keys()
        .find(|w| w.name() == name)
        .copied()
}

pub fn drop_vote(e: &mut Engine, vid: u64, name: &str, app: &mut App) {
    let Some(me) = me(e, vid) else { return };
    let Some(target) = member_named(e, vid, name) else {
        return app.notice(vid, "nobody by that name is in this union.");
    };
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    let term = u.term;
    u.votes.entry(target).or_default().insert(me);
    app.notice(
        vid,
        format!("I vote to rotate keys away from {name}. it takes a majority of the others."),
    );
    send(e, vid, Body::Drop { target, term });
    evaluate(e, vid, target, app);
}

fn evaluate(e: &mut Engine, vid: u64, target: Who, app: &mut App) {
    let Some(me) = me(e, vid) else { return };
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    let mut electorate: HashSet<Who> = u.members.keys().copied().collect();
    electorate.insert(me);
    electorate.remove(&target);
    let votes = u
        .votes
        .get(&target)
        .map(|v| v.intersection(&electorate).count())
        .unwrap_or(0);
    if votes * 2 <= electorate.len() {
        return;
    }
    if target == me {
        return dissolve(
            e,
            vid,
            app,
            "the others rotated their keys away from me. I am no longer in it.",
        );
    }
    u.members.remove(&target);
    u.votes.remove(&target);
    u.dropped.insert(target);
    app.notice(
        vid,
        format!(
            "{votes} of {} agreed: keys rotate away from {}. not a punishment; just no longer us.",
            electorate.len(),
            target.name()
        ),
    );
    shrink(e, vid, app);
}

fn push_said(app: &mut App, vid: u64, from: Who, said: union::Said, ttl: u64) {
    app.receive(vid, from, said.kind, said.id, said.text, ttl, false);
}

pub fn on_blob(e: &mut Engine, vid: u64, mbox: &Mbox, it: &Item, app: &mut App) {
    let Some(me) = me(e, vid) else { return };
    let Some(u) = e.unions.get(&vid) else { return };
    // Current keys first, then keys still in their grace period.
    let t = now();
    let opened = std::iter::once(&u.keys)
        .chain(u.old.iter().filter(|(_, until)| *until > t).map(|(k, _)| k))
        .find_map(|k| {
            k.open(mbox, &it.blob)
                .ok()
                .map(|inner| (k.uid, k.uid == u.keys.uid, inner))
        });
    let Some((uid, current, inner)) = opened else {
        return;
    };
    let Ok((from, body)) = union::verify(&uid, &inner) else {
        return;
    };
    if from == me {
        return;
    }
    // Re-check the work myself; the relay's word is worth nothing.
    let need = u.keys.pow
        + if matches!(body, Body::Join { .. }) {
            JOIN_EXTRA
        } else {
            0
        };
    if !pow::check(it.hour, mbox, &it.blob, it.nonce, need) {
        return;
    }
    if u.dropped.contains(&from) {
        return;
    }
    if u.gone.contains(&from) && !matches!(body, Body::Join { .. }) {
        return;
    }
    // Joins through a void invite are not answered.
    if !current && matches!(body, Body::Join { .. }) {
        return;
    }
    e.pin(from, app);
    let Some(u) = e.unions.get_mut(&vid) else {
        return;
    };
    match body {
        Body::Join { mx, at } => {
            // Old JOINs still on the relay are history; answering them would tell a
            // newcomer who was here before them.
            if at + e.join_skew < u.joined_at || at > now() + e.join_skew {
                return;
            }
            u.gone.remove(&from);
            let fresh = !u.members.contains_key(&from);
            let m = u.members.entry(from).or_insert_with(Member::new);
            if m.mx != Some(mx) {
                m.mx = Some(mx);
                u.sent_to.remove(&from);
            }
            let hello = Body::Hello {
                mx: u.mx_pub(),
                ends_at: u.ends_at,
                term: u.term,
                to: from,
            };
            if fresh {
                app.notice(
                    vid,
                    format!("{} {} entered the union.", from.glyph(), from.name()),
                );
            }
            send(e, vid, hello);
            sync_keys(e, vid);
        }
        Body::Hello {
            mx,
            ends_at,
            term,
            to,
        } => {
            // HELLOs answer one newcomer; the rest are none of my business.
            if to != me {
                return;
            }
            let fresh = !u.members.contains_key(&from);
            let m = u.members.entry(from).or_insert_with(Member::new);
            m.mx = Some(mx);
            if now() < u.hello_until {
                // Dissolution is the default: adopt the earliest end anyone reports.
                if ends_at < u.ends_at && ends_at > now() {
                    u.ends_at = ends_at;
                }
                u.term = u.term.max(term);
            }
            if fresh {
                app.notice(vid, format!("{} {} is here.", from.glyph(), from.name()));
            }
            sync_keys(e, vid);
        }
        Body::Skey { gen, eph, entries } => {
            let Some(rc) = RecvChain::open_skey(&uid, &me, &u.my_mx, gen, &eph, &entries) else {
                return;
            };
            let m = u.members.entry(from).or_insert_with(Member::new);
            if m.chain.as_ref().is_some_and(|c| c.gen > gen) {
                return;
            }
            m.chain = Some(rc);
            let ttl = u.msg_ttl as u64;
            let (ready, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut u.held)
                .into_iter()
                .partition(|h| h.0 == from && h.1 == gen);
            u.held = keep;
            if let Some(chain) = u.members.get_mut(&from).and_then(|m| m.chain.as_mut()) {
                for (_, _, idx, ct, _) in ready {
                    if let Ok(said) = chain.decrypt(&from, idx, &ct) {
                        push_said(app, vid, from, said, ttl);
                    }
                }
            }
        }
        Body::Msg { gen, idx, ct } => {
            let ttl = u.msg_ttl as u64;
            let chain = u
                .members
                .get_mut(&from)
                .and_then(|m| m.chain.as_mut())
                .filter(|c| c.gen == gen);
            let Some(chain) = chain else {
                // No key yet: hold it briefly, it may be on its way.
                u.held.retain(|h| h.4 > now());
                if u.held.len() < 256 {
                    u.held.push((from, gen, idx, ct, now() + 120));
                }
                return;
            };
            if let Ok(said) = chain.decrypt(&from, idx, &ct) {
                push_said(app, vid, from, said, ttl);
            }
        }
        Body::Leave => {
            u.gone.insert(from);
            if u.members.remove(&from).is_some() {
                app.notice(vid, format!("{} left. my keys rotate.", from.name()));
                shrink(e, vid, app);
            }
        }
        Body::Renew { term } => {
            if term == u.term + 1 {
                if let Some(m) = u.members.get_mut(&from) {
                    m.renewed_for = term;
                    let mine = if u.renewed {
                        ""
                    } else {
                        " /renew to stay with them."
                    };
                    app.notice(
                        vid,
                        format!("{} will stay for the next term.{mine}", from.name()),
                    );
                }
            }
        }
        Body::Drop { target, term } => {
            if term == u.term && u.members.contains_key(&from) {
                u.votes.entry(target).or_default().insert(from);
                let who = if target == me {
                    "me".to_string()
                } else {
                    target.name()
                };
                app.notice(
                    vid,
                    format!("{} votes to rotate keys away from {who}.", from.name()),
                );
                evaluate(e, vid, target, app);
            }
        }
        Body::Rekey {
            epoch,
            eph,
            entries,
        } => {
            if !u.members.contains_key(&from) {
                return;
            }
            let Some(secret) = union::open_rekey(&uid, &me, &u.my_mx, epoch, &eph, &entries) else {
                return;
            };
            let cand = h(&[b"eigen/rekey-cand", &secret[..]]);
            // Concurrent rekeys converge: higher epoch wins, then the lowest hash.
            let better = epoch > u.epoch || (epoch == u.epoch && cand < u.cand);
            if better && cand != u.cand {
                adopt(e, vid, &secret, epoch, Some(app));
            }
        }
    }
}

pub fn tick(e: &mut Engine, app: &mut App) {
    let t = now();
    let hour = pow::hour_now();
    let vids: Vec<u64> = e.unions.keys().copied().collect();
    for vid in vids {
        let Some(u) = e.unions.get_mut(&vid) else {
            continue;
        };
        let expired_old = u.old.iter().any(|(_, until)| *until <= t);
        if u.hour != hour || expired_old {
            u.hour = hour;
            u.old.retain(|(_, until)| *until > t);
            watch_all(e, vid);
        }
        let Some(u) = e.unions.get_mut(&vid) else {
            continue;
        };
        if u.rekey_due.is_some_and(|d| d <= t) {
            issue_rekey(e, vid, app);
        }
        let Some(u) = e.unions.get_mut(&vid) else {
            continue;
        };
        if t >= u.ends_at {
            if !u.renewed {
                dissolve(
                    e,
                    vid,
                    app,
                    "dissolved at its end. nothing of it remains here.",
                );
                continue;
            }
            u.term += 1;
            u.ends_at += u.term_len;
            u.renewed = false;
            u.votes.clear();
            u.dropped.clear();
            u.gone.clear();
            let term = u.term;
            let gone: Vec<Who> = u
                .members
                .iter()
                .filter(|(_, m)| m.renewed_for < term)
                .map(|(w, _)| *w)
                .collect();
            for w in &gone {
                u.members.remove(w);
            }
            let stayed = u.members.len();
            app.notice(
                vid,
                format!(
                    "a new term. {stayed} other(s) stayed; {} did not.",
                    gone.len()
                ),
            );
            if !gone.is_empty() {
                shrink(e, vid, app);
            }
        }
        if let Some(u) = e.unions.get(&vid) {
            let (end, renewed, ttl) = (u.ends_at, u.renewed, u.msg_ttl);
            if let Some(v) = app.view_mut(vid) {
                v.ends_at = Some(end);
                v.renewed = renewed;
                v.ttl = ttl as u64;
            }
        }
    }
}

/// `/ttl` in a union: my term length from now on, and never later than now + ttl.
pub fn set_ttl(e: &mut Engine, vid: u64, secs: u64) -> bool {
    let Some(u) = e.unions.get_mut(&vid) else {
        return false;
    };
    u.term_len = secs;
    u.ends_at = u.ends_at.min(now() + secs);
    u.msg_ttl = u.msg_ttl.min(secs as u32);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::harness::*;

    fn invite(p: &Peer) -> String {
        p.texts(ViewKind::Union)
            .into_iter()
            .find(|t| t.starts_with(INVITE_PREFIX))
            .expect("invite shown")
    }

    fn roster(p: &Peer) -> usize {
        p.e.unions
            .values()
            .next()
            .map(|u| u.members.len())
            .unwrap_or(0)
    }

    fn keyed(p: &Peer) -> usize {
        p.e.unions
            .values()
            .next()
            .map(|u| u.members.values().filter(|m| m.chain.is_some()).count())
            .unwrap_or(0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn union_join_speak_drop_leave() {
        let r = relay().await;
        let (mut a, mut b, mut c, mut d) = (
            Peer::new(r.clone()),
            Peer::new(r.clone()),
            Peer::new(r.clone()),
            Peer::new(r),
        );
        a.cmd("/union");
        let inv = invite(&a);
        for p in [&mut b, &mut c, &mut d] {
            p.cmd(&format!("/join {inv}"));
        }
        let all = until(&mut [&mut a, &mut b, &mut c, &mut d], 60, |p| {
            p.iter().all(|x| roster(x) == 3 && keyed(x) == 3)
        })
        .await;
        assert!(
            all,
            "rosters {:?}",
            [roster(&a), roster(&b), roster(&c), roster(&d)]
        );
        a.cmd("one union, no owner");
        assert!(
            until(&mut [&mut a, &mut b, &mut c, &mut d], 20, |p| p[1..]
                .iter()
                .all(|x| x.has(ViewKind::Union, "no owner")))
            .await
        );
        // Drop vote: a and b rotate keys away from d.
        let dn = d.me().name();
        a.cmd(&format!("/drop {dn}"));
        b.cmd(&format!("/drop {dn}"));
        assert!(
            until(&mut [&mut a, &mut b, &mut c, &mut d], 20, |p| p[3]
                .e
                .unions
                .is_empty()
                && roster(p[2]) == 2
                && roster(p[0]) == 2)
            .await,
            "drop did not pass"
        );
        assert!(d.has(ViewKind::Home, "rotated their keys away from me"));
        // c leaves: a and b rotate again and take a new secret c cannot follow.
        let uid_before = a.e.unions.values().next().unwrap().keys.uid;
        let stale_invite = invite(&a);
        c.cmd("/leave");
        assert!(c.e.unions.is_empty());
        let ok = until(&mut [&mut a, &mut b], 30, |p| {
            let (ua, ub) = (
                p[0].e.unions.values().next().unwrap(),
                p[1].e.unions.values().next().unwrap(),
            );
            roster(p[0]) == 1
                && roster(p[1]) == 1
                && ua.keys.uid == ub.keys.uid
                && ua.keys.uid != uid_before
        })
        .await;
        assert!(
            ok,
            "after leave a={} b={} {:?}",
            roster(&a),
            roster(&b),
            a.texts(ViewKind::Union)
        );
        assert!(a.has(ViewKind::Union, "took a new secret"));
        // The old invite is void: a newcomer holding it finds nobody.
        until(&mut [&mut a, &mut b], 3, |_| false).await;
        let mut late = Peer::new(a.e.net.cfg.relays[0].clone());
        late.cmd(&format!("/join {stale_invite}"));
        until(&mut [&mut a, &mut b, &mut late], 6, |_| false).await;
        assert_eq!(roster(&late), 0, "void invite reaches no one");
        assert_eq!(roster(&a), 1);
        a.cmd("after the leaving");
        assert!(
            until(&mut [&mut a, &mut b], 20, |p| p[1]
                .has(ViewKind::Union, "after the leaving"))
            .await
        );
        assert!(!c.has(ViewKind::Union, "after the leaving"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn union_dissolves_unless_renewed() {
        let r = relay().await;
        let (mut a, mut b) = (Peer::new(r.clone()), Peer::new(r));
        a.cmd("/union");
        a.cmd("/ttl 10s");
        let inv = invite(&a);
        b.cmd(&format!("/join {inv}"));
        assert!(
            until(&mut [&mut a, &mut b], 30, |p| keyed(p[0]) == 1
                && keyed(p[1]) == 1)
            .await
        );
        let (ea, eb) = (
            a.e.unions.values().next().unwrap().ends_at,
            b.e.unions.values().next().unwrap().ends_at,
        );
        assert_eq!(ea, eb, "joiner adopts the earliest end");
        a.cmd("/renew");
        // b does not renew: at the end b is out, a carries on alone into term 1.
        assert!(until(&mut [&mut a, &mut b], 20, |p| p[1].e.unions.is_empty()).await);
        assert!(b.has(ViewKind::Home, "dissolved"));
        assert!(
            until(&mut [&mut a], 5, |p| p[0]
                .e
                .unions
                .values()
                .next()
                .is_some_and(|u| u.term == 1 && u.members.is_empty()))
            .await
        );
        // Nobody renews: it ends for everyone.
        assert!(until(&mut [&mut a], 20, |p| p[0].e.unions.is_empty()).await);
    }
}
