//! UI state and command interpretation. Protocol work happens in the engine;
//! the app only records what is displayed and emits [`Action`]s.
use std::collections::HashSet;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use eigen_core::identity::Who;
use eigen_core::now;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LineKind {
    #[default]
    Notice,
    Msg,
    Mine,
    Warn,
}

#[derive(Clone, Debug, Default)]
pub struct Line {
    pub from: Option<Who>,
    pub text: String,
    pub kind: LineKind,
    pub at: u64,
    pub expires: Option<u64>,
    /// Per-message id (lets the author take it back).
    pub id: Option<[u8; 8]>,
    /// `/me` action.
    pub action: bool,
    /// `/once`: removed 30 seconds after it is first displayed.
    pub once: bool,
    pub seen: bool,
}

/// Message kinds, shared by DMs and unions.
pub const SAY_TEXT: u8 = 1;
pub const SAY_HELLO: u8 = 2;
pub const SAY_ONCE: u8 = 3;
pub const SAY_UNSAY: u8 = 4;
pub const SAY_ACTION: u8 = 5;
pub const ONCE_SECS: u64 = 30;
const LOCK_TRIES: u8 = 5;

/// A screen lock: only a slow hash of the passphrase is held.
pub struct Lock {
    salt: [u8; 32],
    hash: zeroize::Zeroizing<[u8; 32]>,
    pub engaged: bool,
    pub fails: u8,
}

impl Lock {
    pub fn new(pass: &str) -> Option<Lock> {
        let salt = eigen_core::crypto::random();
        let hash = eigen_core::vault::derive(pass, &salt).ok()?;
        Some(Lock {
            salt,
            hash,
            engaged: true,
            fails: 0,
        })
    }
    pub fn check(&self, pass: &str) -> bool {
        let Ok(h) = eigen_core::vault::derive(pass, &self.salt) else {
            return false;
        };
        // Constant-time compare.
        h.iter()
            .zip(self.hash.iter())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewKind {
    Home,
    Union,
    Dm,
}

pub struct View {
    pub id: u64,
    pub kind: ViewKind,
    pub title: String,
    pub who: Option<Who>,
    pub mask: usize,
    pub lines: Vec<Line>,
    pub ends_at: Option<u64>,
    pub unread: bool,
    pub muted: HashSet<Who>,
    pub renewed: bool,
    pub ttl: u64,
}

impl View {
    pub fn new(id: u64, kind: ViewKind, title: String, mask: usize) -> View {
        View {
            id,
            kind,
            title,
            who: None,
            mask,
            lines: Vec::new(),
            ends_at: None,
            unread: false,
            muted: HashSet::new(),
            renewed: false,
            ttl: 3600,
        }
    }
}

/// What the app asks the engine to do.
#[derive(Debug, Clone)]
pub enum Action {
    NewMask,
    SwitchMask(usize),
    NewUnion {
        passphrase: Option<String>,
    },
    Join(String),
    Leave(u64),
    Dm(String),
    Say(u64, u8, String),
    Unsay(u64),
    Trust(u64, Option<String>),
    Who(u64),
    /// Show a card or invite on a clean screen.
    Show(u64, Item),
    /// Copy a card or invite to the clipboard.
    Copy(u64, Item),
    Ttl(u64, u64),
    Renew(u64),
    Drop(u64, String),
    Cover(bool),
    Export(Option<String>),
    Import(String),
    Verify(u64, Option<String>),
    Keep(u64),
    Burn,
    Quit,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Item {
    Card,
    Invite,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Boot(u16),
    Normal,
    Help,
    /// A card or invite shown alone on the screen, ready to select or copy.
    Show,
    Burning(u16),
}

/// Text shown on the clean screen (`Mode::Show`).
pub struct Shown {
    pub title: String,
    pub text: zeroize::Zeroizing<String>,
    pub copied: bool,
}

/// Seconds after which copied text is removed from the clipboard.
pub const CLIPBOARD_SECS: u64 = 30;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TorState {
    Off,
    Connecting,
    Up,
    ClearNet,
}

pub struct MaskInfo {
    pub who: Who,
}

pub struct App {
    pub masks: Vec<MaskInfo>,
    pub active_mask: usize,
    pub views: Vec<View>,
    pub active: usize,
    pub input: String,
    pub mode: Mode,
    pub scroll: usize,
    pub tor: TorState,
    /// Transport label for the status bar, for example "Tor", "I2P", "VPN wg0" or
    /// "Direct (unencrypted)". Several labels are joined with "+".
    pub transport: String,
    pub cover: bool,
    pub locked: bool,
    pub vault: bool,
    pub color: bool,
    pub outbox: Vec<Action>,
    pub quit: bool,
    panic_presses: Vec<Instant>,
    next_id: u64,
    /// Keys verified out of band (✓).
    pub trusted: HashSet<Who>,
    /// Screen hiding: names and messages are hidden until a key is pressed.
    pub veiled: bool,
    pub veil_idle: Option<u64>,
    pub lock: Option<Lock>,
    pub lock_input: zeroize::Zeroizing<String>,
    /// Delete all data and exit if no key is pressed for this long.
    pub deadman: Option<u64>,
    pub last_key: Instant,
    history: Vec<String>,
    hist_pos: Option<usize>,
    pub shown: Option<Shown>,
    /// First visible row of the help overlay.
    pub help_scroll: usize,
    /// Text waiting to be sent to the terminal clipboard (OSC 52).
    pub clip_out: Option<zeroize::Zeroizing<String>>,
    /// Set once something was copied; the clipboard is cleared on exit and burn.
    pub clip_used: bool,
}

pub const HELP: &[(&str, &str)] = &[
    ("/mask", "Create a new mask (Ctrl-M where supported)."),
    ("/masks [n]", "List your masks, or switch to mask n."),
    ("/card", "Show your contact card. Press C to copy it."),
    (
        "/copy [card|invite]",
        "Copy your contact card or the union invite.",
    ),
    ("/dm <card>", "Open a direct message using a contact card."),
    (
        "/union [passphrase]",
        "Create a union and show its invite (Ctrl-U).",
    ),
    (
        "/join <invite|passphrase>",
        "Join a union with an invite or passphrase.",
    ),
    ("/invite", "Show this union's invite. Press C to copy it."),
    ("/leave", "Leave this union or direct message."),
    ("/verify [name]", "Show the fingerprint and SAS to compare."),
    (
        "/trust [name]",
        "Mark a key as verified (✓), or remove the mark.",
    ),
    (
        "/ttl <30m|1h|2d>",
        "Set message expiry, or your term in a union.",
    ),
    ("/renew", "Stay in this union for its next term."),
    ("/drop <name>", "Vote to remove a member from this union."),
    ("/who", "List the union members visible to you."),
    (
        "/mute <name>",
        "Hide someone's messages on your screen only.",
    ),
    ("/me <action>", "Send a message that describes an action."),
    (
        "/once <words>",
        "Send a message removed 30 s after it is read.",
    ),
    ("/unsay", "Take back your last message."),
    (
        "/veil [2m|off]",
        "Hide the screen now (Ctrl-V) or when idle.",
    ),
    (
        "/lock [passphrase]",
        "Lock the screen. 5 wrong tries delete all data.",
    ),
    (
        "/deadman <30m|off>",
        "Delete all data and exit after this idle time.",
    ),
    (
        "/cover on|off",
        "Turn constant-rate cover traffic on or off.",
    ),
    ("/keep", "Save this union in the vault, or remove it."),
    (
        "/export [path]",
        "Show your PGP public key or save it to a file.",
    ),
    (
        "/import <path|card>",
        "Import a key from a PGP key file or a card.",
    ),
    ("/burn", "Delete all data and exit (Ctrl-X three times)."),
    ("/help", "Show this list (F1)."),
    (
        "Tab / Shift-Tab",
        "Go to the next or previous conversation.",
    ),
    ("PgUp / PgDn", "Scroll up or down."),
    ("Up / Down", "Show earlier input (kept in RAM only)."),
    ("Ctrl-L", "Redraw the screen."),
];

pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().ok()?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    let v = n.checked_mul(mult)?;
    (10..=7 * 86400).contains(&v).then_some(v)
}

pub fn fmt_duration(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

impl App {
    pub fn new(color: bool) -> App {
        let mut home = View::new(0, ViewKind::Home, "Home".into(), 0);
        home.ttl = 0;
        App {
            masks: Vec::new(),
            active_mask: 0,
            views: vec![home],
            active: 0,
            input: String::new(),
            mode: Mode::Boot(0),
            scroll: 0,
            tor: TorState::Off,
            transport: String::new(),
            cover: false,
            locked: false,
            vault: false,
            color,
            outbox: Vec::new(),
            quit: false,
            panic_presses: Vec::new(),
            next_id: 1,
            trusted: HashSet::new(),
            veiled: false,
            veil_idle: Some(300),
            lock: None,
            lock_input: zeroize::Zeroizing::new(String::new()),
            deadman: None,
            last_key: Instant::now(),
            history: Vec::new(),
            hist_pos: None,
            shown: None,
            help_scroll: 0,
            clip_out: None,
            clip_used: false,
        }
    }

    pub fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    pub fn me(&self) -> Option<Who> {
        self.masks.get(self.active_mask).map(|m| m.who)
    }

    pub fn view(&self) -> &View {
        &self.views[self.active]
    }

    pub fn view_mut(&mut self, id: u64) -> Option<&mut View> {
        self.views.iter_mut().find(|v| v.id == id)
    }

    pub fn add_view(&mut self, v: View) -> usize {
        self.views.push(v);
        self.views.len() - 1
    }

    pub fn focus(&mut self, id: u64) {
        if let Some(i) = self.views.iter().position(|v| v.id == id) {
            self.active = i;
            self.views[i].unread = false;
            self.scroll = 0;
        }
    }

    pub fn remove_view(&mut self, id: u64) {
        self.views.retain(|v| v.id == 0 || v.id != id);
        if self.active >= self.views.len() {
            self.active = self.views.len() - 1;
        }
    }

    pub fn push(&mut self, id: u64, line: Line) {
        let active_id = self.view().id;
        if let Some(v) = self.view_mut(id) {
            if line.from.map(|w| v.muted.contains(&w)).unwrap_or(false) {
                return;
            }
            v.lines.push(line);
            if v.lines.len() > 2000 {
                v.lines.remove(0);
            }
            if id != active_id {
                v.unread = true;
            }
        }
    }

    pub fn notice(&mut self, id: u64, text: impl Into<String>) {
        self.push(
            id,
            Line {
                from: None,
                text: text.into(),
                kind: LineKind::Notice,
                at: now(),
                expires: None,
                ..Default::default()
            },
        );
    }

    pub fn warn(&mut self, id: u64, text: impl Into<String>) {
        self.push(
            id,
            Line {
                from: None,
                text: text.into(),
                kind: LineKind::Warn,
                at: now(),
                expires: None,
                ..Default::default()
            },
        );
    }

    /// A message arrived or was sent. Handles every kind in one place.
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &mut self,
        vid: u64,
        from: Who,
        kind: u8,
        id: [u8; 8],
        text: String,
        ttl: u64,
        mine: bool,
    ) {
        match kind {
            SAY_UNSAY => {
                let before = self.view_mut(vid).map(|v| v.lines.len()).unwrap_or(0);
                if let Some(v) = self.view_mut(vid) {
                    v.lines
                        .retain(|l| !(l.from == Some(from) && l.id == Some(id)));
                }
                let after = self.view_mut(vid).map(|v| v.lines.len()).unwrap_or(0);
                if after < before && !mine {
                    self.notice(vid, format!("{} took back a message.", from.name()));
                }
            }
            SAY_TEXT | SAY_ONCE | SAY_ACTION => {
                if text.is_empty() {
                    return;
                }
                let line = Line {
                    from: Some(from),
                    text,
                    kind: if mine { LineKind::Mine } else { LineKind::Msg },
                    at: now(),
                    expires: Some(now() + ttl),
                    id: Some(id),
                    action: kind == SAY_ACTION,
                    once: kind == SAY_ONCE,
                    seen: false,
                };
                self.push(vid, line);
            }
            _ => {}
        }
    }

    /// The id of the user's most recent message in a view.
    pub fn last_mine(&self, vid: u64) -> Option<[u8; 8]> {
        self.views
            .iter()
            .find(|v| v.id == vid)?
            .lines
            .iter()
            .rev()
            .find(|l| l.kind == LineKind::Mine)
            .and_then(|l| l.id)
    }

    pub fn history_step(&mut self, up: bool) {
        if self.history.is_empty() {
            return;
        }
        let n = self.history.len();
        let pos = match (self.hist_pos, up) {
            (None, true) => Some(n - 1),
            (None, false) => None,
            (Some(0), true) => Some(0),
            (Some(i), true) => Some(i - 1),
            (Some(i), false) if i + 1 < n => Some(i + 1),
            (Some(_), false) => None,
        };
        self.hist_pos = pos;
        self.input = pos.map(|i| self.history[i].clone()).unwrap_or_default();
    }

    /// Show text alone on a clean screen, so it can be selected or copied.
    pub fn show(&mut self, title: impl Into<String>, text: String) {
        self.shown = Some(Shown {
            title: title.into(),
            text: zeroize::Zeroizing::new(text),
            copied: false,
        });
        self.mode = Mode::Show;
    }

    /// Queue text for the terminal clipboard.
    pub fn copy(&mut self, text: String) {
        self.clip_out = Some(zeroize::Zeroizing::new(text));
    }

    /// Clear all state held by the interface.
    pub fn wipe(&mut self) {
        self.shown = None;
        self.clip_out = None;
        self.views.truncate(1);
        self.views[0].lines.clear();
        self.masks.clear();
        self.input.clear();
        self.history.clear();
        self.trusted.clear();
        self.lock = None;
        self.veiled = false;
        self.active = 0;
    }

    /// Every key press lands here.
    pub fn key(&mut self, k: KeyEvent) {
        self.last_key = Instant::now();
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('x') {
            if self.panic_press() {
                self.outbox.push(Action::Burn);
            }
            return;
        }
        if self.is_locked() {
            match k.code {
                KeyCode::Enter => self.lock_submit(),
                KeyCode::Backspace => {
                    self.lock_input.pop();
                }
                KeyCode::Esc => self.lock_input.clear(),
                KeyCode::Char(c) if !ctrl => self.lock_input.push(c),
                _ => {}
            }
            return;
        }
        if self.veiled {
            // The key that ends screen hiding is discarded, so no input is typed while hidden.
            self.veiled = false;
            return;
        }
        match self.mode {
            Mode::Burning(_) => return,
            Mode::Boot(_) => {
                self.mode = Mode::Normal;
                return;
            }
            Mode::Help => {
                match k.code {
                    KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q') => self.mode = Mode::Normal,
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.help_scroll = self.help_scroll.saturating_sub(1)
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.help_scroll = (self.help_scroll + 1).min(HELP.len())
                    }
                    KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
                    KeyCode::PageDown => self.help_scroll = (self.help_scroll + 10).min(HELP.len()),
                    _ => {}
                }
                return;
            }
            Mode::Show => {
                match k.code {
                    KeyCode::Char('c') | KeyCode::Char('C') if !ctrl => {
                        if let Some(sh) = self.shown.as_mut() {
                            self.clip_out = Some(sh.text.clone());
                            sh.copied = true;
                        }
                    }
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        self.shown = None;
                        self.mode = Mode::Normal;
                    }
                    _ => {}
                }
                return;
            }
            Mode::Normal => {}
        }
        match (k.code, ctrl) {
            (KeyCode::Char('c'), true) | (KeyCode::Char('d'), true) => {
                self.outbox.push(Action::Quit)
            }
            (KeyCode::Char('l'), true) => {}
            (KeyCode::Char('v'), true) => self.veiled = true,
            (KeyCode::Char('u'), true) => self.outbox.push(Action::NewUnion { passphrase: None }),
            (KeyCode::Char('m'), true) => self.outbox.push(Action::NewMask),
            (KeyCode::Char('n'), true) => self.cycle(1),
            (KeyCode::Char('p'), true) => self.cycle(-1),
            (KeyCode::F(1), _) => {
                self.help_scroll = 0;
                self.mode = Mode::Help;
            }
            (KeyCode::Tab, _) => self.cycle(1),
            (KeyCode::BackTab, _) => self.cycle(-1),
            (KeyCode::PageUp, _) => self.scroll += 5,
            (KeyCode::PageDown, _) => self.scroll = self.scroll.saturating_sub(5),
            (KeyCode::Up, _) => self.history_step(true),
            (KeyCode::Down, _) => self.history_step(false),
            (KeyCode::Enter, _) => self.submit(),
            (KeyCode::Backspace, _) => {
                self.input.pop();
            }
            (KeyCode::Esc, _) => self.input.clear(),
            (KeyCode::Char(c), false) => self.input.push(c),
            _ => {}
        }
    }

    pub fn is_locked(&self) -> bool {
        self.lock.as_ref().is_some_and(|l| l.engaged)
    }

    /// Enter on the lock screen.
    pub fn lock_submit(&mut self) {
        let attempt = std::mem::take(&mut *self.lock_input);
        let Some(l) = self.lock.as_mut() else { return };
        if l.check(&attempt) {
            l.engaged = false;
            l.fails = 0;
            self.veiled = false;
        } else {
            l.fails += 1;
            if l.fails >= LOCK_TRIES {
                self.outbox.push(Action::Burn);
            }
        }
    }

    /// Called about once a second: hides the screen when idle and checks auto-burn (/deadman).
    pub fn idle_check(&mut self) {
        let idle = self.last_key.elapsed().as_secs();
        if let Some(v) = self.veil_idle {
            if idle >= v {
                self.veiled = true;
            }
        }
        if let Some(d) = self.deadman {
            if idle >= d {
                self.deadman = None;
                self.outbox.push(Action::Burn);
            }
        }
    }

    pub fn here_notice(&mut self, text: impl Into<String>) {
        let id = self.view().id;
        self.notice(id, text);
    }

    /// Drop expired lines everywhere (disappearing messages).
    pub fn expire(&mut self) {
        let t = now();
        if !self.veiled && !self.lock.as_ref().is_some_and(|l| l.engaged) {
            let active = self.active;
            for l in self.views[active]
                .lines
                .iter_mut()
                .filter(|l| l.once && !l.seen)
            {
                l.seen = true;
                l.expires = Some(l.expires.unwrap_or(u64::MAX).min(t + ONCE_SECS));
            }
        }
        for v in &mut self.views {
            v.lines.retain(|l| l.expires.map(|e| e > t).unwrap_or(true));
        }
    }

    pub fn cycle(&mut self, d: isize) {
        let n = self.views.len() as isize;
        self.active = ((self.active as isize + d).rem_euclid(n)) as usize;
        self.views[self.active].unread = false;
        self.scroll = 0;
    }

    /// Burn key: three Ctrl-X within 1.5 s. Returns true when it fires.
    pub fn panic_press(&mut self) -> bool {
        let t = Instant::now();
        self.panic_presses
            .retain(|p| t.duration_since(*p).as_millis() < 1500);
        self.panic_presses.push(t);
        self.panic_presses.len() >= 3
    }

    pub fn submit(&mut self) {
        let line = std::mem::take(&mut self.input);
        let line = line.trim();
        self.hist_pos = None;
        if line.is_empty() {
            return;
        }
        // Never store a lock passphrase in the history, even in RAM.
        if !line.starts_with("/lock") && self.history.last().map(|h| h != line).unwrap_or(true) {
            self.history.push(line.to_string());
            if self.history.len() > 100 {
                self.history.remove(0);
            }
        }
        if let Some(cmd) = line.strip_prefix('/') {
            self.command(cmd);
        } else {
            let v = self.view();
            if v.kind == ViewKind::Home {
                self.here_notice(
                    "To send messages, open a union or direct message with /union, /join or /dm. Type /help for a list of commands.",
                );
            } else {
                self.outbox
                    .push(Action::Say(v.id, SAY_TEXT, line.to_string()));
            }
        }
    }

    fn command(&mut self, cmd: &str) {
        let (name, arg) = match cmd.split_once(' ') {
            Some((a, b)) => (a, b.trim()),
            None => (cmd, ""),
        };
        let arg_opt = (!arg.is_empty()).then(|| arg.to_string());
        let vid = self.view().id;
        let kind = self.view().kind;
        let need = |app: &mut App, k: ViewKind| {
            if kind != k && !(k == ViewKind::Dm && kind == ViewKind::Union) {
                app.here_notice("This command is only available in a union.");
                false
            } else {
                true
            }
        };
        match name {
            "mask" => self.outbox.push(Action::NewMask),
            "masks" => match arg.parse::<usize>() {
                Ok(n) if n >= 1 && n <= self.masks.len() => {
                    self.outbox.push(Action::SwitchMask(n - 1))
                }
                _ => {
                    let list: Vec<String> = self
                        .masks
                        .iter()
                        .enumerate()
                        .map(|(i, m)| {
                            let mark = if i == self.active_mask { "▸" } else { " " };
                            format!("{mark} {} {} {}", i + 1, m.who.glyph(), m.who.name())
                        })
                        .collect();
                    for l in list {
                        self.here_notice(l);
                    }
                }
            },
            "union" => self.outbox.push(Action::NewUnion {
                passphrase: arg_opt,
            }),
            "join" if !arg.is_empty() => self.outbox.push(Action::Join(arg.to_string())),
            "leave" => {
                if kind == ViewKind::Home {
                    self.here_notice("There is no union or direct message to leave.");
                } else {
                    self.outbox.push(Action::Leave(vid));
                }
            }
            "dm" if !arg.is_empty() => self.outbox.push(Action::Dm(arg.to_string())),
            "card" => self.outbox.push(Action::Show(vid, Item::Card)),
            "copy" => match arg {
                "" | "card" => self.outbox.push(Action::Copy(vid, Item::Card)),
                "invite" => {
                    if need(self, ViewKind::Union) {
                        self.outbox.push(Action::Copy(vid, Item::Invite))
                    }
                }
                _ => self.here_notice("Usage: /copy card, or /copy invite in a union."),
            },
            "verify" => self.outbox.push(Action::Verify(vid, arg_opt)),
            "ttl" => match parse_duration(arg) {
                Some(s) if kind != ViewKind::Home => self.outbox.push(Action::Ttl(vid, s)),
                _ => self.here_notice(
                    "Usage: /ttl <duration> from 10s to 7d, for example /ttl 30m. Use it in a union or direct message.",
                ),
            },
            "renew" => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Renew(vid))
                }
            }
            "drop" if !arg.is_empty() => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Drop(vid, arg.to_string()))
                }
            }
            "mute" if !arg.is_empty() => {
                let target = self
                    .view()
                    .lines
                    .iter()
                    .filter_map(|l| l.from)
                    .find(|w| w.name() == arg);
                match target {
                    Some(w) => {
                        let v = &mut self.views[self.active];
                        if !v.muted.remove(&w) {
                            v.muted.insert(w);
                            v.lines.retain(|l| l.from != Some(w));
                            self.here_notice(format!(
                                "Messages from {arg} are hidden on your screen. Type /mute {arg} again to show them."
                            ));
                        } else {
                            self.here_notice(format!("Messages from {arg} are shown again."));
                        }
                    }
                    None => self.here_notice("No one with that name has sent a message here."),
                }
            }
            "cover" => match arg {
                "on" => self.outbox.push(Action::Cover(true)),
                "off" => self.outbox.push(Action::Cover(false)),
                _ => self.outbox.push(Action::Cover(!self.cover)),
            },
            "export" => self.outbox.push(Action::Export(arg_opt)),
            "me" | "once" if !arg.is_empty() && kind != ViewKind::Home => {
                let k = if name == "me" { SAY_ACTION } else { SAY_ONCE };
                self.outbox.push(Action::Say(vid, k, arg.to_string()))
            }
            "unsay" if kind != ViewKind::Home => self.outbox.push(Action::Unsay(vid)),
            "trust" => self.outbox.push(Action::Trust(vid, arg_opt)),
            "who" => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Who(vid))
                }
            }
            "invite" => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Show(vid, Item::Invite))
                }
            }
            "veil" => match arg {
                "" => {
                    self.veiled = !self.veiled;
                }
                "off" => {
                    self.veil_idle = None;
                    self.here_notice("Automatic screen hiding is off.");
                }
                d => match parse_duration(d) {
                    Some(s) => {
                        self.veil_idle = Some(s);
                        self.here_notice(format!(
                            "The screen will be hidden after {} without input.",
                            fmt_duration(s)
                        ));
                    }
                    None => self.here_notice(
                        "Usage: /veil to hide the screen now, /veil <duration> to hide it when idle, or /veil off.",
                    ),
                },
            },
            "lock" => {
                if !arg.is_empty() {
                    self.here_notice("Setting up the screen lock. This can take a moment.");
                    self.lock = Lock::new(arg);
                } else if let Some(l) = self.lock.as_mut() {
                    l.engaged = true;
                    l.fails = 0;
                } else {
                    self.here_notice("Usage: /lock <passphrase>. A passphrase is required the first time.");
                }
                self.lock_input.clear();
            }
            "deadman" => match arg {
                "off" => {
                    self.deadman = None;
                    self.here_notice("Auto-burn is off.");
                }
                d => match parse_duration(d) {
                    Some(s) if s >= 60 => {
                        self.deadman = Some(s);
                        self.here_notice(format!(
                            "Auto-burn is on. If no key is pressed for {}, all data is deleted and EIGENHEIT exits.",
                            fmt_duration(s)
                        ));
                    }
                    _ => self.here_notice("Usage: /deadman <duration> from 1m to 7d, or /deadman off."),
                },
            },
            "keep" => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Keep(vid))
                }
            }
            "import" if !arg.is_empty() => self.outbox.push(Action::Import(arg.to_string())),
            "burn" => self.outbox.push(Action::Burn),
            "help" => {
                self.help_scroll = 0;
                self.mode = Mode::Help;
            }
            "quit" | "exit" => self.outbox.push(Action::Quit),
            _ => self.here_notice(format!(
                "Unknown command or missing argument: /{name}. Type /help for a list of commands."
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("1h"), Some(3600));
        assert_eq!(parse_duration("2d"), Some(172800));
        assert_eq!(parse_duration("8d"), None);
        assert_eq!(parse_duration("x"), None);
        assert_eq!(fmt_duration(3 * 3600 + 41 * 60 + 12), "03:41:12");
    }

    #[test]
    fn panic_key_needs_three() {
        let mut a = App::new(false);
        assert!(!a.panic_press());
        assert!(!a.panic_press());
        assert!(a.panic_press());
    }

    fn press(a: &mut App, code: KeyCode) {
        a.key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn veil_swallows_the_unveiling_key() {
        let mut a = App::new(false);
        a.mode = Mode::Normal;
        a.veiled = true;
        press(&mut a, KeyCode::Char('x'));
        assert!(!a.veiled);
        assert!(a.input.is_empty(), "no input while the screen is hidden");
        a.key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
        assert!(a.veiled);
    }

    #[test]
    fn lock_opens_with_passphrase_and_burns_after_five() {
        let mut a = App::new(false);
        a.mode = Mode::Normal;
        a.input = "/lock hunter2".into();
        a.submit();
        assert!(a.is_locked());
        assert!(
            a.history.is_empty(),
            "lock passphrase is not stored in the history"
        );
        for c in "hunter2".chars() {
            press(&mut a, KeyCode::Char(c));
        }
        press(&mut a, KeyCode::Enter);
        assert!(!a.is_locked());
        a.input = "/lock".into();
        a.submit();
        assert!(a.is_locked());
        for _ in 0..5 {
            press(&mut a, KeyCode::Char('n'));
            press(&mut a, KeyCode::Enter);
        }
        assert!(matches!(a.outbox.last(), Some(Action::Burn)));
    }

    #[test]
    fn history_and_unsay_and_once() {
        let mut a = App::new(false);
        a.mode = Mode::Normal;
        let v = View::new(9, ViewKind::Dm, "x".into(), 0);
        a.add_view(v);
        a.focus(9);
        for t in ["one", "two"] {
            a.input = t.into();
            a.submit();
        }
        press(&mut a, KeyCode::Up);
        assert_eq!(a.input, "two");
        press(&mut a, KeyCode::Up);
        assert_eq!(a.input, "one");
        press(&mut a, KeyCode::Down);
        assert_eq!(a.input, "two");
        let w = eigen_core::identity::Mask::generate().who();
        a.receive(9, w, SAY_TEXT, [1; 8], "keep".into(), 60, false);
        a.receive(9, w, SAY_ONCE, [2; 8], "fleeting".into(), 3600, false);
        a.receive(9, w, SAY_UNSAY, [1; 8], String::new(), 60, false);
        let v = a.views.iter().find(|v| v.id == 9).unwrap();
        assert!(!v.lines.iter().any(|l| l.text == "keep"), "taken back");
        a.expire();
        let once = a
            .views
            .iter()
            .find(|v| v.id == 9)
            .unwrap()
            .lines
            .iter()
            .find(|l| l.once)
            .unwrap();
        assert!(
            once.expires.unwrap() <= now() + ONCE_SECS,
            "a /once message expires soon after it is displayed"
        );
    }

    #[test]
    fn show_screen_copies_and_closes() {
        let mut a = App::new(false);
        a.mode = Mode::Normal;
        a.input = "/card".into();
        a.submit();
        assert!(matches!(a.outbox.pop(), Some(Action::Show(0, Item::Card))));
        a.input = "/copy".into();
        a.submit();
        assert!(matches!(a.outbox.pop(), Some(Action::Copy(0, Item::Card))));
        a.show("Contact card", "eigen://mask/abc".into());
        assert_eq!(a.mode, Mode::Show);
        press(&mut a, KeyCode::Char('c'));
        assert_eq!(
            a.clip_out.as_deref().map(|s| s.as_str()),
            Some("eigen://mask/abc")
        );
        assert!(a.shown.as_ref().unwrap().copied);
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.shown.is_none());
    }

    #[test]
    fn deadman_burns_when_idle() {
        let mut a = App::new(false);
        a.deadman = Some(0);
        a.idle_check();
        assert!(matches!(a.outbox.last(), Some(Action::Burn)));
    }

    #[test]
    fn commands_emit_actions() {
        let mut a = App::new(false);
        a.input = "/burn".into();
        a.submit();
        assert!(matches!(a.outbox.pop(), Some(Action::Burn)));
        a.input = "/union".into();
        a.submit();
        assert!(matches!(
            a.outbox.pop(),
            Some(Action::NewUnion { passphrase: None })
        ));
    }
}
