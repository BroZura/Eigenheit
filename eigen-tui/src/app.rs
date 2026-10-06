//! UI state and command interpretation. Protocol work happens in the engine;
//! the app only records what I see and emits [`Action`]s.
use std::collections::HashSet;
use std::time::Instant;

use eigen_core::identity::Who;
use eigen_core::now;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineKind {
    Msg,
    Mine,
    Notice,
    Warn,
}

#[derive(Clone, Debug)]
pub struct Line {
    pub from: Option<Who>,
    pub text: String,
    pub kind: LineKind,
    pub at: u64,
    pub expires: Option<u64>,
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
    NewUnion { passphrase: Option<String> },
    Join(String),
    Leave(u64),
    Dm(String),
    Say(u64, String),
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
pub enum Mode {
    Boot(u16),
    Normal,
    Help,
    Burning(u16),
}

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
    pub cover: bool,
    pub locked: bool,
    pub vault: bool,
    pub color: bool,
    pub outbox: Vec<Action>,
    pub quit: bool,
    panic_presses: Vec<Instant>,
    next_id: u64,
}

pub const HELP: &[(&str, &str)] = &[
    ("/mask", "put on a fresh mask (Ctrl-M where supported)"),
    ("/masks [n]", "list my masks, or wear mask n"),
    (
        "/union [passphrase]",
        "form a union; prints its invite (Ctrl-U)",
    ),
    ("/join <invite|passphrase>", "enter a union"),
    (
        "/leave",
        "leave this union or dm, instantly, without a trace",
    ),
    ("/dm <card>", "open a dm with a mask's card"),
    ("/card", "show the card of the mask I wear"),
    ("/verify [name]", "fingerprint + SAS to compare out of band"),
    ("/ttl <30m|1h|2d>", "how long my words live here"),
    ("/renew", "I stay for the next term of this union"),
    ("/drop <name>", "vote to rotate keys away from someone"),
    ("/mute <name>", "my screen, my rules: hide someone locally"),
    ("/cover on|off", "constant-rate cover traffic"),
    ("/keep", "remember this union in my vault (toggle)"),
    ("/export [path]", "my PGP public key (screen, or file)"),
    ("/import <path|card>", "pin someone's PGP key or card"),
    ("/burn", "destroy everything and exit (Ctrl-X x3)"),
    ("/help", "this (F1)"),
    ("Tab / Shift-Tab", "next / previous union or dm"),
    ("PgUp / PgDn", "scroll"),
    ("Ctrl-L", "redraw"),
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
        let mut home = View::new(0, ViewKind::Home, "me".into(), 0);
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
            cover: false,
            locked: false,
            vault: false,
            color,
            outbox: Vec::new(),
            quit: false,
            panic_presses: Vec::new(),
            next_id: 1,
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
            },
        );
    }

    pub fn here_notice(&mut self, text: impl Into<String>) {
        let id = self.view().id;
        self.notice(id, text);
    }

    /// Drop expired lines everywhere (disappearing messages).
    pub fn expire(&mut self) {
        let t = now();
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

    /// Panic key: three Ctrl-X within 1.5 s. Returns true when it fires.
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
        if line.is_empty() {
            return;
        }
        if let Some(cmd) = line.strip_prefix('/') {
            self.command(cmd);
        } else {
            let v = self.view();
            if v.kind == ViewKind::Home {
                self.here_notice(
                    "I speak in a union or a dm. /union, /join, /dm — /help for more.",
                );
            } else {
                self.outbox.push(Action::Say(v.id, line.to_string()));
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
                app.here_notice("not here.");
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
                    self.here_notice("I am already alone here.");
                } else {
                    self.outbox.push(Action::Leave(vid));
                }
            }
            "dm" if !arg.is_empty() => self.outbox.push(Action::Dm(arg.to_string())),
            "card" => self.outbox.push(Action::Export(Some("card".into()))),
            "verify" => self.outbox.push(Action::Verify(vid, arg_opt)),
            "ttl" => match parse_duration(arg) {
                Some(s) if kind != ViewKind::Home => self.outbox.push(Action::Ttl(vid, s)),
                _ => self.here_notice("/ttl <10s..7d>, e.g. /ttl 30m — in a union or dm"),
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
                                "{arg} is silent on my screen. /mute again to hear."
                            ));
                        } else {
                            self.here_notice(format!("{arg} is audible again."));
                        }
                    }
                    None => self.here_notice("nobody by that name spoke here."),
                }
            }
            "cover" => match arg {
                "on" => self.outbox.push(Action::Cover(true)),
                "off" => self.outbox.push(Action::Cover(false)),
                _ => self.outbox.push(Action::Cover(!self.cover)),
            },
            "export" => self.outbox.push(Action::Export(arg_opt)),
            "keep" => {
                if need(self, ViewKind::Union) {
                    self.outbox.push(Action::Keep(vid))
                }
            }
            "import" if !arg.is_empty() => self.outbox.push(Action::Import(arg.to_string())),
            "burn" => self.outbox.push(Action::Burn),
            "help" => self.mode = Mode::Help,
            "quit" | "exit" => self.outbox.push(Action::Quit),
            _ => self.here_notice(format!("/{name}? — /help")),
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
