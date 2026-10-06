//! Rendering. Monochrome base, one accent, box-drawing, no emoji.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{fmt_duration, App, LineKind, Mode, TorState, ViewKind, HELP};
use eigen_core::identity::Who;
use eigen_core::now;

const ACCENT: Color = Color::Indexed(160);
const DIM: Color = Color::Indexed(243);
const BASE: Color = Color::Indexed(250);
const KEY_PALETTE: [u8; 14] = [
    109, 110, 138, 144, 146, 151, 174, 180, 181, 182, 187, 152, 139, 108,
];

pub const SIGIL: &[&str] = &[
    "┌───────────┐",
    "│ ╲       ╱ │",
    "│   ╲   ╱   │",
    "│     ◆     │",
    "│   ╱   ╲   │",
    "│ ╱       ╲ │",
    "└───────────┘",
];
pub const MOTTO: &str = "The one who owns nothing is owned by everything.";
pub const TAGLINE: &str = "Mine. Not yours. Not theirs.";

struct Pal {
    color: bool,
}

impl Pal {
    fn s(&self, c: Color) -> Style {
        if self.color {
            Style::default().fg(c)
        } else {
            Style::default()
        }
    }
    fn accent(&self) -> Style {
        if self.color {
            Style::default().fg(ACCENT)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }
    fn dim(&self) -> Style {
        if self.color {
            Style::default().fg(DIM)
        } else {
            Style::default()
        }
    }
    fn key(&self, w: &Who) -> Style {
        self.s(Color::Indexed(
            KEY_PALETTE[w.color() as usize % KEY_PALETTE.len()],
        ))
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let p = Pal { color: app.color };
    let area = f.area();
    match app.mode {
        Mode::Boot(_) => return boot(f, area, &p),
        Mode::Burning(n) => return burn(f, area, n, &p),
        _ => {}
    }
    if app.is_locked() {
        return locked(f, area, app, &p);
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area);
    status(f, rows[0], app, &p);
    let side_w = if area.width >= 100 { 28 } else { 22 };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(side_w), Constraint::Min(20)])
        .split(rows[1]);
    strip(f, cols[0], app, &p);
    stream(f, cols[1], app, &p);
    input(f, rows[2], app, &p);
    if app.mode == Mode::Help {
        help(f, area, &p);
    }
}

fn status(f: &mut Frame, r: Rect, app: &App, p: &Pal) {
    let sep = Span::styled(" · ", p.dim());
    let mut parts: Vec<Vec<Span>> = Vec::new();
    match app.me() {
        Some(w) => parts.push(vec![
            Span::styled("I am ", p.dim()),
            Span::styled(format!("{} ", w.glyph()), p.key(&w)),
            Span::styled(w.name(), p.s(BASE).add_modifier(Modifier::BOLD)),
        ]),
        None => parts.push(vec![Span::styled("I am nobody yet", p.dim())]),
    }
    parts.push(vec![Span::styled(
        format!("mask {}/{}", app.active_mask + 1, app.masks.len()),
        p.s(BASE),
    )]);
    let (tor_s, tor_style) = match app.tor {
        TorState::Up => (format!("{} ●", app.transport), p.s(BASE)),
        TorState::Connecting => (format!("{} ◌", app.transport), p.dim()),
        TorState::Off => ("offline ○".to_string(), p.dim()),
        TorState::ClearNet => (format!("{} ●", app.transport), p.accent()),
    };
    parts.push(vec![Span::styled(tor_s, tor_style)]);
    parts.push(vec![Span::styled(
        if app.cover { "cover ON" } else { "cover off" },
        p.s(BASE),
    )]);
    let v = app.view();
    let mut union_at = usize::MAX;
    if let (ViewKind::Union, Some(end)) = (v.kind, v.ends_at) {
        union_at = parts.len();
        let left = end.saturating_sub(now());
        let st = if left <= 60 {
            p.accent().add_modifier(Modifier::BOLD)
        } else {
            p.s(BASE)
        };
        parts.push(vec![Span::styled(
            format!("union ends {}", fmt_duration(left)),
            st,
        )]);
    } else if v.kind == ViewKind::Dm {
        parts.push(vec![Span::styled(
            format!("words live {}", fmt_duration(v.ttl)),
            p.s(BASE),
        )]);
    }
    if let Some(d) = app.deadman {
        let left = d.saturating_sub(app.last_key.elapsed().as_secs());
        parts.push(vec![Span::styled(
            format!("deadman {}", fmt_duration(left)),
            p.accent(),
        )]);
    }
    if app.veiled {
        parts.push(vec![Span::styled("veiled", p.accent())]);
    }
    if !app.locked {
        parts.push(vec![Span::styled("swap: exposed", p.dim())]);
    }
    parts.push(vec![Span::styled(
        if app.vault { "vault" } else { "ram-only" },
        p.dim(),
    )]);
    // Fit to width by priority (identity and the union countdown always stay),
    // then render in the original order.
    let prio = |i: usize, n: usize| -> usize {
        match i {
            0 => 0,
            _ if i == union_at => 1,
            1 => 2,
            2 => 3,
            _ => 4 + n - i,
        }
    };
    let n = parts.len();
    let widths: Vec<usize> = parts
        .iter()
        .map(|p| p.iter().map(|s| s.content.chars().count()).sum::<usize>() + 3)
        .collect();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|i| prio(*i, n));
    let mut keep = vec![false; n];
    let mut used = 0usize;
    for i in order {
        if used + widths[i] <= r.width as usize + 3 {
            keep[i] = true;
            used += widths[i];
        }
    }
    let mut spans: Vec<Span> = Vec::new();
    for (_, part) in parts.into_iter().enumerate().filter(|(i, _)| keep[*i]) {
        if !spans.is_empty() {
            spans.push(sep.clone());
        }
        spans.extend(part);
    }
    f.render_widget(Paragraph::new(TLine::from(spans)), r);
}

fn strip(f: &mut Frame, r: Rect, app: &App, p: &Pal) {
    let mut lines: Vec<TLine> = Vec::new();
    let w = r.width.saturating_sub(2) as usize;
    lines.push(TLine::from(Span::styled("masks", p.dim())));
    for (i, m) in app.masks.iter().enumerate() {
        let mark = if i == app.active_mask { "▸" } else { " " };
        lines.push(TLine::from(vec![
            Span::styled(mark, p.accent()),
            Span::styled(format!("{} ", m.who.glyph()), p.key(&m.who)),
            Span::styled(
                if app.veiled {
                    VEIL.to_string()
                } else {
                    trunc(&m.who.name(), w.saturating_sub(3))
                },
                p.s(BASE),
            ),
        ]));
    }
    for (kind, label) in [(ViewKind::Union, "unions"), (ViewKind::Dm, "dms")] {
        lines.push(TLine::from(""));
        lines.push(TLine::from(Span::styled(label, p.dim())));
        for (i, v) in app.views.iter().enumerate().filter(|(_, v)| v.kind == kind) {
            let active = i == app.active;
            let glyph = v.who.map(|w| w.glyph()).unwrap_or('·');
            let gs = v.who.map(|w| p.key(&w)).unwrap_or(p.dim());
            let mark = if active {
                "▸"
            } else if v.unread {
                "•"
            } else {
                " "
            };
            let mut ts = if active {
                p.s(BASE).add_modifier(Modifier::BOLD)
            } else {
                p.s(BASE)
            };
            let mut tail = String::new();
            if let Some(end) = v.ends_at {
                let left = end.saturating_sub(now());
                tail = format!(" {:02}:{:02}", left / 3600, left / 60 % 60);
                if left <= 60 {
                    ts = p.accent();
                }
            }
            let mut title = trunc(&v.title, w.saturating_sub(3 + tail.len()));
            if app.veiled {
                title = VEIL.to_string();
            } else if v.kind == ViewKind::Dm && v.who.is_some_and(|w| app.trusted.contains(&w)) {
                title = trunc(&format!("{} ✓", v.title), w.saturating_sub(3 + tail.len()));
            }
            lines.push(TLine::from(vec![
                Span::styled(mark, p.accent()),
                Span::styled(format!("{glyph} "), gs),
                Span::styled(title, ts),
                Span::styled(tail, p.dim()),
            ]));
        }
    }
    let home = app.active == 0;
    lines.push(TLine::from(""));
    lines.push(TLine::from(vec![
        Span::styled(if home { "▸" } else { " " }, p.accent()),
        Span::styled("◌ ", p.dim()),
        Span::styled(
            "alone",
            if home {
                p.s(BASE).add_modifier(Modifier::BOLD)
            } else {
                p.dim()
            },
        ),
    ]));
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(p.dim());
    f.render_widget(Paragraph::new(lines).block(block), r);
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut out = Vec::new();
    for raw in text.split('\n') {
        let mut cur = String::new();
        for word in raw.split(' ') {
            let wl = word.chars().count();
            let cl = cur.chars().count();
            if cl > 0 && cl + 1 + wl > width {
                out.push(std::mem::take(&mut cur));
            }
            if wl > width {
                for ch in word.chars() {
                    if cur.chars().count() >= width {
                        out.push(std::mem::take(&mut cur));
                    }
                    cur.push(ch);
                }
            } else {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(word);
            }
        }
        out.push(cur);
    }
    out
}

fn stream(f: &mut Frame, r: Rect, app: &App, p: &Pal) {
    let v = app.view();
    let mut title = vec![Span::styled(" ", p.dim())];
    if let Some(w) = v.who {
        title.push(Span::styled(format!("{} ", w.glyph()), p.key(&w)));
    }
    title.push(Span::styled(
        if app.veiled {
            format!("{VEIL} ")
        } else {
            format!("{} ", v.title)
        },
        p.s(BASE).add_modifier(Modifier::BOLD),
    ));
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(p.dim())
        .title(TLine::from(title));
    let inner = block.inner(r);
    f.render_widget(block, r);
    let inner = Rect {
        x: inner.x + 1,
        width: inner.width.saturating_sub(1),
        ..inner
    };
    let width = inner.width as usize;
    let mut out: Vec<TLine> = Vec::new();
    for l in &v.lines {
        match l.kind {
            LineKind::Notice | LineKind::Warn => {
                let (mark, st) = if l.kind == LineKind::Warn {
                    ("! ", p.accent().add_modifier(Modifier::BOLD))
                } else {
                    ("─ ", p.dim())
                };
                let text = if app.veiled {
                    VEIL.to_string()
                } else {
                    l.text.clone()
                };
                for (i, chunk) in wrap(&text, width.saturating_sub(2)).into_iter().enumerate() {
                    out.push(TLine::from(vec![
                        Span::styled(if i == 0 { mark } else { "  " }, st),
                        Span::styled(chunk, st),
                    ]));
                }
            }
            LineKind::Msg | LineKind::Mine => {
                let who = l.from.unwrap_or(Who([0; 32]));
                let name = if app.veiled {
                    VEIL.to_string()
                } else if app.trusted.contains(&who) {
                    format!("{} ✓", who.name())
                } else {
                    who.name()
                };
                let mut ns = p.key(&who);
                if l.kind == LineKind::Mine {
                    ns = ns.add_modifier(Modifier::BOLD);
                }
                let mut bs = p.s(BASE);
                if l.action {
                    bs = bs.add_modifier(Modifier::ITALIC);
                }
                let body = if app.veiled {
                    "░░░░░░░░░░░░".to_string()
                } else if l.action {
                    format!("⁎ {}", l.text)
                } else if l.once {
                    format!("◌ {}", l.text)
                } else {
                    l.text.clone()
                };
                let head = name.chars().count() + 5;
                let body_w = width.saturating_sub(head);
                let narrow = body_w < 24;
                let chunks = wrap(
                    &body,
                    if narrow {
                        width.saturating_sub(2)
                    } else {
                        body_w
                    },
                );
                let mut first = vec![
                    Span::styled(format!("{} ", who.glyph()), ns),
                    Span::styled(name, ns),
                ];
                if narrow {
                    out.push(TLine::from(first));
                    for c in chunks {
                        out.push(TLine::from(vec![
                            Span::styled("  ", p.dim()),
                            Span::styled(c, bs),
                        ]));
                    }
                } else {
                    for (i, c) in chunks.into_iter().enumerate() {
                        if i == 0 {
                            first.push(Span::styled(" │ ", p.dim()));
                            first.push(Span::styled(c, bs));
                            out.push(TLine::from(std::mem::take(&mut first)));
                        } else {
                            out.push(TLine::from(vec![
                                Span::raw(" ".repeat(head - 3)),
                                Span::styled(" │ ", p.dim()),
                                Span::styled(c, bs),
                            ]));
                        }
                    }
                }
            }
        }
    }
    let h = inner.height as usize;
    let end = out
        .len()
        .saturating_sub(app.scroll.min(out.len().saturating_sub(h)));
    let start = end.saturating_sub(h);
    let shown: Vec<TLine> = out.drain(start..end).collect();
    f.render_widget(Paragraph::new(shown), inner);
}

fn input(f: &mut Frame, r: Rect, app: &App, p: &Pal) {
    let v = app.view();
    let pulse = v.kind == ViewKind::Union
        && v.ends_at
            .map(|e| e.saturating_sub(now()) <= 60)
            .unwrap_or(false)
        && !v.renewed;
    let prompt = if pulse { "renew? › " } else { "› " };
    let prompt_style = if pulse && now().is_multiple_of(2) {
        p.accent().add_modifier(Modifier::REVERSED)
    } else {
        p.accent()
    };
    let avail = (r.width as usize).saturating_sub(prompt.chars().count() + 1);
    let n = app.input.chars().count();
    let shown: String = app.input.chars().skip(n.saturating_sub(avail)).collect();
    let shown = if app.veiled { String::new() } else { shown };
    let line = if app.input.is_empty() && v.kind == ViewKind::Home {
        TLine::from(vec![
            Span::styled(prompt, prompt_style),
            Span::styled("/help · /union · /join · /dm", p.dim()),
        ])
    } else {
        TLine::from(vec![
            Span::styled(prompt, prompt_style),
            Span::styled(shown.clone(), p.s(BASE)),
        ])
    };
    let row = Rect {
        y: r.y + 1,
        height: 1,
        ..r
    };
    f.render_widget(Paragraph::new(line), row);
    let cx = r.x + (prompt.chars().count() + shown.chars().count()) as u16;
    f.set_cursor_position(Position {
        x: cx.min(r.x + r.width.saturating_sub(1)),
        y: row.y,
    });
}

fn help(f: &mut Frame, area: Rect, p: &Pal) {
    let w = area.width.min(76);
    let h = (HELP.len() as u16 + 4).min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(p.dim())
        .title(Span::styled(" what is mine to do ", p.accent()));
    let key_w = HELP
        .iter()
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(10)
        .min(26);
    let lines: Vec<TLine> = HELP
        .iter()
        .map(|(k, d)| {
            TLine::from(vec![
                Span::styled(
                    format!(" {:<key_w$} ", trunc(k, key_w)),
                    p.s(BASE).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*d, p.dim()),
            ])
        })
        .chain(std::iter::once(TLine::from(Span::styled(
            " Esc to return",
            p.dim(),
        ))))
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), r);
}

const VEIL: &str = "░░░░░░";

fn locked(f: &mut Frame, area: Rect, app: &App, p: &Pal) {
    let mut lines: Vec<TLine> = Vec::new();
    let top = area.height.saturating_sub(SIGIL.len() as u16 + 6) / 2;
    for _ in 0..top {
        lines.push(TLine::from(""));
    }
    for s in SIGIL {
        lines.push(TLine::from(Span::styled(*s, p.dim())).centered());
    }
    lines.push(TLine::from(""));
    lines.push(
        TLine::from(Span::styled(
            "locked.",
            p.s(BASE).add_modifier(Modifier::BOLD),
        ))
        .centered(),
    );
    let fails = app.lock.as_ref().map(|l| l.fails).unwrap_or(0);
    let note = if fails == 0 {
        "my passphrase, then Enter. wrong too often and everything burns.".to_string()
    } else {
        format!(
            "does not open. {} tries before everything burns.",
            5u8.saturating_sub(fails)
        )
    };
    lines.push(
        TLine::from(Span::styled(
            note,
            if fails > 0 { p.accent() } else { p.dim() },
        ))
        .centered(),
    );
    // No echo, not even the length.
    lines.push(TLine::from(Span::styled("›", p.accent())).centered());
    f.render_widget(Paragraph::new(lines), area);
}

fn boot(f: &mut Frame, area: Rect, p: &Pal) {
    let mut lines: Vec<TLine> = Vec::new();
    let top = area.height.saturating_sub(SIGIL.len() as u16 + 5) / 2;
    for _ in 0..top {
        lines.push(TLine::from(""));
    }
    for s in SIGIL {
        lines.push(TLine::from(Span::styled(*s, p.accent())).centered());
    }
    lines.push(TLine::from(""));
    lines.push(
        TLine::from(Span::styled(
            "E I G E N H E I T",
            p.s(BASE).add_modifier(Modifier::BOLD),
        ))
        .centered(),
    );
    lines.push(TLine::from(""));
    lines.push(TLine::from(Span::styled(MOTTO, p.dim())).centered());
    f.render_widget(Paragraph::new(lines), area);
}

/// The screen decays to noise, then to nothing.
pub const BURN_FRAMES: u16 = 18;

fn burn(f: &mut Frame, area: Rect, n: u16, p: &Pal) {
    let density = 1.0 - (n as f32 / BURN_FRAMES as f32);
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15 ^ (n as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
    let noise = ['░', '▒', '▓', '·', ':', '█', ' '];
    let mut lines = Vec::with_capacity(area.height as usize);
    for _ in 0..area.height {
        let mut s = String::with_capacity(area.width as usize);
        for _ in 0..area.width {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let roll = (seed % 1000) as f32 / 1000.0;
            s.push(if roll < density * density {
                noise[(seed >> 20) as usize % noise.len()]
            } else {
                ' '
            });
        }
        lines.push(TLine::from(Span::styled(s, p.dim())));
    }
    f.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{MaskInfo, View};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        buf.content.iter().map(|c| c.symbol()).collect::<String>()
    }

    #[test]
    fn layout_fits_80x24() {
        let mut app = App::new(false);
        app.mode = Mode::Normal;
        let m = eigen_core::identity::Mask::generate();
        app.masks.push(MaskInfo { who: m.who() });
        let mut v = View::new(5, ViewKind::Union, "union test".into(), 0);
        v.ends_at = Some(now() + 3600);
        app.add_view(v);
        app.active = 1;
        app.notice(5, "a long notice ".repeat(20));
        let s = render(&app, 80, 24);
        assert!(s.contains("I am"));
        assert!(s.contains("union ends"));
    }

    #[test]
    fn wrap_respects_width() {
        for l in wrap(&"word ".repeat(50), 17) {
            assert!(l.chars().count() <= 17);
        }
    }
}

#[cfg(test)]
mod snapshot {
    use super::*;
    use crate::app::{Line, MaskInfo, View};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// `cargo test -p eigen-tui snapshot -- --ignored --nocapture` prints the 80x24 layout.
    #[test]
    #[ignore]
    fn print_80x24() {
        let mut app = App::new(false);
        app.mode = Mode::Normal;
        app.tor = TorState::Up;
        let ms: Vec<_> = (0..4)
            .map(|_| eigen_core::identity::Mask::generate().who())
            .collect();
        app.masks.push(MaskInfo { who: ms[0] });
        app.masks.push(MaskInfo { who: ms[3] });
        let mut v = View::new(5, ViewKind::Union, "union ochre-heron".into(), 0);
        v.who = Some(ms[1]);
        v.ends_at = Some(now() + 13272);
        app.add_view(v);
        let mut d = View::new(6, ViewKind::Dm, ms[2].name(), 0);
        d.who = Some(ms[2]);
        app.add_view(d);
        app.active = 1;
        app.notice(5, "the union holds 3. it dissolves unless renewed.");
        for (w, t) in [
            (ms[1], "no names here, only keys."),
            (
                ms[0],
                "the relay holds nothing but expiring noise, and that is the point of it all.",
            ),
            (ms[2], "renew at dusk."),
        ] {
            app.push(
                5,
                Line {
                    from: Some(w),
                    text: t.into(),
                    kind: LineKind::Msg,
                    at: 0,
                    expires: None,
                    ..Default::default()
                },
            );
        }
        app.input = "mine, not yours".into();
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        for y in 0..24 {
            let row: String = (0..80).map(|x| buf[(x, y)].symbol().to_string()).collect();
            println!("{row}");
        }
    }
}
