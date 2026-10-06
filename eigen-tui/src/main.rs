#![deny(unsafe_code)]
use std::io::{stdout, Write};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{event::KeyboardEnhancementFlags, execute};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use eigen_core::identity::Mask;
use eigen_tui::app::{Action, App, MaskInfo, Mode, View, ViewKind};
use eigen_tui::{harden, ui};

struct TermGuard {
    enhanced: bool,
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let mut out = stdout();
        if self.enhanced {
            let _ = execute!(out, crossterm::event::PopKeyboardEnhancementFlags);
        }
        let _ = execute!(out, LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = disable_raw_mode();
    }
}

fn main() {
    let hard = harden::apply();
    let color = std::env::var_os("NO_COLOR").map(|v| v.is_empty()).unwrap_or(true);
    let mut app = App::new(color);
    app.locked = hard.locked;
    let mut masks = vec![Mask::generate()];
    app.masks.push(MaskInfo { who: masks[0].who() });
    if std::env::args().any(|a| a == "--mock") {
        mock(&mut app);
    }
    let burned = run(&mut app, &mut masks).unwrap_or_default();
    drop(masks);
    if burned {
        let mut out = stdout();
        let _ = out.write_all(b"\x1b[H\x1b[2J\x1b[3J");
        let _ = out.flush();
    }
}

fn mock(app: &mut App) {
    use eigen_core::identity::Who;
    let others: Vec<Who> = (0..3).map(|_| Mask::generate().who()).collect();
    let mut v = View::new(10, ViewKind::Union, "union ochre-heron-1a2b".into(), 0);
    v.who = Some(others[0]);
    v.ends_at = Some(eigen_core::now() + 3 * 3600 + 41 * 60);
    app.add_view(v);
    app.notice(10, "the union holds 3. it dissolves unless renewed.");
    for (i, t) in ["no names here, only keys.", "the relay holds nothing but expiring noise.", "agreed. renew at dusk."].iter().enumerate() {
        app.push(10, eigen_tui::app::Line { from: Some(others[i]), text: t.to_string(), kind: eigen_tui::app::LineKind::Msg, at: 0, expires: None });
    }
    let mut d = View::new(11, ViewKind::Dm, others[1].name(), 0);
    d.who = Some(others[1]);
    app.add_view(d);
    app.notice(11, "forward secret. words live 01:00:00.");
    app.active = 1;
}

fn run(app: &mut App, masks: &mut Vec<Mask>) -> std::io::Result<bool> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let enhanced = crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false)
        && execute!(out, crossterm::event::PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)).is_ok();
    let _guard = TermGuard { enhanced };
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;
    let boot_until = Instant::now() + Duration::from_millis(1400);
    loop {
        if let Mode::Boot(_) = app.mode {
            if Instant::now() >= boot_until {
                app.mode = Mode::Normal;
            }
        }
        if let Mode::Burning(n) = app.mode {
            if n >= ui::BURN_FRAMES {
                return Ok(true);
            }
            app.mode = Mode::Burning(n + 1);
        }
        app.expire();
        term.draw(|f| ui::draw(f, app))?;
        let wait = if matches!(app.mode, Mode::Burning(_)) { 45 } else { 200 };
        if event::poll(Duration::from_millis(wait))? {
            match event::read()? {
                Event::Key(k) if k.kind != KeyEventKind::Release => key(app, k),
                Event::Resize(..) => term.clear()?,
                _ => {}
            }
        }
        for a in std::mem::take(&mut app.outbox) {
            match a {
                Action::NewMask => {
                    masks.push(Mask::generate());
                    app.masks.push(MaskInfo { who: masks.last().map(|m| m.who()).unwrap_or(eigen_core::identity::Who([0; 32])) });
                    app.active_mask = masks.len() - 1;
                    app.here_notice("a fresh mask. nothing links it to the others.");
                }
                Action::SwitchMask(i) => app.active_mask = i,
                Action::Burn => {
                    masks.clear();
                    app.views.truncate(1);
                    app.mode = Mode::Burning(0);
                }
                Action::Quit => return Ok(false),
                _ => app.here_notice("not yet — no relay in M1."),
            }
        }
        if app.quit {
            return Ok(false);
        }
    }
}

fn key(app: &mut App, k: KeyEvent) {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl && k.code == KeyCode::Char('x') {
        if app.panic_press() {
            app.outbox.push(Action::Burn);
        }
        return;
    }
    match app.mode {
        Mode::Burning(_) => return,
        Mode::Boot(_) => {
            app.mode = Mode::Normal;
            return;
        }
        Mode::Help => {
            if matches!(k.code, KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q')) {
                app.mode = Mode::Normal;
            }
            return;
        }
        Mode::Normal => {}
    }
    match (k.code, ctrl) {
        (KeyCode::Char('c'), true) => app.outbox.push(Action::Quit),
        (KeyCode::Char('l'), true) => {}
        (KeyCode::Char('u'), true) => app.outbox.push(Action::NewUnion { passphrase: None }),
        (KeyCode::Char('m'), true) => app.outbox.push(Action::NewMask),
        (KeyCode::F(1), _) => app.mode = Mode::Help,
        (KeyCode::Tab, _) => app.cycle(1),
        (KeyCode::BackTab, _) => app.cycle(-1),
        (KeyCode::PageUp, _) => app.scroll += 5,
        (KeyCode::PageDown, _) => app.scroll = app.scroll.saturating_sub(5),
        (KeyCode::Enter, _) => app.submit(),
        (KeyCode::Backspace, _) => {
            app.input.pop();
        }
        (KeyCode::Esc, _) => app.input.clear(),
        (KeyCode::Char(c), false) => app.input.push(c),
        _ => {}
    }
}
