#![deny(unsafe_code)]
//! eigen — mine, not yours, not theirs.
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, KeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc;

use eigen_core::identity::Mask;
use eigen_tui::app::{Action, App, Mode};
use eigen_tui::engine::{Engine, Net, NetCfg, NetEvent};
use eigen_tui::tor::RelayAddr;
use eigen_tui::{harden, ui};

const USAGE: &str = "eigen [--relay RELAY]... [--tor-socks 127.0.0.1:9050] [--sam 127.0.0.1:7656]
      [--vpn IFACE | --wireguard IFACE] [--i-accept-the-risk]
      [--cover] [--cover-ms 500] [--delay-ms 1500] [--vault PATH] [--no-boot]

  RELAY is one of:
    x.onion:PORT          through tor (SOCKS, one circuit per mask/dm/union)
    x.b32.i2p             through i2p (SAM, one transient destination per mask/dm/union)
    IP:PORT#KEY           direct, Noise-encrypted; needs --vpn/--wireguard IFACE
                          (every direct connection is bound to IFACE and fails closed)
  Default: RAM-only. Nothing touches the disk.";

pub struct Opts {
    relays: Vec<RelayAddr>,
    socks: String,
    risk: bool,
    cover: bool,
    cover_ms: u64,
    delay_ms: u64,
    vault: Option<String>,
    boot: bool,
    sam: String,
    vpn: Option<String>,
    warnings: Vec<String>,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        relays: Vec::new(),
        socks: "127.0.0.1:9050".into(),
        risk: false,
        cover: false,
        cover_ms: 500,
        delay_ms: 1500,
        vault: None,
        boot: true,
        sam: eigen_transport::sam::DEFAULT_SAM.into(),
        vpn: None,
        warnings: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| USAGE.to_string());
        match a.as_str() {
            "--relay" => o.relays.push(
                RelayAddr::parse(&val()?)
                    .ok_or("relay must be x.onion:PORT, x.b32.i2p or IP:PORT#KEY")?,
            ),
            "--tor-socks" => o.socks = val()?,
            "--sam" => o.sam = val()?,
            "--vpn" | "--wireguard" => o.vpn = Some(val()?),
            "--i-accept-the-risk" => o.risk = true,
            "--cover" => o.cover = true,
            "--cover-ms" => o.cover_ms = val()?.parse().map_err(|_| USAGE)?,
            "--delay-ms" => o.delay_ms = val()?.parse().map_err(|_| USAGE)?,
            "--vault" => o.vault = Some(val()?),
            "--ram-only" => o.vault = None,
            "--no-boot" => o.boot = false,
            _ => return Err(USAGE.into()),
        }
    }
    o.warnings = eigen_tui::policy::admit(&o.relays, o.vpn.as_deref(), o.risk)?;
    Ok(o)
}

struct TermGuard {
    enhanced: bool,
}

/// Set once anything was copied, so the clipboard is cleared on every exit path.
static CLIP_USED: AtomicBool = AtomicBool::new(false);

/// Put text on the terminal's clipboard (OSC 52). An empty string clears it.
/// Inside tmux the sequence is passed through to the outer terminal.
fn osc52(text: &str) {
    let seq = format!(
        "\x1b]52;c;{}\x07",
        eigen_core::wire::base64(text.as_bytes())
    );
    let seq = if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;{}\x1b\\", seq.replace('\x1b', "\x1b\x1b"))
    } else {
        seq
    };
    let mut out = stdout();
    let _ = out.write_all(seq.as_bytes());
    let _ = out.flush();
    zeroize::Zeroize::zeroize(&mut seq.into_bytes());
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        if CLIP_USED.load(Ordering::Relaxed) {
            osc52("");
        }
        let mut out = stdout();
        if self.enhanced {
            let _ = execute!(out, crossterm::event::PopKeyboardEnhancementFlags);
        }
        let _ = execute!(out, LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = disable_raw_mode();
    }
}

enum Ev {
    Key(KeyEvent),
    Resize,
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            println!("{e}");
            std::process::exit(2);
        }
    };
    let hard = harden::apply();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => std::process::exit(1),
    };
    let burned = rt.block_on(run(opts, hard)).unwrap_or(false);
    rt.shutdown_timeout(Duration::from_millis(200));
    if burned {
        let mut out = stdout();
        // Clear screen and scrollback where the terminal allows it.
        let _ = out.write_all(b"\x1b[H\x1b[2J\x1b[3J\x1bc");
        let _ = out.flush();
    }
}

async fn run(opts: Opts, hard: harden::Hardening) -> std::io::Result<bool> {
    let color = std::env::var_os("NO_COLOR")
        .map(|v| v.is_empty())
        .unwrap_or(true);
    let mut app = App::new(color);
    app.locked = hard.locked;
    app.cover = opts.cover;
    if !opts.boot {
        app.mode = Mode::Normal;
    }
    let (ntx, mut nrx) = mpsc::unbounded_channel::<NetEvent>();
    let net = Net::new(NetCfg {
        socks: Some(opts.socks.clone()),
        relays: opts.relays.clone(),
        cover: Arc::new(AtomicBool::new(opts.cover)),
        cover_ms: opts.cover_ms,
        delay_ms: opts.delay_ms,
        sam: Some(opts.sam.clone()),
        device: opts.vpn.clone(),
    });
    let mut engine = Engine::new(net, ntx);
    if let Some(path) = &opts.vault {
        match open_or_create(path) {
            Ok((v, data)) => {
                engine.vault = Some(v);
                app.vault = true;
                engine.load(data, &mut app);
            }
            Err(msg) => {
                println!("{msg}");
                return Ok(false);
            }
        }
    }
    if engine.masks.is_empty() {
        let first = engine.add_mask(Mask::generate(), &mut app);
        app.active_mask = first;
    }
    engine.persist(&app);
    let me = app.masks[app.active_mask].who.name();
    app.notice(0, format!("I am {me}. generated here, known nowhere."));
    for w in &opts.warnings {
        app.warn(0, w.clone());
    }
    if opts.relays.is_empty() {
        app.notice(
            0,
            "no relays given: I can speak to nobody. start with --relay <onion>:<port>.",
        );
    }
    if app.vault {
        app.notice(0, "my vault is open: masks, pins and /keep'd unions persist. never messages. /burn destroys it.");
    } else {
        app.notice(
            0,
            "nothing is written to disk. /help for what is mine to do.",
        );
    }

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let enhanced = crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false)
        && execute!(
            out,
            crossterm::event::PushKeyboardEnhancementFlags(
                KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
            )
        )
        .is_ok();
    let _guard = TermGuard { enhanced };
    let mut term = Terminal::new(CrosstermBackend::new(stdout()))?;

    let (ktx, mut krx) = mpsc::unbounded_channel::<Ev>();
    std::thread::spawn(move || loop {
        if ktx.is_closed() {
            return;
        }
        if let Ok(true) = event::poll(Duration::from_millis(100)) {
            match event::read() {
                Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                    let _ = ktx.send(Ev::Key(k));
                }
                Ok(Event::Resize(..)) => {
                    let _ = ktx.send(Ev::Resize);
                }
                _ => {}
            }
        }
    });

    let boot_until = Instant::now() + Duration::from_millis(1600);
    let mut frame = tokio::time::interval(Duration::from_millis(200));
    let mut clip_clear_at: Option<Instant> = None;
    let mut last_tick = 0u64;
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
        term.draw(|f| ui::draw(f, &app))?;
        let burning = matches!(app.mode, Mode::Burning(_));
        tokio::select! {
            Some(ev) = krx.recv() => match ev {
                Ev::Key(k) => app.key(k),
                Ev::Resize => term.clear()?,
            },
            Some(ne) = nrx.recv(), if !burning => engine.on_net(ne, &mut app),
            _ = frame.tick() => {}
            _ = tokio::time::sleep(Duration::from_millis(45)), if burning => {}
        }
        let t = eigen_core::now();
        if t != last_tick && !burning {
            last_tick = t;
            engine.tick(&mut app);
            app.idle_check();
            app.expire();
        }
        for a in std::mem::take(&mut app.outbox) {
            match a {
                Action::Burn => {
                    // Wipe first, animate after: the burn is already done when the screen decays.
                    engine.burn();
                    app.wipe();
                    if CLIP_USED.load(Ordering::Relaxed) {
                        osc52("");
                        clip_clear_at = None;
                    }
                    app.mode = Mode::Burning(0);
                }
                Action::Quit => return Ok(false),
                other => engine.act(other, &mut app),
            }
        }
        if engine.dirty {
            engine.persist(&app);
        }
        if let Some(text) = app.clip_out.take() {
            osc52(&text);
            CLIP_USED.store(true, Ordering::Relaxed);
            clip_clear_at =
                Some(Instant::now() + Duration::from_secs(eigen_tui::app::CLIPBOARD_SECS));
        }
        if clip_clear_at.is_some_and(|d| Instant::now() >= d) {
            osc52("");
            clip_clear_at = None;
        }
    }
}

/// Read a line from the terminal without echo.
fn read_secret(prompt: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
    let mut out = stdout();
    out.write_all(prompt.as_bytes())?;
    out.flush()?;
    enable_raw_mode()?;
    let mut s = zeroize::Zeroizing::new(String::new());
    let res = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => {
                    s.pop();
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(std::io::ErrorKind::Interrupted.into())
                }
                KeyCode::Char(c) => s.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    disable_raw_mode()?;
    out.write_all(b"\r\n")?;
    res.map(|_| s)
}

fn open_or_create(
    path: &str,
) -> Result<(eigen_core::vault::Vault, eigen_core::vault::VaultData), String> {
    use eigen_core::vault::{Vault, VaultData};
    let io = |_| "aborted.".to_string();
    if std::path::Path::new(path).exists() {
        let pass = read_secret("passphrase: ").map_err(io)?;
        return Vault::open(path, &pass).map_err(|_| "does not open.".to_string());
    }
    println!("no vault at {path}. making one: a single file, indistinguishable from random bytes.");
    let p1 = read_secret("new passphrase: ").map_err(io)?;
    let p2 = read_secret("again: ").map_err(io)?;
    if *p1 != *p2 || p1.is_empty() {
        return Err("passphrases differ (or are empty). nothing written.".into());
    }
    println!("a duress passphrase opens a decoy instead (one fresh mask). it can also silently wipe the real vault.");
    let d = read_secret("duress passphrase (empty for none): ").map_err(io)?;
    let real = VaultData {
        masks: vec![Mask::generate().to_bytes()],
        ..Default::default()
    };
    let v = if d.is_empty() {
        Vault::create(path, &p1, &real, None)
    } else {
        if *d == *p1 {
            return Err("the duress passphrase must differ. nothing written.".into());
        }
        let mode =
            read_secret("on duress: [d]ecoy only, or [w]ipe the real vault? ").map_err(io)?;
        let decoy = VaultData {
            masks: vec![Mask::generate().to_bytes()],
            wipe_other: mode.trim() == "w",
            ..Default::default()
        };
        Vault::create(path, &p1, &real, Some((&d, &decoy)))
    }
    .map_err(|_| "could not write the vault.".to_string())?;
    Ok((v, real))
}
