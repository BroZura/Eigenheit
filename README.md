# EIGENHEIT

**Mine. Not yours. Not theirs.**

`eigen` is an IRC-style terminal chat (DMs and rooms) built on one idea taken from Max Stirner: *what is mine is whatever I have power over* — my identity, my keys, my words, my exits. Nobody grants them, so nobody can revoke them.

- **No accounts.** I am my key. My name (`amber-fox-3f9a`) and glyph are derived from it; nobody can choose, reserve or take a name. Masks (identities) are free and unlinkable to each other.
- **No authority.** A room is a *union*: defined by a secret, held together by agreement, and dissolving by default. No admins, no kicks, no topics. A drop vote only rotates keys.
- **No memory unless I choose it.** RAM-only by default. No history, no read receipts, no typing indicators, no presence. Messages disappear (default 1 h).
- **No server that knows anything.** Relays store fixed-size ciphertext under opaque, rotating mailbox ids, for at most 24 h, in RAM, and log nothing.
- **Exit is one keystroke.** `/leave` is instant. `/burn` (or `Ctrl-X Ctrl-X Ctrl-X`) destroys all local state and exits.

> **This is unaudited software.** Read [SECURITY.md](SECURITY.md) and [THREATMODEL.md](THREATMODEL.md) before relying on it for anything.

```
I am ◍ velvet-scythe-839f · mask 1/1 · tor ● · cover ON · union ends 23:59:51
masks                │ ⬡ union dim-garnet-0177
▸◍ velvet-scythe-839f│ ─ ⊘ old-toad-8a8a entered the union.
                     │ ⊘ old-toad-8a8a │ no names here, only keys.
unions               │ ◍ velvet-scythe-839f │ one union, no owner
▸⬡ union dim-ga… 23:59│
```

## Build

Rust stable (1.80+). No C dependencies.

```sh
cargo build --release --locked
# binaries: target/release/eigen, target/release/eigen-relay
```

## Run

EIGENHEIT talks to relays **only through Tor onion services**. Run a local `tor` (SOCKS on `127.0.0.1:9050`, control port `9051` with `CookieAuthentication 1` for relay hosts).

```sh
# Host a relay as an ephemeral onion service (its address dies with the process):
eigen-relay --onion
# → eigen-relay at abcd…xyz.onion:7777

# Chat through it:
eigen --relay abcd…xyz.onion:7777
eigen --relay abcd…xyz.onion:7777 --cover          # constant-rate cover traffic
eigen --relay abcd…xyz.onion:7777 --vault ~/.x     # opt-in encrypted vault
```

Several `--relay` flags fan out to several relays; relays are interchangeable and untrusted.

### Local development (two terminals, no Tor)

```sh
eigen-relay --listen 127.0.0.1:7777
eigen --relay 127.0.0.1:7777 --i-accept-the-risk     # terminal 1
eigen --relay 127.0.0.1:7777 --i-accept-the-risk     # terminal 2
```
Clear-net is refused without that flag: my network would see which mailboxes I touch and when. The status bar then reads `CLEAR-NET`.

**A walk through:** in terminal 1 `/card` prints my card; in terminal 2 `/dm <card>` opens a forward-secret DM; `/verify` on both sides shows the same SAS. In terminal 1 `/union` prints an invite; in terminal 2 `/join <invite>`. `/ttl 2m` shortens my term; `/renew` before the end to stay; without it the union dissolves. `/drop <name>` votes keys away from someone. `/burn` everything. Then check: `eigen-relay --self-test` proves the relay writes and prints nothing.

## Commands

| | |
|---|---|
| `/mask`, `/masks [n]` | new mask; list or wear mask n |
| `/card` | my contact card (whoever holds it can reach this mask) |
| `/dm <card>` | open a DM |
| `/union [passphrase]` | form a union (random secret → invite), or by passphrase |
| `/join <invite\|passphrase>` | enter a union |
| `/leave` | leave this union or DM, instantly |
| `/verify [name]` | fingerprint, PGP fingerprint, identicon, SAS |
| `/ttl <30m\|1h\|2d>` | how long my words live (DM) / my term length (union) |
| `/renew` | I stay for the next term |
| `/drop <name>` | vote to rotate keys away from someone (majority of the others) |
| `/mute <name>` | hide someone on my screen |
| `/me <action>`, `/once <words>`, `/unsay` | an action; words that vanish 30 s after being read; take back my last words |
| `/who`, `/invite` | who is in this union (as far as I can see); its current invite |
| `/trust [name]` | mark a key ✓ after comparing the SAS |
| `/veil [2m\|off]` | hide names and words now (Ctrl-V) or after idle (default 5 min) |
| `/lock <passphrase>` | lock the screen; 5 wrong tries burn everything |
| `/deadman <30m\|off>` | burn everything if I am idle that long |
| `/cover on\|off` | cover traffic |
| `/keep` | remember this union in my vault |
| `/export [path]`, `/import <path\|card>` | PGP public key out; pin a PGP key or card |
| `/burn` | destroy everything, exit |

Keys: `Tab`/`Shift-Tab` (or `Ctrl-N`/`Ctrl-P`) switch, `PgUp`/`PgDn` scroll, `Ctrl-U` new union, `Ctrl-M` new mask (only where the terminal distinguishes it from Enter), `Ctrl-L` redraw, `Ctrl-V` veil, `Up`/`Down` my earlier lines (RAM only), `F1` help, `Ctrl-X ×3` panic burn, `Ctrl-C` quit. Works at 80×24, honours `NO_COLOR`.

## How it works (short)

- **DMs:** X3DH with signed prekeys and one-time prekeys held (encrypted) at relays → Double Ratchet. Sealed sender: the first message encrypts my identity to the recipient's prekey. Receive mailboxes rotate with each ratchet step.
- **Unions:** the secret derives hourly mailbox ids and a control key; content uses per-participant sender-key chains, signed by each mask. Whenever anyone leaves or is dropped, sender keys rotate *and* the union takes a new secret, so those gone cannot even watch the mailboxes.
- **Wire:** every frame is exactly 1024 bytes; every stored blob exactly 960 bytes; one response per request. Hashcash PoW on every write.
- Details: [docs/PROTOCOL.md](docs/PROTOCOL.md), choices and their costs: [docs/DECISIONS.md](docs/DECISIONS.md), builds: [docs/BUILD.md](docs/BUILD.md).

## Layout

```
eigen-core   crypto + protocol (identity, x3dh, ratchet, dm, union, cell, pow, vault, pgp)
eigen-relay  RAM-only relay (+ --onion, --self-test)
eigen-tui    client: engine, links, tor SOCKS, ratatui UI; binary `eigen`
```

License: AGPL-3.0-or-later.
