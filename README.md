```
'||''''|                             '||                   ||
 ||   .   ''                          ||             ''    ||
 ||'''|   ||  .|''|, .|''|, `||''|,   ||''|, .|''|,  ||  ''||''
 ||       ||  ||  || ||..||  ||  ||   ||  || ||..||  ||    ||
.||....| .||. `|..|| `|...  .||  ||. .||  || `|...  .||.   `|..'
                  ||
               `..|'
```

“My power is my property. My power gives me property. My power am I myself, and through it am I my property.”

EIGENHEIT (`eigen`) is a terminal chat program for direct messages and group conversations. A group conversation is called a union.

- **Identities.** An identity is a set of keys created on your device. There are no accounts. Your name (for example `amber-fox-3f9a`) and glyph are derived from your public key. An identity is called a mask. You can create several masks. Masks share no keys and use separate network connections.
- **Encryption.** All messages are end-to-end encrypted.
- **Unions.** A union is defined by a shared secret. It has no administrators. A union ends after a set term unless its members renew it. The status bar shows the time left as `Union ends in HH:MM:SS`. Members can vote to remove a member, which replaces the keys.
- **Cards and invites.** A contact card is a line of text that lets another person contact one of your masks. An invite is a line of text that lets another person join a union. It contains the union's secret, so share it only with people you trust.
- **Storage.** By default, all data is kept in RAM only. Nothing is written to disk. There is no message history, no read receipts, no typing indicator and no online status. Messages expire after one hour by default.
- **Relays.** A relay is a server that passes messages between clients. Relays store only encrypted messages of a fixed size, under mailbox IDs that change regularly. By default, they keep data in RAM for at most 24 hours (`eigen-relay --max-ttl`), and they keep no logs.
- **Leaving.** `/leave` leaves a conversation immediately. `/burn` (or `Ctrl-X` three times within 1.5 seconds) deletes all local data and exits.

> **Warning:** This software has not been audited. Read [SECURITY.md](SECURITY.md) and [THREATMODEL.md](THREATMODEL.md) before you rely on it.

```
◣ bronze-robin-7380 · Mask 1/2 · Tor ● · Union ends in 03:41:12 · RAM only
Masks                │ ⬡ Union ochre-heron-1c7d
▸◣ bronze-robin-7380 │ ─ ⬡ dawn-buoy-3e8f joined the union.
 □ third-well-5aaf   │ ⬡ dawn-buoy-3e8f │ Hello.
                     │ ◣ bronze-robin-7380 │ The meeting is moved to 18:00.
Unions               │                     │ Please confirm that you can attend.
▸⬡ Union ochr… 03:41 │ ◊ heavy-marsh-a505 │ Confirmed.
                     │
Direct messages      │
 ◊ heavy-marsh-a505  │
                     │
 ◌ Home              │
                     │──────────────────────────────────────────────────────────

› See you then.
```

## Build

Requires Rust stable 1.88 or later. There are no C dependencies.

```sh
cargo build --release --locked
# Binaries: target/release/eigen, target/release/eigen-relay
```

For reproducible builds, see [docs/BUILD.md](docs/BUILD.md).

## Run

EIGENHEIT connects to relays through Tor, I2P or a VPN (WireGuard) interface. You can use one or more of these at the same time.

| Relay address | Connection | Requirements |
|---|---|---|
| `x.onion:7777` | Tor. Each mask, direct message and union uses a separate circuit. | A local `tor` daemon with the SOCKS port on `9050`. To host a relay, also the control port on `9051` with `CookieAuthentication 1`. |
| `x.b32.i2p` | I2P. Each mask, direct message and union uses a separate destination. | A local I2P router (i2pd or Java I2P) with the SAM bridge on `7656`. |
| `IP:PORT#KEY` | Direct connection, encrypted with Noise and bound to a VPN or WireGuard interface. | `--vpn wg0` (or `--wireguard wg0`). |

Other relay addresses are refused: a direct relay without `--vpn`, and a direct relay without `#KEY`. The option `--i-accept-the-risk` allows them. Use this option for development only. With `--vpn`, a direct relay must be given as an IP address. A host name is always refused, because resolving it would send a DNS query outside the tunnel. The interface given with `--vpn` must exist.

```sh
# Host a relay. Each address is new at every start and stops working when the relay exits.
eigen-relay --onion                     # Prints the onion address: eigen-relay at abcd…xyz.onion:7777
eigen-relay --i2p                       # Prints the I2P address: eigen-relay at efgh…uvw.b32.i2p
eigen-relay --public 10.8.0.1:7778      # Prints the address for clients: eigen-relay at 10.8.0.1:7778#KEY (encrypted; …)
eigen-relay --onion --i2p --public 10.8.0.1:7778   # All three addresses, one message store

# Connect to a relay.
eigen --relay abcd…xyz.onion:7777
eigen --relay abcd…xyz.onion:7777 --cover          # Send cover traffic
eigen --relay abcd…xyz.onion:7777 --vault ~/.x     # Use an encrypted vault file
eigen --relay efgh…uvw.b32.i2p                      # Connect through I2P
eigen --wireguard wg0 --relay 10.8.0.1:7778#KEY     # Connect through wg0. Fails if wg0 is not available.
```

- **Cover traffic** (`--cover`): data sent on each connection to a relay at a constant rate. When there is no message to send, padding is sent, so an observer of the connection cannot tell when you send messages.
- **Vault** (`--vault PATH`): an encrypted file that stores your masks, known contact keys, the keys you marked as verified with `/trust`, and unions saved with `/keep`. Messages are never stored.
- `--relay` can be given more than once to use several relays, also on different networks. Relays are interchangeable and are not trusted.
- A VPN hides your IP address from the relay. The VPN provider can see your IP address and that you connect to the relay. See [THREATMODEL.md](THREATMODEL.md).

Run `eigen --help` and `eigen-relay --help` for all options.

### Local development

This setup uses two terminals and no Tor.

```sh
eigen-relay --listen 127.0.0.1:7777
eigen --relay 127.0.0.1:7777 --i-accept-the-risk     # Terminal 1
eigen --relay 127.0.0.1:7777 --i-accept-the-risk     # Terminal 2
```

Without a tunnel, your network can see which mailboxes you use and when. For this reason, unencrypted connections require `--i-accept-the-risk`. The status bar then shows `Direct (unencrypted)`.

**Example session:**

1. In terminal 1, run `/card`. Your contact card is shown on a clean screen. Press `C` to copy it and `Esc` to close the screen.
2. In terminal 2, run `/dm <card>` with the copied card. This opens a direct message with forward secrecy.
3. Run `/verify` on both sides. Both sides must show the same SAS (short authentication string).
4. In terminal 1, run `/union`. The invite is shown in the union view. Run `/invite` to show it on a clean screen and press `C` to copy it, or run `/copy invite`. In terminal 2, run `/join <invite>`.
5. Run `/ttl 2m` to set your term in the union to two minutes. Run `/renew` before the term ends to stay. If you do not renew, you leave the union when the term ends. The union continues for members who renewed.
6. Run `/drop <name>` to vote to remove a member.
7. Run `/burn` to delete all data and exit.
8. Run `eigen-relay --self-test`. It starts a test relay, sends traffic to it and checks that the relay prints nothing after start-up. On Linux, it also checks that the relay writes nothing to disk and has no files open.

## Commands

| Command | Description |
|---|---|
| `/mask` | Create a new mask. |
| `/masks [n]` | List your masks, or switch to mask n. |
| `/card` | Show the contact card of the active mask on a clean screen. Anyone with the card can contact this mask. Press `C` to copy it and `Esc` to close. |
| `/copy [card\|invite]` | Copy your contact card or the union invite to the clipboard. |
| `/dm <card>` | Open a direct message using a contact card. |
| `/union [passphrase]` | Create a union with a random secret and show its invite, or create a union from a passphrase. |
| `/join <invite\|passphrase>` | Join a union with an invite or passphrase. |
| `/invite` | Show this union's invite on a clean screen. Press `C` to copy it and `Esc` to close. |
| `/leave` | Leave this union or direct message immediately. |
| `/verify [name]` | Show the fingerprint, PGP fingerprint, identicon and SAS to compare with your contact. |
| `/trust [name]` | Mark a key as verified (✓) after you have compared the SAS. Run it again to remove the mark. |
| `/ttl <30m\|1h\|2d>` | In a direct message, set how long your messages are kept. In a union, set your term length. This also limits how long messages are kept on your screen and how long your messages are kept on relays. |
| `/renew` | Stay in this union for its next term. |
| `/drop <name>` | Vote to remove a member. The member is removed and the keys are replaced when more than half of the members, not counting that member, have voted. |
| `/who` | List the union members visible to you. |
| `/mute <name>` | Hide someone's messages on your screen only. |
| `/me <action>` | Send a message that describes an action. |
| `/once <words>` | Send a message that is removed 30 seconds after it is read. |
| `/unsay` | Take back your last message. |
| `/veil [2m\|off]` | Hide the screen now (`Ctrl-V`), or after a time without input. The default is 5 minutes. If the terminal is wide enough, the status bar shows `Screen hidden`. |
| `/lock [passphrase]` | Lock the screen. A passphrase is required the first time. Five wrong attempts delete all data. |
| `/deadman <30m\|off>` | Delete all data and exit after this long without input (auto-burn). If the terminal is wide enough, the status bar shows the time left as `Auto-burn in HH:MM:SS`. |
| `/cover on\|off` | Turn cover traffic on or off. |
| `/keep` | Save this union in the vault, or remove it from the vault. |
| `/export [path]` | Show your PGP public key, or save it to a file. |
| `/import <path\|card>` | Import a key from a PGP key file or a contact card. `/verify` and `/trust` can then find the key by its name. |
| `/burn` | Delete all data and exit. |
| `/help` | Show the list of commands (`F1`). |

**Copying.** `/card` and `/invite` show the text on a clean screen, where you can also select it with the mouse. A contact card is 97 characters long. In a terminal narrower than 97 columns, it is split across lines, and a mouse selection may then contain line breaks. Press `C` to copy the text without line breaks. `C` and `/copy` use the terminal clipboard (OSC 52). Inside tmux, the text is passed through to the outer terminal. In tmux 3.3 or later, this requires `set -g allow-passthrough on`. The clipboard is cleared after 30 seconds, on `/burn` and when EIGENHEIT exits normally.

## Keys

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` (or `Ctrl-N` / `Ctrl-P`) | Go to the next or previous conversation. |
| `PgUp` / `PgDn` | Scroll up or down. |
| `Up` / `Down` | Show earlier input. It is kept in RAM only. |
| `Ctrl-U` | Create a new union. |
| `Ctrl-M` | Create a new mask. This works only in terminals that distinguish `Ctrl-M` from `Enter`. |
| `Ctrl-V` | Hide the screen. |
| `Ctrl-L` | Redraw the screen. |
| `F1` | Show help. |
| `Ctrl-X` three times within 1.5 seconds | Delete all data and exit. |
| `Ctrl-C` or `Ctrl-D` | Quit. The commands `/quit` and `/exit` do the same. |

The interface works in terminals of 80×24 characters or larger. If the status bar does not fit in one line, the items with the lowest priority are hidden. The mask name, the union countdown, the mask number and the connection have the highest priority. In a small terminal, the command list (`/help`) scrolls with `Up` and `Down`. Set `NO_COLOR` to turn off colors.

## How it works

- **Direct messages:** X3DH key agreement with signed prekeys and one-time prekeys, followed by the Double Ratchet. One-time prekeys are stored encrypted at relays. The first message encrypts the sender's identity to the recipient's signed prekey (sealed sender). Receive mailboxes change with each ratchet step.
- **Unions:** The union secret derives the mailbox IDs, which change every hour, and a control key. Each member encrypts messages with a separate sender-key chain and signs them with their mask. When a member leaves or is removed, all sender keys are replaced and the union gets a new secret. Former members can no longer find the mailboxes.
- **Wire format:** Every cell sent between client and relay is exactly 1024 bytes. Over a Noise link, each cell is sent as a 1040-byte frame. Every stored blob is exactly 960 bytes. Each request receives exactly one response. Every write requires a hashcash proof of work.
- **Further documents:** protocol in [docs/PROTOCOL.md](docs/PROTOCOL.md), design decisions in [docs/DECISIONS.md](docs/DECISIONS.md), reproducible builds in [docs/BUILD.md](docs/BUILD.md).

## Layout

```
eigen-core       Cryptography and protocol: identity, X3DH, ratchet, direct messages,
                 unions, cells, proof of work, vault, PGP
eigen-transport  Noise relay connection, I2P SAM, connections bound to a VPN interface
eigen-relay      Relay that keeps all data in RAM (--onion, --i2p, --public, --self-test)
eigen-tui        Client: engine, connections, Tor SOCKS, terminal interface; binary `eigen`
```

License: AGPL-3.0-or-later.
