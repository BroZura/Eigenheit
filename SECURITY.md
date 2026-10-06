# Security

## Status: unaudited

EIGENHEIT has not been reviewed by an independent auditor. It implements published protocols (X3DH, the Double Ratchet and sender keys) and uses audited libraries for the cryptographic primitives. The code that combines them, including the message formats, state machines and key handling, is new and has not been reviewed. Do not rely on EIGENHEIT for your safety until it has been independently audited.

## Terms

- **Mask**: an identity. Its name and glyph are derived from its public key. Your masks share no keys with each other.
- **Card**: a contact card for a mask. It contains the mask's public signing key and a random value that identifies the mask's mailboxes on relays. Anyone who has it can open a direct message with that mask.
- **Union**: a group conversation. Anyone who has the union's secret can join it. A union runs for a set period (a term). Members use `/renew` to stay for the next term.
- **Invite**: the text that lets someone join a union. It contains the union's secret.
- **Relay**: a server that stores encrypted messages in RAM. By default, each message is stored for at most 24 hours.
- **Mailbox ID**: the address under which a relay stores messages.
- **Vault**: an optional encrypted file that stores your masks, known contact keys, the keys you marked as verified with `/trust`, and the unions you saved with `/keep`. Messages are never stored.
- **Cover traffic**: data sent on each connection to a relay at a constant rate. When there is no message to send, padding is sent, so an observer of the connection cannot tell when you send messages.
- **Burn**: delete all local data and exit (`/burn`).

## What is protected

These protections apply only if the code is correct.

- **Message content.** Direct messages and union messages are encrypted end to end with XChaCha20-Poly1305, using keys derived with X25519 and HKDF. Relays see only ciphertext.
- **Forward secrecy and post-compromise security for direct messages.** These are provided by the Double Ratchet. In unions, each sender's key chain is a hash ratchet, which provides forward secrecy within the chain. Union sender keys are replaced each time a member leaves or is removed.
- **Sender anonymity towards relays.** Messages carry no sender field. Mailbox IDs change regularly, and they cannot be linked to each other without the secret keys.
- **Network metadata, in part.**
  - Tor onion services and I2P destinations hide your IP address. A VPN hides your IP address from the relay only. The VPN provider can still see it.
  - All messages are sent in fixed 1024-byte cells, which hides their size.
  - Each mask, direct message and union uses a separate Tor circuit.
  - Optional constant-rate cover traffic and a random delivery delay make timing analysis harder.
- **Data on disk.** By default, nothing is written to disk. The optional vault is encrypted with Argon2id and XChaCha20-Poly1305. It has no header, its size is rounded up to a fixed bucket size, and unused space is filled with random data.
- **Impersonation.** Names are derived from keys. The full key is pinned the first time it is seen (trust on first use). If a known name appears with a different key, a clear warning is shown. `/verify` shows the full fingerprint and a short authentication string (SAS) to compare with the other person over a separate channel.

## What is not protected

- **Global passive adversary.** An adversary who can watch Tor traffic on a large scale may match senders and recipients by timing. Cover traffic makes this harder. It does not prevent it.
- **Compromised device.** Malware, a compromised operating system, a malicious terminal emulator or a keylogger can read everything.
- **Other participants.** The people you talk to can take screenshots, keep logs, or use a modified client that ignores message expiry, `/once` and `/unsay`.
- **Screen hiding and screen lock.** `/veil` and `/lock` protect against someone looking at your screen. While the screen is hidden with `/veil`, the status bar still shows the name of the active mask. `/lock` hides the whole screen. Neither protects against someone with access to the running process or to the terminal scrollback.
- **Clipboard.** `/card`, `/invite` and `/copy` can copy text to the terminal clipboard (OSC 52, also through tmux). Other programs may read the clipboard while it holds the text. A clipboard manager may keep its own copy. EIGENHEIT asks the terminal to clear the clipboard after 30 seconds, on `/burn` and when EIGENHEIT exits normally. The clipboard is not cleared if EIGENHEIT is terminated by a signal (for example, when the terminal window is closed) or crashes. Some terminals ignore the request to clear the clipboard. A copied invite contains the union's secret.
- **Union members.** Members see everything written in the union and how much traffic it has. A member who leaves or is removed can still see how much ciphertext is sent to the union until the remaining members switch to a new union secret. This happens a few seconds after their clients detect the departure, or up to 15 seconds later if the member expected to send the new secret is offline.
- **Relays** can drop, delay or withhold messages. Use several relays.
- **Vault deniability is weak.** Anyone who finds the vault file can see that it exists. An adversary who knows that the vault format supports two slots can demand a second passphrase. The duress wipe mode destroys the real slot. It cannot remove copies left in SSD blocks, file system journals or snapshots.
- **Swap.** Secrets are kept out of swap only on Linux, and only if `RLIMIT_MEMLOCK` allows all memory to be locked. Otherwise, the status bar shows `Memory not locked` if the terminal is wide enough. Use encrypted swap.
- **Names can be imitated.** A word name has only 32 bits, so an attacker can generate keys until one has the same name. Only the fingerprint and the SAS confirm who someone is.
- **Removal is temporary.** No list of removed members is kept after the current term. A removed member can return with another mask.
- **Connections allowed by `--i-accept-the-risk`.** This option allows relay connections that are otherwise refused. A direct relay given without `#KEY` is reached without link encryption. The network can then see mailbox IDs and timing, and the status bar shows `Direct (unencrypted)` or, for example, `VPN wg0 (unencrypted)`. A direct relay used without `--vpn` can see your IP address, and the status bar shows `Direct (encrypted)` or `Direct (unencrypted)`. The option also allows `--vpn` to use an interface that does not appear to be a tunnel. Message content stays encrypted end to end in all cases.
- **VPN mode.** The VPN provider can see who you are, when you send and receive traffic, and which relay you use. It cannot see mailbox IDs, because the link to the relay is encrypted with Noise. Sockets are bound to the VPN interface with `SO_BINDTODEVICE`. EIGENHEIT does not control how DNS, other programs, or the Tor and I2P daemons route their traffic.

## Untested parts

The build environment had no access to the Tor or I2P networks, so neither full round trip was tested.

- **Tor.** The relay's onion service publication was tested against a real Tor daemon. The client's SOCKS connection was tested against a mock.
- **I2P.** The SAM flow was tested against a scripted bridge. The handshake was tested against a real i2pd.

## Code that needs independent review

Review these parts first:

1. `eigen-core/src/ratchet.rs`, `x3dh.rs`, `dm.rs`: KDF usage, handling of skipped message keys, transactional state updates and the sealed-sender envelope.
2. `eigen-core/src/union.rs` and `eigen-tui/src/unions.rs`: sender key distribution, membership rules, key rotation triggers, drop vote counting and replay handling.
3. `eigen-core/src/vault.rs`: whether the file cannot be told apart from random data, duress behavior and safe writing.
4. `eigen-transport`: Noise NK usage and nonce handling, SAM parsing and interface binding.
5. `eigen-relay`: memory exhaustion, proof-of-work parameters, and the guarantee that nothing is logged or written to disk (see `--self-test`).
6. `eigen-tui/src/harden.rs`: the only `unsafe` code (rlimits, prctl, mlockall).
7. Side channels in code paths that branch on secret data.

## Reporting a vulnerability

Open an issue without exploit details and ask for a private channel, or contact the maintainer directly. Allow time for a fix before you disclose the issue publicly.
