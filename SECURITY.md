# Security

## Status: unaudited

EIGENHEIT has **not** been reviewed by anyone independent. It implements published protocols (X3DH, Double Ratchet, sender keys) on audited primitives, but the *composition* — formats, state machines, key handling — is new code written quickly. Do not trust your safety to it until it has had an independent audit.

## What is protected (if the code is correct)

- **Content** of DMs and unions, end to end: XChaCha20-Poly1305 under keys from X25519/HKDF; relays see only ciphertext.
- **Forward secrecy and post-compromise security for DMs** (Double Ratchet). Union sender chains are hash ratchets (forward secrecy inside a chain) and rotate on every roster shrink.
- **Sender anonymity towards relays**: there is no sender field on the wire; mailbox ids are unlinkable without the secrets and rotate.
- **Network metadata, partially**: Tor onion services hide IP addresses; fixed 1024-byte cells hide sizes; separate Tor circuits per mask/DM/union; optional constant-rate cover traffic and random delivery delay blunt timing.
- **Disk**: RAM-only by default. The opt-in vault is Argon2id + XChaCha20-Poly1305, no header, bucketed size, random fill.
- **Impersonation**: names are derived from keys; TOFU pins warn loudly when a name reappears with a different key; `/verify` compares a full fingerprint and SAS out of band.

## What is NOT protected

- A **global passive adversary** correlating Tor traffic. Cover traffic raises the cost; it does not defeat this.
- A **compromised endpoint** (malware, OS, terminal emulator, keyloggers).
- **The other people.** They can screenshot, log, or run a modified client that ignores disappearing timers.
- **Union participants** see what is said in the union and its traffic volume; a departed participant can see ciphertext volume on the union mailbox until it rotates (hourly) — and can compute future hourly mailboxes, since it knew the secret.
- **Relays can drop, delay or withhold** traffic. Use several.
- **Deniability of the vault is weak.** The file's existence is visible. An adversary aware of the two-slot design can demand a second passphrase. The wipe duress mode destroys the real slot but cannot unwrite SSD blocks, journals or snapshots.
- **Swap**: secrets are locked in RAM only if `RLIMIT_MEMLOCK` allows locking everything; otherwise the status bar says `swap: exposed`. Use encrypted swap.
- **Name grinding**: the 32-bit word-name can be ground by an attacker; only the fingerprint/SAS authenticates.
- **No ban survives a term**; a dropped participant may return with another mask.
- **Clear-net mode** (`--i-accept-the-risk`) exposes mailbox ids and timing to the network.
- The **full Tor onion round trip was not exercised** in the build environment (no route to the Tor network there); the relay's onion publication was tested against a real tor, the client's SOCKS path against a mock.

## What needs independent review first

1. `eigen-core/src/ratchet.rs`, `x3dh.rs`, `dm.rs` — KDF usage, skipped-key handling, transactional state, sealed-sender envelope.
2. `eigen-core/src/union.rs` and `eigen-tui/src/unions.rs` — sender-key distribution, roster rules, rotation triggers, drop-vote counting, replay handling.
3. `eigen-core/src/vault.rs` — format indistinguishability, duress semantics, write safety.
4. `eigen-relay` — memory exhaustion, PoW parameters, the no-log/no-disk guarantee (see `--self-test`).
5. `eigen-tui/src/harden.rs` — the only `unsafe` code (rlimits, prctl, mlockall).
6. Side channels of Rust code paths around secret-dependent branches.

## Reporting

Open an issue without exploit details and ask for a private channel, or contact the maintainer directly. Please give time to fix before disclosure.
