# EIGENHEIT — Threat model

What is mine is whatever I have power over. This document says exactly where that power ends.

## Assets
1. Message content (DMs and unions).
2. Who talks to whom (the social graph), and when.
3. Which masks belong to the same person.
4. Long-term keys (mask identity keys, union secrets).
5. Local state at rest (the optional vault).

## Adversaries I defend against

| Adversary | Capability | Defense |
|---|---|---|
| Passive network observer (ISP, Wi-Fi) | Sees my packets | All relay traffic over Tor onion services. Fixed 1024-byte cells. Optional constant-rate cover traffic. |
| Malicious / logging relay operator | Sees every cell it receives, keeps everything forever, can drop / replay / reorder / inject | Relay only sees opaque mailbox ids and fixed-size ciphertext. No sender field exists (sealed sender). Mailbox ids rotate (DM: per ratchet step; union: hourly). PoW nonces are bound to mailbox+blob+hour. Replays are rejected by the ratchet / sender-key indices. Fan-out over several relays defeats a single dropping relay. |
| Compromised relay host (seizure) | Dumps RAM | Relay holds only ciphertext blobs with hard TTL (≤ 24 h). No disk, no logs, no wall-clock timestamps. |
| Other union participants | See everything I say in the union, try to link my masks or find my IP | I appear only as the mask I chose for that union. Each mask/union uses a separate Tor circuit (SOCKS isolation). No presence, typing, read receipts, or "last seen". |
| Former participants (left / dropped) | Still know the union secret | Sender keys rotate on every roster change; they can no longer read content. They can still see *ciphertext volume* on the union mailbox until the hourly mailbox rotation they can also compute (documented limit). |
| Later seizure of my disk | Reads files | Default is RAM-only: nothing is written. Vault (opt-in) is Argon2id + XChaCha20-Poly1305, no header, fixed bucket size, indistinguishable from random. `/burn` overwrites and deletes it. |
| Later compromise of my long-term keys | Has my identity keys | DMs: X3DH + Double Ratchet → forward secrecy and post-compromise security. Unions: sender-key chains are hash ratchets (forward secrecy within a chain); rotation on roster change. |
| Anonymous spam / floods | Unlimited identities | Hashcash PoW on every PUT (relay minimum, rising with per-mailbox burst rate) and per-union minimums (higher for JOIN). Relay rate limits per mailbox and memory caps. |
| Mask correlation | Links masks by timing / connection | One Tor circuit per mask/union. Cover traffic and random delivery delay blunt timing. Masks share no key material. |
| Name impersonation | Grinds a key whose word-name matches mine (~2^32 work) | Names are handles, not authenticators. TOFU pins full keys; a second key with an already-seen name raises a loud warning. `/verify` gives a full fingerprint + SAS for out-of-band comparison. |

## Explicitly out of scope
- **Global passive adversary** correlating Tor entry and exit/onion traffic at scale. Cover traffic raises the cost; it does not defeat this.
- **Compromised endpoint**: malware, a compromised OS, a malicious terminal emulator, hardware keyloggers. If my machine is theirs, my keys are theirs.
- **Rubber-hose cryptanalysis.** The duress passphrase helps against a naive search; an adversary who knows EIGENHEIT supports two vault slots can keep demanding passphrases. Deniability is weak — see `SECURITY.md`.
- **The other party.** Screenshots, cameras, a modified client that keeps logs. Disappearing messages are a courtesy enforced by *their* client.
- **Denial of service** by a relay (it can drop everything). Mitigation is using several relays.
- **Traffic volume of a union** as seen by any participant (including past ones within the hour).
- **Side channels** (timing of crypto operations, power, cache) beyond what the upstream audited crates provide.
- **Swap / hibernation** when `mlock` is not permitted by the OS; the UI says so when it happens.

## Assumptions
- Tor works as designed; onion services hide both ends.
- Upstream crates (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `blake2`, `sha2`, `hkdf`, `argon2`) are correct.
- The OS CSPRNG (`getrandom`) is sound.
- Participants exchange contact cards / union invites over a channel they trust for that purpose.
