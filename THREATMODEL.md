# EIGENHEIT threat model

This document lists what EIGENHEIT protects, which adversaries it is designed to resist, what it does not protect against, and what it assumes.

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

## Assets

1. Message content in direct messages and unions.
2. Who talks to whom, and when (the social graph).
3. Which masks belong to the same person.
4. Long-term keys: mask identity keys and union secrets.
5. Data stored on disk (the optional vault).

## Adversaries and defenses

| Adversary | Capability | Defense |
|---|---|---|
| Passive network observer (for example, an ISP or a Wi-Fi operator) | Sees your packets. | Traffic to relays goes through Tor onion services, I2P, or a VPN or WireGuard tunnel with a Noise-encrypted link. All cells are 1024 bytes (1040-byte Noise frames). Constant-rate cover traffic is optional. |
| Malicious or logging relay operator | Sees every cell the relay receives and keeps everything. Can drop, replay, reorder or inject cells. | The relay sees only opaque mailbox IDs and fixed-size ciphertext. Messages carry no sender field (sealed sender). Mailbox IDs change at each ratchet step for direct messages and every hour for unions. Each proof of work is bound to the mailbox, the message and the hour. Replayed messages are rejected by the ratchet and sender key counters. Messages are sent to all configured relays, so one relay that drops messages does not stop delivery. |
| Compromised relay host (for example, a seized server) | Reads the relay's RAM. | The relay holds only ciphertext, each item for at most 24 hours by default. It writes nothing to disk, keeps no logs and stores no wall-clock timestamps. |
| Other union members | See everything you write in the union. Try to link your masks or find your IP address. | They see you only as the mask you use in that union. Each mask, direct message and union uses a separate Tor circuit (SOCKS isolation). There are no presence indicators, typing indicators, read receipts or "last seen" times. |
| Former union members (left or removed) | Know the previous union secret. | When a member leaves or is removed, the remaining members switch to a new union secret and new sender keys. Former members cannot read new messages, and old invites stop working. Until the switch, they can see how much ciphertext is sent to the union mailbox. The switch happens a few seconds after the departure is detected, or up to 15 seconds later if the member expected to send the new secret is offline. |
| Later seizure of your disk | Reads your files. | By default, nothing is written to disk. The optional vault is encrypted with Argon2id and XChaCha20-Poly1305. It has no header, has a fixed bucket size and cannot be told apart from random data. `/burn` overwrites and deletes it. |
| Later theft of your long-term keys | Has your identity keys. | Direct messages use X3DH and the Double Ratchet, which provide forward secrecy and post-compromise security. In unions, sender key chains are hash ratchets, which provide forward secrecy within a chain. They are replaced when membership changes. |
| Anonymous spam and floods | Can create unlimited identities. | Every message stored on a relay (PUT) requires a Hashcash proof of work. The relay sets a minimum that rises when a mailbox receives many messages in a short time. Each union also sets a minimum, which is higher for join messages. Relays limit the rate per mailbox and cap their memory use. |
| VPN provider | Sees all traffic that leaves your tunnel. | Direct relays require a Noise link authenticated with the relay's key. The provider sees fixed-size frames sent to one IP address and cannot see mailbox IDs. It can see when and how much you send, and which relay you use. Cover traffic makes timing and volume harder to observe. |
| Mask correlation | Links your masks by timing or by connection. | Each mask, direct message and union uses its own Tor circuit or I2P destination. Cover traffic and a random delivery delay make timing analysis harder. Masks share no key material. |
| Name impersonation | Generates a key whose word name matches yours (about 2^32 attempts). | A name is a label and does not prove identity. The full key is pinned the first time it is seen (trust on first use). If a known name appears with a different key, a clear warning is shown. `/verify` shows the full fingerprint and a short authentication string (SAS) to compare over a separate channel. |

## Out of scope

EIGENHEIT does not protect against the following.

- **VPN provider knowledge.** A VPN does not make you anonymous. The VPN provider knows who you are (through payment, account details and your IP address) and when you contact which relay. Only message content and mailbox IDs are hidden from it.
- **Global passive adversary.** An adversary who watches Tor entry, exit and onion traffic on a large scale can correlate it. Cover traffic makes this harder. It does not prevent it.
- **Compromised device.** Malware, a compromised operating system, a malicious terminal emulator or a hardware keylogger. An attacker who controls your computer has your keys.
- **Coercion.** The duress passphrase protects against a simple search. An adversary who knows that EIGENHEIT supports two vault slots can keep demanding passphrases. Deniability is weak. See [SECURITY.md](SECURITY.md).
- **The other participants.** They can take screenshots, photograph the screen, or use a modified client that keeps logs. Message expiry is enforced only by the recipient's client.
- **Clipboard.** Copied cards and invites are placed in the terminal clipboard. Other programs may read the clipboard while it holds the text. EIGENHEIT asks the terminal to clear it after 30 seconds, on `/burn` and when EIGENHEIT exits normally. It is not cleared if EIGENHEIT is terminated by a signal or crashes.
- **Denial of service by a relay.** A relay can drop all messages. Use several relays.
- **Union traffic volume** seen by any member, including former members until the union secret is replaced.
- **Side channels**, such as the timing of cryptographic operations, power use or cache behavior, beyond the protection that the audited upstream libraries provide.
- **Swap and hibernation** when the operating system does not allow `mlock`. If the terminal is wide enough, the status bar then shows `Memory not locked`.

## Assumptions

- Tor works as designed, and onion services hide the IP addresses of both ends.
- The upstream libraries (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `blake2`, `sha2`, `hkdf`, `argon2`) are correct.
- The operating system's random number generator (`getrandom`) is secure.
- Participants exchange contact cards and union invites over a channel they trust for that purpose.
