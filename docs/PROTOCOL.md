# EIGENHEIT protocol (v1)

Integers are big-endian. `‖` is concatenation. All formats are length-checked by `eigen-core::wire`.

## Primitives
- `H(x)` = BLAKE2b-256. `MAC(k, x)` = keyed BLAKE2b-256 (k = 32 bytes).
- `KDF(salt, ikm, info, n)` = HKDF-SHA256.
- `AEAD` = XChaCha20-Poly1305, 24-byte nonce, 16-byte tag.
- `DH` = X25519. `Sig` = Ed25519.
- `seal_fixed(k, pt, size)`: `pt` is length-prefixed (u16) and zero-padded to `size` bytes, then `AEAD(k, random nonce)` → `nonce ‖ ct` (size + 40 bytes).

## Cells (client ↔ relay)
Every cell is exactly **1024 bytes**. Unused tail bytes are random.

Request: `ver:u8=1 ‖ op:u8 ‖ rid:u32 ‖ body`

| op | name | body |
|---|---|---|
| 0 | PAD | — |
| 1 | PUT | `mbox:32 ‖ ttl:u32 ‖ hour:u64 ‖ nonce:u64 ‖ blob:960` |
| 2 | FETCH | `mbox:32 ‖ after:u64` (returns the first blob with seq > after) |
| 3 | TAKE | `mbox:32` (removes and returns the oldest blob) |

Response: `ver:u8 ‖ op:u8 ‖ rid:u32 ‖ status:u8 ‖ body`. Exactly one response per request.

| status | body |
|---|---|
| 0 OK | — |
| 1 ITEM | `seq:u64 ‖ hour:u64 ‖ nonce:u64 ‖ more:u8 ‖ blob:960` |
| 2 EMPTY | — |
| 3 POW | `need:u8` (the difficulty currently required) |
| 4 FULL / 5 BAD | — |

## Transports
- **Tor**: cells are sent unchanged over a SOCKS5 stream to `x.onion`. The SOCKS username is random for each context, which isolates circuits.
- **I2P**: cells are sent unchanged over a SAM v3 `STREAM CONNECT` from a separate `TRANSIENT` destination for each context (Ed25519, ECIES-X25519 lease sets).
- **Direct (VPN/WireGuard)**: `Noise_NK_25519_ChaChaPoly_BLAKE2s`. Client → relay `e, es` (48 bytes), relay → client `e, ee` (48 bytes), empty payloads. Then each cell is one transport message with explicit per-direction nonces 0, 1, 2…: 1024-byte cell → 1040-byte frame. The relay's static key travels in the address: `IP:PORT#base32(key)`.

## Proof of work
`pow = H("eigen/pow/v1" ‖ hour ‖ mbox ‖ H(blob) ‖ nonce)`; valid if it has ≥ `d` leading zero bits. `hour = unix_time / 3600`; relays accept current and previous hour. Relay: `d ≥ 12 + 2·⌊log2(1 + puts_last_60s(mbox)/16)⌋`. Receivers re-verify PoW against their own (union) minimum. Exact `(mbox, pow)` duplicates are rejected until expiry.

## Relay state
`mbox → [(seq, expiry_instant, hour, nonce, blob)]`. TTL ≤ `max_ttl` (default 24 h), ≤ 256 blobs per mailbox, global memory cap. Neither wall-clock time nor connection identity is stored.

## Masks (identities)
A mask holds: Ed25519 `sk_sig`, X25519 identity `ik`, X25519 signed prekey `spk` (id u32), up to 16 one-time prekeys, and `intro:16` random bytes.
- `d = H("eigen/name" ‖ ed_pub)`. Name: `ADJ[d0]-NOUN[d1]-hex(d2 d3)`. Glyph: `GLYPHS[d4 mod n]`. Color: `d5`. Identicon: 5×5 mirrored from `d6..d8`.
- Contact card: `eigen://mask/` ‖ base32(`ed_pub:32 ‖ intro:16 ‖ H(…)[0..4]`).
- Native fingerprint: hex `H("eigen/fpr" ‖ ed_pub)`. PGP fingerprint: SHA-1 v4 of the exported EdDSA key packet.
- SAS (verify): `s = H("eigen/sas" ‖ min(edA,edB) ‖ max(edA,edB))` → 5 words + 6 digits.

## Mailboxes of a mask
`B = H("eigen/bundle" ‖ intro)`, `O = H("eigen/opk" ‖ intro)`, `I = H("eigen/intro" ‖ intro)`, `Kb = KDF(0, intro, "eigen/bundle-key", 32)`.
- Bundle blob at `B`: `0x20 ‖ seal_fixed(Kb, ik_pub ‖ spk_id ‖ spk_pub ‖ Sig(sk_sig, "eigen/bundle" ‖ ik_pub ‖ spk_id ‖ spk_pub), 256)`. The bundle is republished every 30 minutes.
- OPK blobs at `O`: `0x21 ‖ seal_fixed(Kb, opk_id ‖ opk_pub, 64)`. Fetched with TAKE.

## X3DH (Alice → Bob)
Alice fetches Bob's newest valid bundle with FETCH, optionally takes an OPK with TAKE, and generates an ephemeral key `EK`.
`DH1 = DH(IKa, SPKb)`, `DH2 = DH(EKa, IKb)`, `DH3 = DH(EKa, SPKb)`, `DH4 = DH(EKa, OPKb)`.
`SK = KDF(0³², 0xFF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], "eigen/x3dh", 32)`. `AD = edA ‖ IKa ‖ edB ‖ IKb`.
Initial blob at `I`:
`0x01 ‖ EKa:32 ‖ spk_id:u32 ‖ opk_id:u32 (0xFFFFFFFF = none) ‖ seal_fixed(K0, edA ‖ IKa ‖ Sig(skA, "eigen/bind" ‖ IKa ‖ EKa) ‖ ratchet_msg, 720)` (AAD = the 41 header bytes)
with `K0 = KDF(0, DH(EKa, SPKb), "eigen/seal", 32)`. Alice sends every message in this format until she has received a reply. Bob deduplicates sessions by `EKa`.

## Double Ratchet
The Double Ratchet follows the Signal specification, with `KDF_RK(rk, dh) = KDF(rk, dh, "eigen/rk", 64)`, `KDF_CK(ck) = (HMAC-SHA256(ck, 0x02), HMAC-SHA256(ck, 0x01))`, `MAX_SKIP = 256`. Bob's signed prekey is his initial ratchet key. Message: `header = dh:32 ‖ pn:u32 ‖ n:u32`, `ct = AEAD(mk → KDF(0, mk, "eigen/mk", 56) = key ‖ nonce, pt, AD ‖ header)`. Message keys are consumed on use and cannot be derived twice.

Ratchet plaintext (padded to 512): `kind:u8 ‖ ttl:u32 ‖ reply_mbox_secret:32 ‖ id:8 ‖ len:u16 ‖ text`. Kinds (shared with unions): 1 text, 2 hello, 3 once (the receiver removes it 30 s after display), 4 unsay (`id` identifies an earlier message from the same sender; receivers remove it), 5 action (`/me`). `id` is random per message.

## Direct message transport
Each side announces a receive mailbox secret `m`. `id = H("eigen/mbox" ‖ m)`, `Km = KDF(0, m, "eigen/mbox-key", 32)`.
Blob: `0x02 ‖ seal_fixed(Km, header ‖ ct, 600)` (AAD = mailbox ID). Each side creates a new `m` whenever it starts a new sending chain and continues to poll old mailboxes for 15 min.

## Unions
Secret `S:32` (random, or `Argon2id(passphrase, "eigen/union-pass/v1", m=64 MiB, t=3)`).
Invite: `eigen://union/` ‖ base32(`S ‖ pow:u8 ‖ H(S)[0..3]`).
- `uid = H("eigen/uid" ‖ S)`, `Kc = KDF(0, S, "eigen/union-ctrl", 32)`, mailbox at hour h: `MAC(S, "eigen/umbox" ‖ h)`. Poll h and h−1; post to h.
- Blob: `0x10 ‖ seal_fixed(Kc, inner, 880)` with AAD = the hour mailbox ID, so a relay cannot move blobs between hours.
- `inner = kind:u8 ‖ from_ed:32 ‖ len:u16 ‖ body ‖ Sig(sk, "eigen/union" ‖ uid ‖ kind ‖ from_ed ‖ body)`.

| kind | body |
|---|---|
| 1 JOIN | `mx:32 ‖ at:u64 ‖ rnd:8` (member X25519 key; JOINs whose `at` is earlier than the receiver's own join time minus the allowed clock skew are ignored) |
| 2 HELLO | `mx:32 ‖ ends_at:u64 ‖ term:u32 ‖ to_ed:32` (reply to a JOIN; processed only by the member `to_ed`) |
| 3 SKEY | `gen:u32 ‖ eph:32 ‖ count:u8 ‖ count × (tag:8 ‖ AEAD(K_i, ck:32 ‖ idx:u32))` with `tag = H("eigen/skey-tag" ‖ to_ed)[0..8]`, `K_i = KDF(0, DH(eph, mx_i), "eigen/skey" ‖ uid, 32)`, nonce = 0 (fresh `eph` per SKEY → single-use key), AD = gen; ≤ 12 entries per SKEY |
| 4 MSG | `gen:u32 ‖ idx:u32 ‖ len:u16 ‖ ct` with `ct = AEAD(KDF(mk_i) → key ‖ nonce, kind:u8 ‖ id:8 ‖ len:u16 ‖ text padded to 576, uid ‖ from ‖ gen ‖ idx)`, sender chain `mk_i = MAC(ck_i, "mk")`, `ck_{i+1} = MAC(ck_i, "ck")` |
| 5 LEAVE | `rnd:16` |
| 6 RENEW | `term:u32` (the sender commits to term `term`) |
| 7 DROP | `target_ed:32 ‖ term:u32` |
| 8 REKEY | `epoch:u32 ‖ eph:32 ‖ count:u8 ‖ count × (tag:8 ‖ AEAD(K_i, S':32, epoch))`, `K_i = KDF(0, DH(eph, mx_i), "eigen/rekey" ‖ uid, 32)` |

Rules: the roster is the set of senders seen in JOIN or HELLO messages. Receivers re-verify PoW (`pow`, `pow+6` for JOIN). Members who LEAVE or are dropped are ignored for the rest of the term (a member who sent LEAVE may JOIN again; a dropped key may not). MSGs that arrive before their SKEY are held ≤ 2 min. On any roster shrink, every remaining member mints a new generation and SKEYs it to the remaining roster only. On roster growth, existing members SKEY their *current* chain position to the newcomer only. A joiner takes `ends_at = min(HELLO.ends_at)`. Term end: those who sent `RENEW(term+1)` continue with `ends_at += term_len` (the term length); others are removed. DROP passes at a strict majority of the roster minus the target. In a union, `/ttl` sets the term length of the member who runs it and can only shorten that member's current term.

### Rekey
Every roster shrink (LEAVE, passed DROP, term end with departures) triggers a new union secret `S'`, sent only to the remaining members (REKEY). The member with the lowest key sends it immediately. Any other member sends its own REKEY if none has arrived after 15 s. Conflicting REKEYs are resolved deterministically: the higher `epoch` wins; for equal epochs, the lowest `H("eigen/rekey-cand" ‖ S')` wins. On adoption, every member rotates its sender chain under the new `uid`, polls the new hourly mailboxes, and keeps reading the old ones for 5 min. JOINs sent under old keys are not answered, so old invites no longer work.
