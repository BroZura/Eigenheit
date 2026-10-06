# EIGENHEIT protocol (v1)

Integers are big-endian. `‖` is concatenation. All formats are length-checked by `eigen-core::wire`.

## Primitives
- `H(x)` = BLAKE2b-256. `MAC(k, x)` = keyed BLAKE2b-256 (k = 32 bytes).
- `KDF(salt, ikm, info, n)` = HKDF-SHA256.
- `AEAD` = XChaCha20-Poly1305, 24-byte nonce, 16-byte tag.
- `DH` = X25519. `Sig` = Ed25519.
- `seal_fixed(k, pt, size)`: `pt` is length-prefixed (u16) and zero-padded to `size` bytes, then `AEAD(k, random nonce)` → `nonce ‖ ct` (size + 40 bytes).

## Cells (client ↔ relay)
Every frame on the socket is exactly **1024 bytes**. Unused tail bytes are random.

Request: `ver:u8=1 ‖ op:u8 ‖ rid:u32 ‖ body`

| op | name | body |
|---|---|---|
| 0 | PAD | — |
| 1 | PUT | `mbox:32 ‖ ttl:u32 ‖ hour:u64 ‖ nonce:u64 ‖ blob:960` |
| 2 | FETCH | `mbox:32 ‖ after:u64` (returns first blob with seq > after) |
| 3 | TAKE | `mbox:32` (removes and returns the oldest blob) |

Response: `ver:u8 ‖ op:u8 ‖ rid:u32 ‖ status:u8 ‖ body`. Exactly one response per request.

| status | body |
|---|---|
| 0 OK | — |
| 1 ITEM | `seq:u64 ‖ hour:u64 ‖ nonce:u64 ‖ more:u8 ‖ blob:960` |
| 2 EMPTY | — |
| 3 POW | `need:u8` (difficulty required now) |
| 4 FULL / 5 BAD | — |

## Proof of work
`pow = H("eigen/pow/v1" ‖ hour ‖ mbox ‖ H(blob) ‖ nonce)`; valid if it has ≥ `d` leading zero bits. `hour = unix_time / 3600`; relays accept current and previous hour. Relay: `d ≥ 12 + 2·⌊log2(1 + puts_last_60s(mbox)/16)⌋`. Receivers re-verify PoW against their own (union) minimum. Exact `(mbox, pow)` duplicates are rejected until expiry.

## Relay state
`mbox → [(seq, expiry_instant, hour, nonce, blob)]`. TTL ≤ 24 h, ≤ 256 blobs per mailbox, global memory cap. No wall-clock time, no connection identity is stored.

## Masks (identities)
A mask holds: Ed25519 `sk_sig`, X25519 identity `ik`, X25519 signed prekey `spk` (id u32), up to 16 one-time prekeys, and `intro:16` random bytes.
- `d = H("eigen/name" ‖ ed_pub)`. Name: `ADJ[d0]-NOUN[d1]-hex(d2 d3)`. Glyph: `GLYPHS[d4 mod n]`. Colour: `d5`. Identicon: 5×5 mirrored from `d6..d8`.
- Contact card: `eigen://mask/` ‖ base32(`ed_pub:32 ‖ intro:16 ‖ H(…)[0..4]`).
- Native fingerprint: hex `H("eigen/fpr" ‖ ed_pub)`. PGP fingerprint: SHA-1 v4 of the exported EdDSA key packet.
- SAS (verify): `s = H("eigen/sas" ‖ min(edA,edB) ‖ max(edA,edB))` → 5 words + 6 digits.

## Mailboxes of a mask
`B = H("eigen/bundle" ‖ intro)`, `O = H("eigen/opk" ‖ intro)`, `I = H("eigen/intro" ‖ intro)`, `Kb = KDF(0, intro, "eigen/bundle-key", 32)`.
- Bundle blob at `B`: `0x20 ‖ seal_fixed(Kb, ik_pub ‖ spk_id ‖ spk_pub ‖ Sig(sk_sig, "eigen/bundle" ‖ ik_pub ‖ spk_id ‖ spk_pub), 256)`. Republished every 30 min.
- OPK blobs at `O`: `0x21 ‖ seal_fixed(Kb, opk_id ‖ opk_pub, 64)`. Fetched with TAKE.

## X3DH (Alice → Bob)
Alice FETCHes Bob's newest valid bundle, TAKEs an OPK (optional), makes `EK`.
`DH1 = DH(IKa, SPKb)`, `DH2 = DH(EKa, IKb)`, `DH3 = DH(EKa, SPKb)`, `DH4 = DH(EKa, OPKb)`.
`SK = KDF(0³², 0xFF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], "eigen/x3dh", 32)`. `AD = edA ‖ IKa ‖ edB ‖ IKb`.
Initial blob at `I`:
`0x01 ‖ EKa:32 ‖ spk_id:u32 ‖ opk_id:u32 (0xFFFFFFFF = none) ‖ seal_fixed(K0, edA ‖ IKa ‖ Sig(skA, "eigen/bind" ‖ IKa ‖ EKa) ‖ ratchet_msg, 720)` (AAD = the 41 header bytes)
with `K0 = KDF(0, DH(EKa, SPKb), "eigen/seal", 32)`. Alice repeats this format until she has received a reply. Bob dedupes sessions by `EKa`.

## Double Ratchet
Per the Signal specification with `KDF_RK(rk, dh) = KDF(rk, dh, "eigen/rk", 64)`, `KDF_CK(ck) = (HMAC-SHA256(ck, 0x02), HMAC-SHA256(ck, 0x01))`, `MAX_SKIP = 256`. Bob's signed prekey is his initial ratchet key. Message: `header = dh:32 ‖ pn:u32 ‖ n:u32`, `ct = AEAD(mk → KDF(0, mk, "eigen/mk", 56) = key ‖ nonce, pt, AD ‖ header)`. Message keys are consumed on use and cannot be derived twice.

Ratchet plaintext (padded to 512): `kind:u8 ‖ ttl:u32 ‖ reply_mbox_secret:32 ‖ id:8 ‖ len:u16 ‖ text`. Kinds (shared with unions): 1 text, 2 hello, 3 once (receiver drops it 30 s after display), 4 unsay (`id` names my earlier message; receivers remove it), 5 action (`/me`). `id` is random per message.

## DM transport
Each side announces a receive mailbox secret `m`. `id = H("eigen/mbox" ‖ m)`, `Km = KDF(0, m, "eigen/mbox-key", 32)`.
Blob: `0x02 ‖ seal_fixed(Km, header ‖ ct, 600)` (AAD = mailbox id). A side mints a new `m` whenever it starts a new sending chain and keeps polling old ones for 15 min.

## Unions
Secret `S:32` (random, or `Argon2id(passphrase, "eigen/union-pass/v1", m=64 MiB, t=3)`).
Invite: `eigen://union/` ‖ base32(`S ‖ pow:u8 ‖ H(S)[0..3]`).
- `uid = H("eigen/uid" ‖ S)`, `Kc = KDF(0, S, "eigen/union-ctrl", 32)`, mailbox at hour h: `MAC(S, "eigen/umbox" ‖ h)`. Poll h and h−1; post to h.
- Blob: `0x10 ‖ seal_fixed(Kc, inner, 880)` with AAD = the hour mailbox id (a relay cannot move blobs between hours).
- `inner = kind:u8 ‖ from_ed:32 ‖ len:u16 ‖ body ‖ Sig(sk, "eigen/union" ‖ uid ‖ kind ‖ from_ed ‖ body)`.

| kind | body |
|---|---|
| 1 JOIN | `mx:32 ‖ at:u64 ‖ rnd:8` (member X25519 key; JOINs with `at` older than my own entry − skew are history and ignored) |
| 2 HELLO | `mx:32 ‖ ends_at:u64 ‖ term:u32 ‖ to_ed:32` (answer to a JOIN; ignored by everyone but `to`) |
| 3 SKEY | `gen:u32 ‖ eph:32 ‖ count:u8 ‖ count × (tag:8 ‖ AEAD(K_i, ck:32 ‖ idx:u32))` with `tag = H("eigen/skey-tag" ‖ to_ed)[0..8]`, `K_i = KDF(0, DH(eph, mx_i), "eigen/skey" ‖ uid, 32)`, nonce = 0 (fresh `eph` per SKEY → single-use key), AD = gen; ≤ 12 entries per SKEY |
| 4 MSG | `gen:u32 ‖ idx:u32 ‖ len:u16 ‖ ct` with `ct = AEAD(KDF(mk_i) → key ‖ nonce, kind:u8 ‖ id:8 ‖ len:u16 ‖ text padded to 576, uid ‖ from ‖ gen ‖ idx)`, sender chain `mk_i = MAC(ck_i, "mk")`, `ck_{i+1} = MAC(ck_i, "ck")` |
| 5 LEAVE | `rnd:16` |
| 6 RENEW | `term:u32` (I commit to term `term`) |
| 7 DROP | `target_ed:32 ‖ term:u32` |
| 8 REKEY | `epoch:u32 ‖ eph:32 ‖ count:u8 ‖ count × (tag:8 ‖ AEAD(K_i, S':32, epoch))`, `K_i = KDF(0, DH(eph, mx_i), "eigen/rekey" ‖ uid, 32)` |

Rules: roster = senders seen via JOIN/HELLO. Receivers re-verify PoW (`pow`, `pow+6` for JOIN). Participants who LEAVE or are dropped are ignored for the rest of the term (a LEAVEr may JOIN again; a dropped key may not). MSGs that arrive before their SKEY are held ≤ 2 min. On any roster shrink, every remaining participant mints a new generation and SKEYs it to the remaining roster only. On roster growth, existing participants SKEY their *current* chain position to the newcomer only. A joiner takes `ends_at = min(HELLO.ends_at)`. Term end: those who sent `RENEW(term+1)` continue with `ends_at += ttl`; others are removed. DROP passes at a strict majority of the roster minus the target. `/ttl` in a union sets my term length and can only shorten my current term.

### Rekey
Every roster shrink (LEAVE, passed DROP, term end with departures) triggers a new union secret `S'`, sent only to the remaining participants (REKEY). The participant with the lowest key sends it at once; anyone else sends their own after 15 s of silence. Conflicts converge: higher `epoch` wins, then the lowest `H("eigen/rekey-cand" ‖ S')`. On adoption everyone rotates their sender chain under the new `uid`, polls the new hourly mailboxes, and keeps reading the old ones for 5 min. JOINs arriving under old keys are not answered: old invites are void.
