# Phase 1 Report — Foundation (2026-09-06)

## Delivered
- `proof-core`: closed domain types, `ErrorCode` (13 stable codes), `HashRef` (sha-256/384),
  `Limits` (enforced defaults), `EventContent`/`AttestationContent`/`Claim`.
- `proof-format`: deterministic CBOR codec (RFC 8949 §4.1+§4.2.1), strict decoder
  (dup-key/shortest-form/order/trailing-byte checks), closed Event/Attestation schemas.
- `proof-crypto`: SHA-256/384, b64u-no-pad ids, Ed25519 keys + KeyRefs,
  COSE_Sign1 build/verify (`-19` required, `-9` opt-in, `-8/-7/-35/-36` → `DEPRECATED_ALGORITHM`),
  header `{1,4}` only, `external_aad=h'503531'`, empty unprotected enforced.
- `fixtures/golden-0{1..5}.json` + `tests/golden.rs` (5/5 pass on clean checkout).
- Quality: `cargo build --locked` ok, `cargo test` 32/32 ok (12 crypto + 15 format + 5 golden),
  `cargo fmt --check` clean, `cargo clippy --all-targets` zero warnings. `cargo deny` deferred
  (needs network audit DB; run before Phase 7).

## Gate (plan §Phase 1): PASS
codec round-trip, canonical re-encode, id stability, known-answer sig (fixed seed `[9u8;32]`),
`UNKNOWN/DEPRECATED_ALGORITHM` + `NON_CANONICAL` + `ID_MISMATCH` negatives, proptests
(256 round-trip + 512 raw-byte cases, deterministic TestRunner seed).

## Hostile review (spec §53, foundation scope)
- Forged payload → `ID_MISMATCH`/`SIGNATURE_INVALID`. Attacker re-signing victim subject
  under own key is A1 (malicious issuer) — correctly deferred to policy trust lists (Phase 5).
- Replay/nonce, clocks, revocation, graph scale → explicitly later phases; no nonce logic
  half-built into Phase 1 (would be worse than none).
- Ambiguous encoding → closed subset + re-encode-and-compare both layers (outer + protected).
- Accidental trust → `kid` treated as hint, bound to `expected_issuer`; unprotected forced empty;
  label-6 reuse rejected by test.
- `parse_sign1` returns UNTRUSTED shapes — only `verify_sign1` output may drive decisions
  (documented in code; Phase 4 pipeline must never call parse alone for trust).

## Residual risks / deviations (must not be forgotten)
1. **nint range restricted to i64** (`-2^63..-1`); full CBOR range is `-2^64..-1`. Explicit V0.1
   protocol restriction (schemas need only uint); second implementations must enforce the same
   rejection or interop breaks. FORMAT §1 to be amended in Phase 7 docs pass.
2. **P-256 path thinly tested** (1 test, default-off). Harden or drop before V0.1 if unused.
3. Timing: id `==` is non-constant-time (ids public — acceptable); sig verify delegated to
   `ed25519-dalek`/`p256` (constant-time primitives).
4. Decoder depth counter is iterative — no stack-overflow vector; encoder recursion is only
   reachable via decoder-limited values or trusted constructors.
5. ` cargo deny` + mobile-target audit not run (toolchain installed for `aarch64-linux-gnu`
   under PRoot; on-device Android target validation deferred).

## Build environment notes (local only, not part of spec)
- Rust 1.98.1 via rustup (minimal profile) + `apt-get install gcc` (gnu linker; Termux clang
  targets Android and lacks `-lgcc_s`).
- sdcard FUSE blocks exec → `.cargo/config.toml` sets `target-dir=/root/.cache/proof-target`.
