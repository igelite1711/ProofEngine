# Phase 4 Report — Proof (2026-09-06)

## Delivered
- `proof-core`: `Proposition`, `StoredAttestation`, `Proof` types.
- `proof-format`: proposition + full proof envelope codec (`AttestationEntry =
  {"content","sign1"}`), semantic bounds (relationships ≤ max_edges, artifacts ≤
  max_nodes), `proof_id` must start with `prf:v1:` at schema level.
- `proof-crypto::id::proof_id`: byte-precise member-set binding (canonical map of
  proposition + sorted id lists; `created_at` informational, not covered).
- `proof-verify` (new crate): `ProofBuilder` (sort-by-id, duplicate rejection,
  limit check, parse-back self-check) and `verify_proof` implementing pipeline
  stages 1–6 + 9–11 with per-stage `CheckRecord`s and the triple
  `{cryptographic_validity, evidence_validity, policy_decision}`.
  Policy is stubbed to `INDETERMINATE` with an explicit note; lifecycle stages
  record `lifecycle_checked: false`. `allow_remote=true` is a caller error.
- `fixtures/golden-11..12.json` (valid proof, mutated proof → `ID_MISMATCH`).
- Quality: 79/79 tests, fmt clean, clippy zero warnings, `build --locked` ok.

## Gate (plan §Phase 4): PASS
Portable bytes verify on a fresh context (no DB); mutations fail with the exact
stage/code (event→`IDENTIFIERS/ID_MISMATCH`, sig→`SIGNATURES/SIGNATURE_INVALID`,
bad id→`IDENTIFIERS`, v=2→`SCHEMA/UNSUPPORTED_VERSION`); ungrounded proof shows
crypto VALID + evidence INVALID (triple separation holds); garbage input fails
closed at PARSE with `proof_id: None`.

## Spec amendments (FORMAT.md)
- §3 Proof row: byte-precise `proof_id` construction (was member-set prose).
- §4.6: `AttestationEntry` storage form; portability rule (in-proof resolution,
  digests-only externals).

## Hostile review notes
- Builder/parser cross-check: builder self-checks via the same `cbor_to_proof`
  the pipeline uses — codec drift breaks the build, not just verification.
- Mutation tests re-encode outer CBOR after surgery, so they exercise the real
  attacker shape (canonical bytes, stale bindings), not an artificial error path.
- `verify_proof` never fetches, never trusts `kid` alone (issuer derived from the
  verified key, then payload-bound), and never emits PASS (no policy engine yet).
- Residual: attestation `evidence_ref` dangling is reported at EVIDENCE stage while
  relationship refs report at RELATIONSHIPS — overlapping but stage-honest; the
  Phase 5+ explain pass may unify the presentation without changing codes.
