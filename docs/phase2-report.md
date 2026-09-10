# Phase 2 Report — Evidence (2026-09-06)

## Delivered
- `proof-core`: `Evidence` struct + model unit tests (closed-enum rejection, grounding flags).
- `proof-format`: `evidence_to_cbor` / `cbor_to_evidence` (FORMAT §4.3, closed, hint ≤256),
  + round-trip and unknown-kind tests.
- `proof-crypto::build`: `create_event` / `verify_event`, `attest` / `verify_attestation`,
  `make_evidence` / `verify_evidence`, shared `fixtures` (fixed seed `[9u8;32]`, fixed
  timestamps). Every builder round-trips through canonical CBOR + schema and refuses to
  sign bytes the issuer field disowns (`issuer == key.key_ref()` enforced at creation).
- `fixtures/golden-06..08.json` + 3 new golden tests (builder chain incl. cross-binding
  subject→event id and evidence→attestation id, wrong-issuer FAIL, evidence tamper → `ID_MISMATCH`).
- Quality: `cargo test` 48/48 (2 core + 21 crypto + 8 golden + 17 format), `cargo fmt --check`
  clean, `cargo clippy --all-targets` zero warnings, `cargo build --locked` ok.

## Gate (plan §Phase 2): PASS
sign→verify ok; 1-byte tamper → `SIGNATURE_INVALID`; wrong key → `SIGNATURE_INVALID`;
unknown event/evidence kinds → `SCHEMA_VIOLATION`; issuer/key mismatch and bad time order
refused at creation; fixed-key fixtures shared between unit tests and vectors 06–08.

## Explicitly NOT done here (later phases — do not assume)
- `verify_attestation` does NOT check expiry/revocation (Phase 6). Expiry fields are
  carried and schema-ordered only.
- `attestation.evidence_ref` / `evidence.attestation_ref` are NOT resolved (no graph until
  Phase 3; no full pipeline until Phase 4). Dangling refs are accepted in Phase 2.
- No replay/nonce handling (documented limitation since Phase 0).

## Hostile review (foundation + evidence scope)
- Re-wrapping attack (valid sign1 presented under another issuer) → `kid != expected` → FAIL (tested).
- Non-canonical issuer strings (padded b64, wrong prefix) can never be signed: creation
  requires exact `key_ref()` equality; verification parses strictly.
- Payload/issuer substitution inside verified payload → re-checked (`content.issuer ==
  expected_issuer`) even though `kid` already matched; defense in depth, near-zero cost.
- Evidence has no signature by design; its tamper-evidence is the id binding (tested) plus
  the referenced attestation's signature (tested end-to-end in golden-06).
