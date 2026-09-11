# Proof Engine — Interoperability (V1 draft — in development)

## Levels

- **I1 — self verification.** Rust creates and verifies its own artifacts
  (test suite, demo, golden harnesses).
- **I2 — independent verification.** A separate stdlib-only implementation
  verifies Rust-generated artifacts using independently implemented CBOR
  handling, identifier calculation, and signature verification (`interop/`
  verifier; proven over golden-01/04/05 during audit).
- **I3 — cross-generation.** The independent implementation creates
  artifacts (events, attestations with RFC 8032 signatures, proofs) that
  Rust verifies, and Rust-created artifacts that it verifies (`interop/`
  creator + `tools/differential.py` both directions).

## Golden vectors (append-only; see VERSIONING.md)

`fixtures/golden-01..31` (+19 `not_superseded`, +20 text-byte/normalization, +21/22/23 ESP256 P-256 valid/tampered/wrong-key, +24/25/26 composition linkage, +27 vocabulary declarations, +28 conflict quorum, +29/30 withdrawal/compromise, +31) pin canonical bytes, ids and signatures (both COSE -19 Ed25519 and opt-in -9 ECDSA P-256) - see INTEROP and LONGEVITY;
ids, signatures, and expected verdict triples. Each embeds its expectation;
generators under `crates/*/examples/gen_*vectors.rs` self-check before
writing and harnesses re-verify on clean checkout. Required coverage:
valid, invalid signature, wrong key, unknown algorithm, unknown version,
canonicality failure, identifier mismatch, expired, revoked, superseded,
relationship failure, policy failure (pass + fail on same evidence),
malformed input, resource-limit input.

## Second-verifier recipe (normative minimum)

Using ONLY this doc set + fixtures:

1. Parse CBOR per the FORMAT §1 subset (reject everything else).
2. Re-encode and require byte-identity (canonicality).
3. Recompute the object id: `sha256(canonical)` → base64url-no-pad with the
   typed prefix; require equality (`ID_MISMATCH` otherwise).
4. For attestations: parse COSE_Sign1 (4-array, protected `{1:alg,4:kid}`,
   empty unprotected, embedded payload); rebuild `Sig_structure =
   ["Signature1", body_protected, h'504531', payload]`; verify Ed25519
   (alg -19) with `kid` as the raw 32-byte pubkey.
5. Recompute `proof_id` over sorted member id sets; compare.
6. Compare PASS/FAIL per vector with the harness (`golden-01..05` minimum).

`interop/` executes exactly this recipe outside the Rust codebase.

## Implementer notes (learned from the audit)

- Canonical CBOR means RFC 8949 preferred serialization AND lexicographic
  map order AND shortest-form ints; enforce on decode, compare on encode.
- Compressed Edwards points store **y** with the top bit = x parity (a
  second implementation got this backwards once — differential tests exist
  so the mistake cannot survive).
- `external_aad` is the three bytes `50 45 31` ("PE1"), not to be confused
  with any hex transcription in prose (code constant governs).
- Base64url ids: no-pad alphabet; compare full strings (pad-bit variants
  decode alike — canonicalize before comparing).

Traceability: PE-INTEROP-001..003 (`docs/requirements-matrix.md`).
