# VERIFICATION.md — how to verify a checkout or release

> How-to authority for checking out and releasing (commands, gates). Stages,
> context, and verdicts live in `VERIFICATION-MODEL.md` (sub-reference of
> `PROOF-ENGINE-SPEC.md` §§9–11,14); on semantics `PROOF-ENGINE-SPEC.md` wins.

Everything below is runnable today. Anything not yet runnable is listed under
"Current limitations" and must not be represented as done.

## Quick gate

```console
cargo build --locked
cargo test --locked        # all workspace tests must pass (see `make test`)
cargo fmt --check
cargo clippy --locked --workspace --all-targets   # zero warnings
make demo                  # deterministic; artifacts land in demo/out/
```

`make demo` verifies the headline flow end to end: a proof verifies PASS
fresh, fails after a one-byte tamper (`ID_MISMATCH`), and fails with `REVOKED`
after the issuer's signed revocation arrives — the same bytes each time. The
demo is byte-identical across runs (fixed test key `--seed test`, fixed
timestamps), which is itself a regression test for determinism.

The CLI surface is part of the release contract (PE-CLI-001..007): exit codes
0 = PASS/valid, 1 = FAIL/INDETERMINATE verdict, 2 = usage/engine error —
matrix-tested through the real dispatch path. `verify`/`evaluate` emit
machine-readable JSON reports; `evaluate --json` (PE-CLI-007) adds the
machine-readable policy decision (`policy_outcome` + `report`) without
changing the exit contract, and `explain` remains prose-only.

## Golden vectors

`fixtures/golden-*.json` (01..31) cover the negative matrix and lifecycle: tampered
signatures, wrong keys, expired / revoked / superseded attestations, missing
revocation info, malformed CBOR, duplicate map keys, non-canonical ints,
oversized proofs, ungrounded edges, dangling references, cycles, unauthorized
revokers. Golden-20 pins text byte-identity: no normalization/folding anywhere
(PE-FMT-009, FORMAT §3.1). Each embeds its expected verdict triple (crypto,
evidence, policy)
and error codes. The harnesses in `crates/proof-verify/tests/` and
`crates/proof-policy/tests/` re-verify every vector and pin the exact triple.

Regenerate (self-checking; they assert before writing):

```console
cargo run -p proof-verify --example gen_proof_vectors
cargo run -p proof-verify --example gen_lifecycle_vectors
cargo run -p proof-policy --example gen_policy_vectors
```

## Second-implementer check (A10)

`FORMAT.md` plus the vectors are sufficient to reimplement id computation and
signature verification: ids are `sha256(canonical CBOR)` in base64url with a
typed prefix; signatures are COSE_Sign1 with Ed25519 (-19) required and
ESP256 (-9) accepted. Recompute ids and signature checks over
`fixtures/golden-01..05` and compare PASS/FAIL with the harness.

## Error codes (complete table, stable wire strings — 24 codes)

| Code | Meaning (failure stage) |
|------|--------------------------|
| `NON_CANONICAL` | re-encoding decoded bytes differs from the input (CANONICAL) |
| `DUPLICATE_MAP_KEY` | CBOR map contained a repeated key (PARSE) |
| `FORBIDDEN_CBOR_CONSTRUCT` | float, tag, indefinite length, bignum, reserved ai (PARSE) |
| `ID_MISMATCH` | recomputed object id ≠ stated id — tamper evidence (IDENTIFIERS) |
| `SIGNATURE_INVALID` | COSE signature did not verify, or payload issuer ≠ envelope key (SIGNATURES) |
| `UNKNOWN_ALGORITHM` | COSE alg number not known to this verifier (SIGNATURES) |
| `DEPRECATED_ALGORITHM` | alg known but deprecated (-8/-7/-35/-36); fail closed (SIGNATURES) |
| `UNSUPPORTED_VERSION` | object/proof/policy version not supported (SCHEMA) |
| `LIMIT_EXCEEDED` | size/depth/entries/items limit exceeded (PARSE/SCHEMA/GRAPH) |
| `MALFORMED` | truncated input, trailing bytes, bad UTF-8, odd-length map (PARSE) |
| `INVALID_BASE64URL` | id component is not valid base64url (PARSE) |
| `UNEXPECTED_HEADER_PARAM` | COSE header carried an unexpected label/value (KEYS) |
| `ALGORITHM_CONFUSION` | key type does not match attestation alg (KEYS) |
| `SCHEMA_VIOLATION` | unknown enum variant/field, missing field, closed-set violation (SCHEMA) |
| `RELATIONSHIP_UNGROUNDED` | trust-relevant edge lacks backing evidence (RELATIONSHIPS) |
| `DANGLING_REFERENCE` | endpoint or reference resolves to nothing (RELATIONSHIPS/EVIDENCE) |
| `CYCLE_DETECTED` | SUPERSEDES subgraph is cyclic (GRAPH); or any relationship cycle under the opt-in provenance DAG profile (`--require-acyclic`) |
| `POLICY_INVALID` | policy syntax/version/requirement rejected before evaluation (POLICY) |
| `EXPIRED` | attestation outside validity window at the verifier clock (TIME); or status effect not valid yet at the verifier clock — future-dated feed object (STATUS, validity unaffected) |
| `REVOKED` | attestation covered by a valid signed revocation (REVOCATION) |
| `REVOCATION_UNKNOWN` | no/stale revocation info for a proof-bearing attestation (REVOCATION) |
| `UNAUTHORIZED_STATUS` | status object signer has no authority over its target (STATUS — feed hygiene; validity unaffected, see `status_inputs_valid`) |
| `WITHDRAWN` | covered by a valid signed withdrawal (REVOCATION/EVIDENCE) |
| `COMPROMISED` | tainted by a valid signed compromise marking (REVOCATION/EVIDENCE) |

## Current limitations (honest list)

- **Fuzz CI log (A8): GREEN 2026-09-07.** `cbor_decoder`, `proof_verify`,
  `policy_parser`, `graph_ingest` cargo-fuzz targets under `fuzz/` with
  seeds and nightly wiring (`.github/workflows/fuzz.yml`, 600s per target):
  the latest green CI run finished 4/4 `success` with no findings (an earlier run
  caught a misstated `proof_verify` invariant — a legitimate proof is
  crypto-`Valid` — fixed, clean re-run green). Locally all four
  **build** but cannot **run** in this container (ASan shadow `mmap` blocked
  under PRoot — see `fuzz/README.md`). Parser invariants stay enforced on
  stable by the negative tests, proptests, and mutation-soak
  (`crates/proof-verify/tests/soak.rs`).
- **Hostile review loop** for Phase 7 is pending (spec §53 questions are not
  in the repository; the loop needs them to run).
- CLI `--seed` key handling is demo-grade by design (see `SECURITY.md`).

## Reproducibility notes

All outputs (reports, demo artifacts, vectors) are deterministic for fixed
inputs; JSON reports are printed with sorted keys. On a clean checkout of a
given commit, `make demo` must reproduce `demo/out/` byte-for-byte — any
difference is a bug, not a version quirk.
