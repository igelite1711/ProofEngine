# Phase 7 Report — CLI + demo + docs (2026-09-07)

## Delivered

- **`crates/proof-cli`** (workspace member, no new external dependencies — hand-rolled
  arg parsing): subcommands `create-event`, `attest`, `add-evidence`, `relate`,
  `build`, `verify`, `evaluate`, `explain`, `revoke`, `supersede`, `demo`, `help`.
  Exit codes: 0 PASS/valid, 1 FAIL/INDETERMINATE verdict, 2 usage/engine error.
  Progress on stderr; machine-readable JSON on stdout. `USAGE` text in
  `crates/proof-cli/src/lib.rs` matches implemented flags exactly.
- **Artifact files**: JSON wrappers around canonical CBOR bytes (hex) + id +
  (for attestations/status) base64url COSE envelope. Every artifact is
  re-verified on load — id recomputed, signature checked, canonical encoding
  enforced, cross-field consistency asserted (envelope payload vs `cbor`
  field; stated issuer vs signed key). Files are transport, never authority.
- **Demo** (`proof-cli demo`, wired to `make demo`): deterministic killer
  use-case — payment+invoice events, merchant attestation, SETTLES edge with
  grounding evidence; rebuild-from-scratch byte-identity assertion; PASS fresh
  (exit 0); one-byte tamper → FAIL (`ID_MISMATCH`,`DANGLING_REFERENCE`, exit 1);
  issuer-signed revocation → FAIL (`REVOKED`, exit 1) on the same bytes.
  Artifacts: `demo/out/{proof.cbor, report.json, explanation.txt}` plus CLI
  wrapper files. Byte-identical across runs (sha256-verified in gate below).
- **Tests** (`crates/proof-cli/tests/cli_e2e.rs`, 4 tests): parser
  (repeatable/boolean/inline/bad-u64 flags), `parse_fields` mapping, full
  artifact workflow verify→revoke→verify with exit-code assertions, policy
  separation (same proof PASSes merchant policy; `issuer_trusted` with empty
  trust list FAILs — signature alone never grants trust), demo determinism
  (two runs byte-identical).
- **Docs**: new `README.md`, `SECURITY.md`, `POLICY.md`, `VERIFICATION.md`
  (complete 22-code error table), `CONTRIBUTING.md`, root `Makefile`.
  Accuracy fixes in existing docs: THREAT-MODEL (COSE numbers `-19/-9`,
  "All fuzzed" → honest negative-tested claim, phantom `UNVERIFIED_EXTERNAL`
  code removed, replay-mitigation text aligned to implemented fields),
  ARCHITECTURE (`explain_full`, `evaluate_policy(state, policy, inputs)`,
  real `VerifyCtx` fields, EVIDENCE stage text).
- **Integration test for the full chain** (plan test-matrix) covered by the
  CLI workflow test plus the existing per-crate suites.

## Gate PASS

- `cargo build --locked` clean; `cargo test --locked`: **121 passed / 0 failed**
  (adds 4 CLI integration tests to the 117 from Phase 6).
- `cargo fmt --check` clean; `cargo clippy --locked --workspace --all-targets`
  zero warnings.
- `make demo` exit 0; sha256 of `demo/out/{proof.cbor,report.json,explanation.txt}`
  identical across two consecutive runs (A2 determinism).
- CLI smoke matrix (manual, logged here): verify fresh → exit 0 `valid/valid/ACTIVE`;
  after revoke → exit 1 code `REVOKED`; after supersede → lifecycle `SUPERSEDED`
  with evidence still `valid`, exit 0 (historical note per Phase 6 semantics /
  A6 — only expiry, revocation, or unknown-freshness are failures);
  `evaluate` 5-requirement merchant policy → `pass`; trust-list missing issuer →
  `fail` exit 1; trust-list containing issuer → `pass`; malformed flag input →
  exit 2 via error path.
- A12 dependency scan: `cargo tree --workspace` greps for
  blockchain/token/vm/zk/http/database/sql/tokio/hyper/reqwest → zero matches;
  tree is path deps + serde_json/serde/sha2/ed25519-dalek/p256/signature/
  base64/hex/thiserror only.

## Semantics locked

- Exit-code contract 0/1/2 as above; JSON reports go to stdout unless `--out`
  is given; `explain` prints prose only (never dumps JSON on top of it).
- Boolean CLI flags never swallow following `--flag` tokens (parser peeks).
- `--seed test` = fixed test key (demo/test only); otherwise 64 hex chars.
- Revocation info must be explicit: `--status` files (signature-verified) +
  `--revocations-known-at` timestamp; nothing is fetched or assumed.

## Hostile review notes (honest limitations)

- **A8 fuzz targets are NOT done**: `cbor_decoder`, `proof_verify`,
  `policy_parser`, `graph_ingest` cargo-fuzz targets and the 10-minute CI
  smoke run remain future work; `cargo fuzz`/nightly is unavailable in this
  environment. No "fuzzed" claim is made anywhere; VERIFICATION.md lists this
  under Current limitations. All parser surfaces are covered by hand-written
  negative tests only.
- The hostile review loop for Phase 7 (spec §53 questions) is pending — the
  questions are not in the repository.
- CLI key custody is demo-grade by design (SECURITY.md non-guarantees).

## Hostile review addendum (2026-09-07; spec §53 questions reconstructed)

Spec §53 itself is not in the repository (ARCHITECTURE.md spans §1–§9), so
the loop ran against the 13 THREAT-MODEL §3 threats as the question set,
scoped to Phase 7 (CLI loaders, exit codes, demo determinism, docs). 12/13
returned non-findings against implemented behavior (artifact loaders
re-verify ids/signatures/canonical form plus cross-field agreement;
`attest`/`revoke` derive issuer from the key; `--clock` mandatory;
`explain` never mixes JSON into prose; exit 0 only on crypto AND evidence
valid; bool flags never swallow `--flag`; valid-sig + empty trust FAILs —
all covered by `cli_e2e.rs`, `soak.rs`, or golden harnesses).

- **H1 (fixed): unbounded CLI file reads.** `read_json` / `load_proof` /
  policy read buffered whole files before any limit applied (library limits
  bind only post-decode bytes). Fix: `MAX_INPUT_FILE_BYTES` (8 MiB) enforced
  during buffering via `read_input_file` (`crates/proof-cli/src/lib.rs`),
  wired into all three load paths; regression test
  `oversized_input_files_fail_closed` in `cli_e2e.rs`. Suite now 129 green.
- **Fuzz evidence:** nightly + cargo-fuzz installed in this environment;
  `cargo +nightly fuzz build` succeeds for all four targets (needs
  `CXX=/usr/bin/g++` here); **runs** are blocked by ASan shadow `mmap`
  under PRoot, so the 600s runs await `.github/workflows/fuzz.yml`
  (ubuntu-latest). Details in `fuzz/README.md`.
