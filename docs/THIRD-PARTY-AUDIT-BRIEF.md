# Third-party audit brief (commissioning pack)

> Status: READY TO SEND. This repository has never had an external security
> review — every number below is self-reported and machine-reproducible via
> the listed command. Send this file plus repo access to the auditor; publish
> their report next to the freeze manifest on receipt.

## 1. Scope to commission

In scope (trust-critical, frozen paths): canonical CBOR codec
(`proof-format/src/cbor.rs`), schemas + id binding (`schema.rs`,
`proof-crypto/src/id.rs`), COSE_Sign1 profile (`cose.rs`), envelope
verification (`proof-crypto/src/envelope.rs`), staged pipeline
(`proof-verify/src/pipeline.rs`), lifecycle derivation, policy evaluator
(`proof-policy/src/eval.rs`), graph validation (`proof-graph/src/lib.rs`).
Out of scope: HTTP reference API, bench harness, demo/pilot scripts,
domain journeys (test-only vocabulary), docs prose.

Ask for: parser-differential review (any input the strict decoder accepts
that a second implementation would reject, and vice versa), key-confusion
and algorithm-confusion cases, lifecycle precedence holes, policy-evaluator
soundness (AND-semantics, INDETERMINATE handling), resource-exhaustion
vectors against every `Limits` knob.

## 2. Evidence pack (reproduce everything)

| Claim | Command | Last verified |
|---|---|---|
| Workspace suite | `cargo test --locked --workspace` | 314 passed, 0 failed |
| Format/graph/verify/policy/cli units | included above | envelope modules ~100% (new) |
| Coverage | `make coverage` (needs `cargo-llvm-cov`) | ~80% lines workspace |
| Domain neutrality + adversary (12 industries) | `make domain-tests` | 9 passed, 0 failed |
| Independent verifiers | `make interop` (Python 37 + TS differential) | 37 pass, 0 fail |
| SCITT adapter + differential | `make scitt-check` | 5 pass, 0 fail |
| Fuzz builds (all 4 targets) | `make fuzzcheck` + CI `fuzz.yml` build job | present + seeded |
| Fuzz smokes (600 s × 4, nightly-only) | `.github/workflows/fuzz.yml` smoke job | last published green run cited in `docs/certification-report.md`; confirm current log in Actions — no findings log is published yet (gap §3) |
| Stable fuzz mirrors (all 4 harnesses) | `cargo test --locked -p proof-format --test fuzz_seeds` (+ graph, verify, policy) | green |
| Mutation soak (2000 flips) | `cargo test --locked -p proof-verify --test soak` | green |
| Demo determinism | `make demo` twice + `sha256sum -c` | byte-identical |
| Pilots | `make quick-proof`, `make pilot-legal` | PASS, deterministic |
| Perf tripwire | `make bench-check` (release vs `crates/proof-bench/baseline.json`) | passed |
| Traceability / neutrality / no-panic / CDDL / freeze | `make trace neutrality no-panic cddl-validate freeze-guard` | 90 ids / 57 files / clean / 31 vectors / guard OK |
| SBOM determinism | double `gen_sbom.py` + `cmp` | 99 components, identical |
| Supply chain | `cargo deny check` | clean (CI gate) |

## 3. Known residuals (do not let the auditor re-discover these)

1. No external review has ever happened — this brief exists to fix that.
2. Fuzz smokes run nightly-only and publish no findings log; only the build
   gate runs per PR. Stable seed mirrors + soak cover the gap partially.
3. Crates unpublished (`publish --dry-run` fails per design until ordered
   registry publish); downstream consumers pin via git, not crates.io.
4. Freeze proposal `docs/ARCHITECTURE-CHANGE-PROPOSAL-conformance-hardening.md`
   awaits the §5 maintainer decision; the manifest record is bookkeeping.
5. `proof-api` is a loopback reference (no auth/TLS/rate-limiting by design);
   production deployments must front it — say so in the report if unclear.

## 4. What to publish on receipt

The auditor's report (as received, plus a one-page maintainer response
mapping each finding to commit + test), next to the freeze manifest, with a
CHANGELOG entry. Findings that change frozen-path behavior follow
`ARCHITECTURE-FREEZE.md` §5 like any other CORE change.
