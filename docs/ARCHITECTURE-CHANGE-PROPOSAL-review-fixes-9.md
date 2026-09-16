# Architecture Change Proposal: Review-Fixes Batch (9 findings)

**Classification: CORE (fail-closed conformance, pre-V1.0) — §11 PENDING**

| | |
|---|---|
| Proposal | Close 9 substantiated external-review findings (HIGH×3, MEDIUM×4, LOW×2): empty-feed fail-open, derivation cycles, dangling-hint currency, future-status skew, claim-digest binding, evaluate split-brain, freeze-process, ungrounded creation, surface strictness |
| Layer | `proof-graph` (derivation acyclic) + `proof-verify` (status cutoff, evidence_digest binding, derivation enforcement) + `proof-crypto` (reserved field docs) + `proof-cli` (explicit --require-status, --production, relate fail-fast, evaluate prose, currently_acceptable) + docs |
| Trigger | Independent external review challenge (9 findings, all reproduced) |
| Status | Implemented; merge requires maintainer decision (ARCHITECTURE-FREEZE.md §6) |

## 1. Problem

| # | Sev | Finding |
|---|---|---|
| 1 | HIGH | `verify --revocations-known-at <fresh>` with 0 `--status` → ACTIVE exit 0. Caller-asserted absence misread as feed-proved absence. |
| 2 | HIGH | `PRODUCED` cycle A→B→A verifies VALID exit 0; only opt-in `--require-acyclic` catches. Derivation laundering passes as linkage. |
| 3 | HIGH | Evidence with dangling `attestation_ref` → `evidence_validity: valid` exit 0 with `UNKNOWN` note. Provenance-unverified reported as valid. |
| 4 | MED | Status issued AFTER verifier clock applies when within skew (e.g. revoke at T+100 verified at T → REVOKED). Historical "was valid then?" unanswerable. |
| 5 | MED | Claim `value=23` + unrelated evidence digest PASSes. Evidence supports claim by assertion, not cryptography. |
| 6 | MED | `evaluate` prose prints pipeline JSON (`policy_decision: indeterminate`) AND decision text (`decision pass`) to stdout. Two truths confuse automation. |
| 7 | MED | Working-tree auto-enable of `require_status_feed` on `revocations-known-at` breaks 8 e2e tests under frozen major (silent breaking change). |
| 8 | LOW | Bare trust-relevant edges (`SETTLES` without refs) build successfully, only fail later at `verify`. Invalid graphs travel too far. |
| 9 | LOW | 20+ CLI commands, 2 policy languages, 35 docs; no single strict operator profile. Steep curve, dual-language tax. |

## 2. Foundation deficiency (why CORE, not extension)

- **1/3**: currency vs history lives in pipeline verdict + `is_currently_acceptable`; policy cannot see empty feed or dangling hints without pipeline exposure (`currently_acceptable` JSON, `--production` exit).
- **2**: cycle semantics live in GRAPH stage; adapters see only post-verify reports.
- **4**: status knowledge cutoff (`issued_at <= verified_at`) is lifecycle semantics; policy cannot retroactively un-apply.
- **5**: `evidence_digest` binding must be checked where digests + claims meet (EVIDENCE stage); policy alone cannot fail evidence validity.
- **6/8**: CLI output contract + creation-time validation are front-end fail-closed behavior, but 8 touches trust-relevant grounding (graph semantics surfaced early).
- **7/9**: process + docs; no wire change.

## 3. Change

- **1+7** (`make.rs`, `check.rs`, `lib.rs`): revert auto-enable — `require_status_feed = (has require-status || has production) && !has no-require-status` (default false, frozen verdicts preserved). Add `--production` (implies `--require-acyclic` + `--require-status` + strict currency). `verify` `strict_fail` includes production. JSON gains `currently_acceptable`; human `VALID` becomes `VALID (historical ...)` when currency fails but pipeline passes. Help + completion + runbook document profile.
- **2** (`proof-graph`, `pipeline.rs`): new `check_derivation_acyclic` (all types except REFERENCES/EQUIVALENT) called unconditionally in GRAPH (fail `CYCLE_DETECTED` → evidence invalid). Existing `check_acyclic_provenance` retained for opt-in full-DAG (REFERENCES included). Unit + pipeline tests pin both.
- **3**: no validity break (renewal-carried evidence preserved per ACP review-hardening-2 §6). Split via `currently_acceptable` + `--production`/`--strict-current` + v2 `evidence_usable`; human notes + JSON make the split machine-readable.
- **4** (`pipeline.rs`): status effect timeliness strict — `issued_at <= verified_at` (no `+skew` grace). TIME windows keep skew (drift). Future statuses recorded as STATUS hygiene (`Expired`, `status_inputs_valid:false`), never applied. Test pins T vs T+100 vs T+200.
- **5** (`pipeline.rs`, `claim.rs`, `artifact.rs`): reserved claim field `evidence_digest` (64/96 hex, optional 0x). When present on verified statement, must match digest of `evidence_ref` target; mismatch/missing/malformed/non-text fails EVIDENCE (`ID_MISMATCH`/`DANGLING_REFERENCE`/`SCHEMA_VIOLATION`). Absent = no check (backward compatible). CLI `attest` fail-fasts malformed/missing-ref/non-text at creation (exit 2) + help documents binding.
- **6** (`make.rs`, `lib.rs`): `evaluate` prose prints decision prose ONLY on stdout (no report JSON); `--out` writes report file; `--json` prints merged `{policy_outcome, report}` (authoritative `policy_outcome.decision`). Matches POLICY.md ("plain prose stays default").
- **8** (`artifact.rs`, `lib.rs`): `relate` rejects ungrounded trust-relevant types (`requires_grounding()`) without refs; `--allow-ungrounded` preserves intentional negative vectors (verify still fails closed). Help updated.
- **9** (docs only): runbook `--production` banner + §§2/6/7 updates; attest/verify/evaluate/relate help; completion includes new flags. Perimeter crates (`proof-api`/`proof-bench`/`adapter-scitt`) remain `--workspace`-only (not default build); V1 boundary clarified without workspace surgery.
- **Follow-up propagation (same batch):** `evaluate`/`explain`/`batch-verify` enforce `--strict-current`/`--production` currency overlay (VALID-but-not-current fails even when policy/validity passes; batch JSON gains `currently_acceptable`+counts, resolve JSON gains `currently_acceptable`); `evaluate --json` human line coherent + currency note on stdout for `--quiet`; non-text `evidence_digest` fails closed; docs drift fixed (requirements-matrix PE-GRAPH-003/PE-EVID-002/PE-VERIFY-008/009/PE-CLI-004/006/007, ARCHITECTURE §4, SPEC §9, FORMAT §4 reserved field, LIFECYCLE clock rules, POLICY decisions, README stage table + CLI table + strict line, CHANGELOG, interop scope, capability-map CAP-012/020/041, SECURITY-MODEL T10 grounding+derivation, examples policies README); test harness handles `supersede`.
- **Round 4 (API parity + fail-fast + messages):** reference API accepts full `VerifyCtx` surface (`esp256`/`historical`/`report_all`/`accepted_vocab`/`extra_grounded`/`require_acyclic`/`require_status`/`no_require_status`/`production`/`strict_current`) with CLI-identical wire strings (lowercase validities/policy, UPPER lifecycle/status) + `currently_acceptable` (verify) and `currently_acceptable`/`currency_fail` (evaluate/explain) + full `conflicts` records (was bare count); `attest` fail-fast covered by `attest_rejects_bad_evidence_digest_fast`; API `verify_production_flags_parse_and_gate_empty_feed` pins feed gate + flag parsing; README strict line; SECURITY-MODEL grounding list + derivation residual; capability-map currency/binding/graph rows.

## 4. What breaks

| Item | Impact | Action |
|---|---|---|
| Proofs with derivation cycles | Now `GRAPH CYCLE_DETECTED` → evidence invalid (previously VALID) | Intended fail-closed; supply-chain loops were never valid; REFERENCES-only cycles unaffected |
| Statuses issued after verifier clock (even within skew) | No longer apply to historical verification (ACTIVE at past clock, REVOKED later) | Intended history fix; forensic callers verify at later clock to see effect |
| Attestations carrying `evidence_digest` mismatches | Now EVIDENCE fail (previously VALID) | Opt-in only; absent field = zero change; previously-bound proofs without the field unaffected |
| `relate` bare trust edges | Now creation error (exit 2) unless `--allow-ungrounded` | Intended fail-fast; use flag for negative tests |
| `evaluate` prose stdout | No longer contains report JSON (decision prose only) | Intended split-brain fix; machine callers use `--json`/`--out` (exit codes unchanged) |
| `verify` human `VALID` line | Appends `(historical ...)` when currency fails but pipeline passes; exit stays 0 bare | Presentation only; exits + JSON validity unchanged except new `currently_acceptable` field (additive) |
| Golden vectors (31) | None — no wire bytes change; new checks are additive fail-closed on previously-accepted invalid shapes | `validate_cddl.py` 31/31; differentials 39 py + 33 ts green |

## 5. Verification

| Gate | Result |
|---|---|
| `cargo build --locked` | green |
| `cargo test --locked` | 36 suites ok (incl. new: `derivation_cycles_fail_closed_by_default`, `future_status_within_skew_does_not_apply_to_history`, `evidence_digest_*×3`, `derivation_cycle_fails_by_default`, `relate_rejects_ungrounded_trust_edges`, `production_profile_enforces_currency`, `production_overlays_currency_on_evaluate_and_batch`, `init_policy_minimal_has_no_domain_vocabulary`, `add_evidence_digest_file_matches_digest_hex`, `build_omitted_evidence_and_relationships_means_empty`, `build_evidence_flag_may_be_omitted`, `attest_rejects_bad_evidence_digest_fast`) |
| `cargo fmt --check` / `clippy --workspace --all-targets -D warnings` | green |
| `make demo` determinism | `prf:v1:aKlERqgUZ…` identical |
| Manual repro (9 findings) | bare 0 vs require-status/production 1; derivation CYCLE_DETECTED 1; history ACTIVE 0 vs current REVOKED 1; digest mismatch 1; evaluate prose decision-only + --json merged; bare relate rejected |
| Python differential | 39 pass, 0 fail |
| TS differential | 33 pass, 0 fail |
| `neutrality` / `no-panic` / `trace` / `validate_cddl` | green |
| `freeze-guard` | manifest records added below (uncommitted until merge) |

## 6. Alternatives rejected

| Alternative | Why rejected |
|---|---|
| `require_status_feed` default-true | Breaks fresh-proof UX + 8 e2e tests under frozen major (ACP review-hardening-2 §6 already rejected); explicit + production is the honest balance |
| Fail pipeline on all dangling `attestation_ref` | Breaks renewal-carried evidence; currency split + `evidence_usable` already gates |
| New `ErrorCode` for digest mismatch | Reused `ID_MISMATCH`/`DANGLING`/`SCHEMA_VIOLATION` to avoid wire-code churn; codes are append-only |
| `evaluate` JSON by default | Breaks prose UX + docs; single-truth-per-mode preserves both |
| Extract perimeter crates from workspace now | Build-system churn for zero mechanism gain; already `--workspace`-only, boundary clarified in docs |

## 12. Usability push (follow-up, CLI + docs only — no frozen behavior)

- `init-policy --template minimal` (domain-agnostic starter) + fail-fast
  domain inputs for settlement-family templates (missing `--proof`/
  explicit flags is a usage error naming the remedy, not silent payment
  defaults); help lists the new template and the requirement.
- `build --evidence`/`--relationships` omittable (explicit `""` still works);
  events/attestations/`--proofs` stay required.
- `add-evidence --digest-file` (SHA-256 over file bytes, stdin via `-`).
- New `proof-cli id` command (`--artifact` + `--field id|issuer`) replacing
  every python id/issuer one-liner; README + `quick_proof.sh` are now
  zero-python flows (ids/issuers via `$(proof-cli id …)`).
- `explain --json` merged machine document (`{policy_outcome, report,
  explanation}`); prose stays default for both commands (never mixed).
- Fixed literal `{out}`/`{issuer}` next-hints (`init-policy` + two artifact
  hints now interpolate real paths).
- README manual flow rewritten around `--payload-file`/`--digest-file`/
  `init-policy --proof` with an annotated `--production` close; 5-minute
  orienting block + `--production` in common flags; `quick_proof.sh`
  modernized identically and pins the empty-feed fail-closed behavior;
  interactive tour closes with history-vs-currency.

## 13. Adoption push (CLI-side guardrail + conformance runner + wiring docs)

- `--seen-store`/`--seen-context`/`--seen-record` on `verify`/`evaluate`
  (`src/seen.rs`, CLI crate only — core stays stateless): success-path
  replay check + optional record, same file shape as `tools/seen_set.py`,
  fail-closed I/O (exit 2), verdict FAIL paths skip the gate. Help,
  runbook §4b, and 3 e2e tests pin it.
- `tools/conformance.py` (stdlib-only) + `make conformance` + interop-CI
  step: 17 golden proof vectors (triples, codes, stage/code, proof_id,
  conflicts) + 5 policy vectors (decision, requirement/passed) replayed
  through the CLI — 22 checks green; recipe in `INTEROPERABILITY.md`.
- `docs/INTEGRATION.md` (Rust one-shot with compile-checked example, shell/
  API production patterns, feeds/rotation/replay/blobs/keys/PII checklist);
  README For Developers shows `verify_and_evaluate`; `docs/INDEX.md` lists
  the guide; reference API README documents the full context surface.
- Frozen surface untouched by this section (CLI crate, tools, docs only).

## 14. Architecture push (semantic model, extension proof, verdict goldens)

- v2 `evidence_bound{kind}` leaf (policy CAN require cryptographic bindings,
  not just benefit when asserted): shared normalization
  `proof-crypto::claim::evidence_digest_hex` (pipeline refactored onto it,
  behavior-preserving); `VerifiedState.evidence_bindings` projection over
  verified ACTIVE statements; eval against AVAILABLE evidence of the kind;
  parse/describe/CBOR/EBNF/fuzz tripwires; v1 rejects the name; POLICY.md +
  POLICY-MODEL + capability CAP-059b; `v2_evidence_bound_*` tests.
- Fail-closed `compose`: union graph validated pre-build (grounding with
  `--extra-grounded` passthrough, dangling, SUPERSEDES linearity, derivation
  acyclicity; shared members deduped); TIME/REVOCATION stays verify-time
  (documented split); single `build` stays structural for negative vectors.
  `compose_validates_union_graph_coherence` pins cyclic-union refusal +
  valid-union verify.
- `custom_vocabulary` synthetic-domain test: novel `acme` vocabulary +
  caller `extra_grounded` trust kind + custom policy, zero core changes
  ( Bare custom edge valid by default, promoted kind fails closed).
- Golden-32/33/34 via new `gen_conformance_vectors` example (append-only;
  01–31 untouched): cycle, mismatch, future-history. Rust
  `golden_conformance_vectors_verify_as_recorded` + `make conformance`
  (22→25) cover them with zero runner changes (fixture iteration).
- Durability: manifest record extended (policy/state/eval/EBNF/fixtures);
  `check_freeze.py` gates untracked frozen-path files too (negative-tested);
  `RELEASE.md` requires interop + conformance + manifest/ACP coverage.

## 11. Maintainer Decision (PENDING)

| | |
|---|---|
| Decision | PENDING — freeze-manifest records added (`uncommitted`: 1× CORE) |
| Rationale | Fail-closed conformance on frozen invariants; additive policy/CLI surface; pre-V1.0 window |
| Breaking | Intended fail-closed only for previously-invalid shapes (cycles, future-status history, digest mismatch, ungrounded creation) + prose stdout narrowing (documented); no valid-proof wire changes |
| Compat | Goldens untouched; `currently_acceptable` additive; `--production` opt-in; `--allow-ungrounded` escape hatch |
| Pin action | Re-evaluated at merge; targeted tests + CI gates are the record |
