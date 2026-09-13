# Architecture Change Proposal: status-input hygiene (`STATUS` stage)

**Classification: CORE DEVIATION (verdict-impacting, pre-V1.0) — §11 DECIDED below**

| | |
|---|---|
| Proposal | Record caller-feed and ineffective-effect problems in a new `STATUS` stage that never flips `evidence_validity`; expose feed health via `VerifyReport::status_inputs_valid` |
| Layer | `proof-verify` (pipeline + report), `proof-policy` (state projection), CLI/API JSON |
| Trigger | Independent external review, finding F2: "status-input errors poison validity" |
| Status | Implemented in `779a730`; decided here |

## 1. Requirement

A verifier operator must be able to distinguish "this proof is revoked" from "the status feed handed me a bad object" — for the proof subject, the auditor, and the policy engine. One paragraph, no solution: same bytes + same applied lifecycle must yield the same validity verdict regardless of how many ineffective (malformed, unauthorized, future-dated, badly-signed) status objects rode along in the caller-supplied inputs.

## 2. Why existing primitives cannot represent it

Attempted encoding with current primitives: report `UNAUTHORIZED_STATUS` / future-dated `EXPIRED` / malformed `SCHEMA_VIOLATION` as `REVOCATION`-stage failures (status quo ante). Where it fails: `stage_valid(EVIDENCE_STAGES)` folds every `REVOCATION` failure into `evidence_validity`, so a proof whose lifecycle is `ACTIVE` reports `evidence invalid` and policy short-circuits to `INDETERMINATE`. The report cannot answer "valid proof, broken feed" — validity conflates proof state with input hygiene at the byte level (demonstrated: forged revoke → `crypto valid, evidence invalid`, lifecycle `ACTIVE`).

## 3. Affected semantics

Frozen element F4 (verification order) and F5 (verdict shape). Old meaning: any `REVOCATION`-stage failure ⇒ `evidence_validity = Invalid`. New meaning: `REVOCATION` carries lifecycle outcomes only (`REVOKED` / `COMPROMISED` / `REVOCATION_UNKNOWN`, plus informational `EXPIRED`/`SUPERSEDED` notes); input-hygiene failures carry the new `STATUS` stage, excluded from `EVIDENCE_STAGES`, and set `status_inputs_valid = false`. For identical historical bytes: proofs with no hygiene failures verify byte-identically (no new records); proofs with hygiene failures move from `evidence invalid` (+`INDETERMINATE` policy) to `evidence valid` (+evaluated policy) with `status_inputs_valid: false` and the feed error still in `failure_codes`. Lifecycle outcomes are unchanged.

## 4. Security implications

Threats removed: feed-injection DoS (any party handing the verifier a mis-signed status object could previously force `INVALID`/`INDETERMINATE` on a good proof with no trust consequence to the attacker). Threats introduced: none — ineffective effects still never apply (authority + timeliness gates unchanged); a verifier that ignores `status_inputs_valid` accepts exactly the proofs whose applied lifecycle is clean, which is the documented validity definition. No downgrade (closed alg registry untouched), no replay change, no parser change. Fuzz + negative matrix: existing `proof_verify` fuzz seeds + soak mutation suites re-run green; `lifecycle::unauthorized_revocation_fails` and `lifecycle::future_dated_status_object_ignored` updated to pin new semantics (valid + `status_inputs_valid: false` + code present + lifecycle `ACTIVE`).

## 5. Compatibility implications

Pre-V1.0: no wire change (proof bytes, ids, signatures untouched), no version bump. Report JSON gains one boolean (`status_inputs_valid`); `failure_codes` still contains the feed error under a different stage. Golden vectors: untouched (31/31, none cover hygiene failures). Second implementations: unaffected (stages 1–6 + binding only; `STATUS` is engine-side).

## 6. Migration requirements

Proofs written before the change: none (bytes unchanged). Consumers: replace `evidence_validity == Invalid && code == UNAUTHORIZED_STATUS ⇒ revoked-ish` triage with `status_inputs_valid == false ⇒ feed broken; lifecycle RECORD is the revocation answer`. CLI human summary now prints the feed note explicitly. Migration ≠ reinterpretation: old reports are not rewritten; new runs state both dimensions.

## 7. Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep poisoning (document feed filtering as integrator duty) | Leaves attacker-cost asymmetry in the core: one bad object DoSes every verification using that feed; auditors cannot distinguish states from the verdict |
| Downgrade hygiene failures to `note` (ok:true) | Loses machine-readable feed signal from `failure_codes`; operators need the error to alert on |
| New `inputs_valid` dimension forcing overall INVALID | Reintroduces the same conflation one layer up |

## 8. Extension-based solution attempted

Filtering adapters (`StatusSource`) already exist and remain recommended — but they cannot fix the core semantics: even a perfect adapter sees the same verdict shape, and direct-`status_objects` callers (CLI `--status`, the documented path) have no adapter in the loop. Measured shortfall: forged revoke via CLI `--status` yielded `evidence invalid` pre-fix.

## 9. Independent verification impact

`interop/` unchanged (out of crypto scope). Recipe updates: none for second implementers; engine-side verdict documentation (`PROOF-ENGINE-SPEC.md` §9.1–9.2, `ERROR-MODEL.md`, `VERIFICATION-MODEL.md`, `LIFECYCLE.md`, operator runbook) updated in lockstep.

## 10. Long-term durability impact

The split is stable: lifecycle outcomes (proof facts) vs feed hygiene (caller-input facts) are disjoint by construction — future status kinds inherit the rule (ineffective ⇒ `STATUS`, applied ⇒ `REVOCATION`) without reopening. `status_inputs_valid` is additive and versioned with the report.

## 11. Decision

| | |
|---|---|
| Decision | **APPROVED** — genuine foundational deficiency (validity definition), unfixable by extension (verdict shape is the foundation) |
| Date | 2026-09-13 |
| Rationale | Pre-V1.0 window; every gate green post-fix (tests, differentials 37/37 py + 33/33 ts, demo, web honesty, traceability, neutrality, no-panic, CDDL) |
| Pin action | Recorded in `docs/freeze-manifest.json` (CORE, commit `779a730`); `ARCHITECTURE-FREEZE.md` §2 F4/F5 re-worded, §6 rows added |
