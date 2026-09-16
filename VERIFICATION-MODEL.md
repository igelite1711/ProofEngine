# VERIFICATION-MODEL.md — Stages, Context, Verdicts

> **Status:** Normative consolidation (2026-09-10). Sub-reference of
> `PROOF-ENGINE-SPEC.md` §§9–11,14. Extends `VERIFICATION.md`. Answers §50:
> how partial, historical, and independent verification work.

---

## 1. Stages (fixed order)

`PARSE → SCHEMA → CANONICAL → IDENTIFIERS → SIGNATURES → KEYS → TIME →
REVOCATION/SUPERSESSION → EVIDENCE → RELATIONSHIPS → GRAPH → STATUS
(feed hygiene, V1.1; never flips validity) → POLICY
(caller hand-off, INDETERMINATE) → FINAL`.

Failures recorded, never repaired. `PARSE/SCHEMA` always fail-fast (no object
to continue with); `CANONICAL/IDENTIFIERS` fail-fast by default, collect-all
with `report_all_failures:true`; later stages always collect. `INVALID` always
carries ≥1 stable code; unknown never becomes valid.

## 2. Context (single object)

`VerificationContext {verified_at (0=sentinel), clock_skew_leeway,
allowed_algs, trusted_issuers, revocation_authorities, status_objects,
revocations_known_at, limits, allow_remote:false, report_all_failures,
accepted_vocabularies, extra_grounded, require_acyclic_provenance}`.
`VerifyCtx`/`EvalInputs` are thin projections (no break). Context echoed in
reports, never stored, never trusted. Zero network I/O in `verify_proof()`.

## 3. Verdicts

V1 triple `{cryptographic_validity, evidence_validity, policy_decision}`
preserved, plus feed health `status_inputs_valid` (V1.1; false = STATUS-stage
failures present, validity unaffected). Additive projection `dimensions()`:
`structural / cryptographic / evidence / provenance / temporal / revocation /
policy / overall` ∈ `VALID | INVALID | INDETERMINATE | NOT_APPLICABLE`.
`NOT_APPLICABLE` (e.g. provenance with no edges) never fails alone;
`INDETERMINATE` in any trust dimension ⇒ never `PASS`. `overall` = AND over
applicable dimensions.

The report also carries `referenced_proofs[]` (composition linkage) and
`conflicts[]` (divergent `(claim.type, subject)` groups — representation
only, validity unchanged, policy adjudicates; identical re-assertions are
corroboration, not conflict).

## 4. Lifecycle & history

Per-statement `ACTIVE | EXPIRED | REVOKED | SUPERSEDED | COMPROMISED |
UNKNOWN`, precedence `COMPROMISED>REVOKED>SUPERSEDED>EXPIRED>UNKNOWN>ACTIVE`.
`SUPERSEDED` preserves
history (`evidence VALID`, `not_superseded` policy fails current use);
`COMPROMISED` taints (history NOT preserved). Per-evidence `AVAILABLE |
WITHDRAWN | COMPROMISED | REVOKED | SUPERSEDED | EXPIRED | UNKNOWN |
UNAVAILABLE` (see LIFECYCLE.md). Status objects are signed attestations
with kind-appropriate authority
(revoke/supersede: original issuer OR `revocation_authorities`; withdraw:
authorities/target-issuer/bound-attestation issuer; compromise: target
identity OR authorities) + timeliness; unsigned lists
never trusted. Freshness (`revocations_known_at`) missing/stale ⇒ UNKNOWN.

## 5. Partial & independent

Partial graphs verify with explicit `PRESENT / REFERENCED / UNAVAILABLE /
VERIFIED / NOT_VERIFIED` matrix; missing evidence ⇒ INDETERMINATE, never
VALID. Composition references are always REFERENCED (linkage only).
Independent verifier (`interop/pengine.py`, stdlib-only, Ed25519 + P-256)
agrees on bytes/ids/signatures/bindings for all golden vectors both
directions (37-check differential); lifecycle/policy/graph verdicts stay
engine-side with binding-only cross-checks.

## 6. Pointers

`crates/proof-verify/src/{pipeline,report,context,builder}.rs`;
`crates/proof-graph/src/lib.rs`; `LIFECYCLE.md`; `TRUST.md`;
`ERROR-MODEL.md`; `fixtures/golden-11..19`.
