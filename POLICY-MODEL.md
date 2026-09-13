# POLICY-MODEL.md — Decisions Without Trust Confusion

> **Status:** Normative consolidation (2026-09-10). Sub-reference of
> `PROOF-ENGINE-SPEC.md` §12. Extends `POLICY.md`. Answers §50: how future
> policy systems are introduced.

---

## 1. Separation

```
Proof + VerificationContext + Policy → Decision
```

Verification establishes facts; policy decides acceptance. Same proof under
different policies may yield different decisions without changing the proof.
Pipeline never emits `PASS` alone (always `INDETERMINATE`); only
`evaluate_policy` decides. Valid signature ≠ trusted issuer ≠ policy
satisfied ≠ universal truth.

## 2. V1 frozen contract

JSON `{policy_version:1, policy_id, requirements[1..=max]}` implicit AND over
closed 10: `signature_valid | issuer_trusted{issuer} | issuer_excluded{issuer}
| relationship_exists{relationship} | not_expired | not_revoked |
not_superseded | evidence_present{kind} | transparency_present |
proof_fresh{max_age_seconds}`.

Validated before eval (`POLICY_INVALID` on any syntax error); deterministic
pure `f(state,policy,inputs)`; no I/O/crypto/AI. Decisions
`PASS | FAIL | INDETERMINATE` (broken preconditions ⇒ INDETERMINATE, never
PASS). `issuer_trusted` requires list membership AND a verified attestation;
status attestations never satisfy trust. `verify_and_evaluate()` pairs
pipeline+policy on one context so mismatched clock/trust is impossible.

## 3. Conflicts

Core represents conflicts, never arbitrates truth. Same `(claim.type,
subject)` with differing fields among verified statements is recorded in
`report.conflicts` (with an EVIDENCE note) while validity stays unchanged;
identical re-assertions are corroboration, not conflict. Policy resolves via
preferred issuer / threshold / recency / corroboration / human decision.
Conflict adjudication via v2 leaves is shipped (`any`/`threshold` quorums +
`no_conflicting_evidence`, pinned by golden-28 conflict→quorum-PASS); only a
dedicated report-level `CONFLICT` verdict remains V2;
currency conflicts (`REVOKED>SUPERSEDED`) handled today.

`proof_fresh` bounds self-declared age against the verifier clock — advisory
replay hygiene, not a boundary against a lying clock. `created_at` IS covered
by `proof_id` (V1 CORE freeze deviation, pre-V1.0 wire fix; re-stamping fails
`ID_MISMATCH`, pinned by test). Strong freshness comes from signed
attestation windows (`not_expired`) and transparency.

## 4. V2 path (boolean layer shipped)

`policy_version: 2` carries an `expression` tree (`all`/`any`/`not`/
`threshold{k,of}`) over the ten frozen v1 leaves plus eight adjudication
leaves (`delegated_authority`, `identity_bound`, `transparency_inclusion`,
`no_conflicting_evidence`, `vocabulary_accepted`, `evidence_usable`,
`requires_reference`, `forbids_reference`).
V1 stays byte-stable forever (v1 rejects v2 leaf names; v2 rejects the
`requirements` key). INDETERMINATE remains reserved for unevaluated policy.
Temporal windows beyond validity/freshness, relationship-provenance
constraints beyond existence, and external-state hooks arrive only via a
further `policy_version`. Pluggable engines allowed behind a versioned
registry; core never embeds a general programming language.

## 5. Pointers

`crates/proof-policy/src/{policy,eval,state,explain,combine}.rs`;
`docs/policy-grammar.ebnf`; `examples/policies/`; `fixtures/golden-13/14/19`.
