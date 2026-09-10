# POLICY.md — the policy language (V1.0)

A policy is the **only** thing that turns verification facts into a trust
decision. Same evidence under different policies may yield different
decisions: Evidence ≠ Policy, Proof ≠ Trust decision.

## Shape

```json
{
  "policy_version": 1,
  "policy_id": "merchant_payment_v1",
  "requirements": [ ... ]   // 1..=max_policy_requirements, implicit AND
}
```

No OR, no NOT, no expressions, no code evaluation, no network. Unknown
requirement types, unknown fields, empty requirement lists, and non-positive
versions are rejected with `POLICY_INVALID` before any evaluation. The
`policy_id` is echoed in outcomes and explanations.

## Requirement types (all ten, closed set)

| Type | Fields | Passes when |
|------|--------|-------------|
| `signature_valid` | — | the pipeline established cryptographic validity |
| `issuer_trusted` | `issuer` | the keyref is in the caller's trust list **and** has a signature-verified attestation in this proof. Valid signature alone never suffices |
| `issuer_excluded` | `issuer` | no signature-verified attestation by this issuer exists in the proof (deny-list screening) |
| `relationship_exists` | `relationship` | a validated edge of that type exists in the proof graph |
| `not_expired` | — | every signature-verified attestation satisfies issued/expires vs. the verifier clock (± skew leeway); attestations without `expires_at` impose no expiry |
| `not_revoked` | — | no signature-verified attestation id appears in the caller-supplied revocation set |
| `not_superseded` | — | no signature-verified attestation in this proof is SUPERSEDED by a valid signed supersession. Without this requirement a superseded (stale but historical) attestation still satisfies the other requirements — PASS then means "valid", not "current" |
| `evidence_present` | `kind` | evidence of that kind is present (digest-bound) |
| `transparency_present` | — | a `transparency_receipt` evidence item is present |
| `proof_fresh` | `max_age_seconds` | the proof's `created_at` is within `max_age_seconds` of the verifier clock. Provides replay protection against stale proofs |

`issuer` must be a well-formed `key:*` KeyRef (validated at parse time);
`relationship` is a closed `RelType` string (`OWNS`, `CREATED`, `SETTLES`,
`REFERENCES`, `CONTAINS`, `PRODUCED`, `EXECUTED`, `ISSUED`, `SUPERSEDES`,
`REVOKES`); `kind` is a closed `EvidenceKind` string (`signed_event`,
`signed_document`, `receipt`, `credential`, `measurement`,
`transaction_record`, `transparency_receipt`, `device_attestation`,
`external_reference`).

## Decisions

- **PASS** — the proof is valid (crypto + evidence) and every requirement passed.
- **FAIL** — the proof is valid but at least one requirement failed.
- **INDETERMINATE** — the proof itself is not valid (crypto or evidence), or
  the report and proof do not belong together. The policy was not evaluated;
  its requirements were neither satisfied nor refuted.

Embed status attestations (revoke/supersede) can never satisfy
`issuer_trusted` and never contribute validity intervals: a revocation
authority is not a statement issuer.

## Trust inputs are explicit and caller-supplied

Every evaluation takes the caller's trust list, revocation set, and a
verifier clock (+ skew leeway, default 300 s). The engine holds no global
state, keeps no issuer directory, and never reads a clock on its own. Zero
clock fails time requirements (fail-closed default).

## CLI usage

```console
proof-cli evaluate --proof proof.json --policy policy.json --clock 1700000300 \
    --trusted key:ed25519:... [--trusted ...] [--revoked id,id] \
    [--revocations-known-at 1700000300] [--skew 300]
proof-cli explain ...   # same flags; prints report + per-requirement prose
```

Exit codes: 0 PASS, 1 FAIL/INDETERMINATE, 2 error. The same evidence under a
merchant policy and a strict transparency policy can (and should) produce
different decisions — that is the point of separating evidence from policy.

## Machine-readable output

`evaluate --json` prints a `policy_outcome` object (stable fields:
`policy_id`, `decision`, `note` (the INDETERMINATE reason when present),
`results[{requirement, passed, message}]`) to stdout,
together with the pipeline `report` JSON — one flat, script-parsable document.
Exit codes are unchanged by `--json`. Plain prose stays the default;
`explain` never mixes JSON with prose (PE-CLI-006).

## V1 boundary and the extension story (current contract — in development)

The requirement set above is a **closed set with closed fields**: pure
conjunction over proof state, no negation, no disjunction, no arithmetic, no
code. Unknown requirement types and unknown fields are rejected
(`POLICY_INVALID`) — extension by schema-openness is deliberately NOT the
mechanism here.

- **New requirement semantics (OR, thresholds/quorum, freshness windows,
  external-state checks) can only arrive via a new `policy_version` with a
  documented capability row** (`docs/capability-map.md`). They will never be
  smuggled into `policy_version: 1`. Unknown versions already fail closed.
- **Multi-signature authorization works in V1 without new machinery**: N
  attestations + N `issuer_trusted` requirements = explicit AND-of-issuers
  (k-of-N quorum is the V2 threshold row, not a V1 hack).
- These limits are a feature: every policy decision remains a deterministic
  function the second implementer can reproduce from this page.
