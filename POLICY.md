# POLICY.md — the policy language (V1.0)

> V1 language authority (requirement types, evaluation). Decisions, conflicts,
> and the v2 path live in `POLICY-MODEL.md` (sub-reference of
> `PROOF-ENGINE-SPEC.md` §12); on semantics `PROOF-ENGINE-SPEC.md` wins.

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
| `proof_fresh` | `max_age_seconds` | the proof's `created_at` is within `max_age_seconds` of the verifier clock. `created_at` IS covered by `proof_id` (V1 CORE freeze deviation, pre-V1.0 wire fix): a holder re-stamp breaks the id and fails `ID_MISMATCH`. Still advisory between cooperating parties: it bounds only self-declared age against the verifier clock — strong freshness comes from signed attestation windows (`not_expired`) and transparency anchoring |

`issuer` must be a well-formed `key:*` KeyRef (validated at parse time);
`relationship` and `kind` are open vocabulary strings (transported verbatim
per FORMAT §4 / PE-FMT-008; acceptance is the policy's judgment, never a core
rejection). Well-known V1 labels for readability: `RelType` (`OWNS`,
`CREATED`, `SETTLES`, `REFERENCES`, `CONTAINS`, `PRODUCED`, `EXECUTED`,
`ISSUED`, `SUPERSEDES`, `REVOKES`, plus `EQUIVALENT`, `CONTRADICTS`);
`EvidenceKind` (`signed_event`, `signed_document`, `receipt`, `credential`,
`measurement`, `transaction_record`, `transparency_receipt`,
`device_attestation`, `external_reference`, plus `transparency_registration`,
`transparency_checkpoint`). Unknown labels evaluate normally against the
proof graph (present-or-not), so `acme:*` domain vocabularies need no core
change.

## Decisions

- **PASS** — the proof is valid (crypto + evidence) and every requirement passed.
- **FAIL** — the proof is valid but at least one requirement failed.
- **INDETERMINATE** — the proof itself is not valid (crypto or evidence), or
  the report and proof do not belong together. The policy was not evaluated;
  its requirements were neither satisfied nor refuted.

Embed status attestations (revoke/supersede/withdraw/compromise) can never
satisfy `issuer_trusted` and never contribute validity intervals: a status
authority is not a statement issuer. Authority per kind (see LIFECYCLE.md):
revoke/supersede — target's original issuer or `revocation_authorities`;
withdraw — authorities, target attestation's issuer, or bound-attestation
issuer for evidence; compromise — target identity itself (self-report) or
authorities.

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

- **New requirement semantics arrive via `policy_version: 2`** (this
  section), never smuggled into `policy_version: 1`. Unknown versions
  already fail closed.
- **Multi-signature authorization works in V1 without new machinery**: N
  attestations + N `issuer_trusted` requirements = explicit AND-of-issuers.
- These limits are a feature: every policy decision remains a deterministic
  function the second implementer can reproduce from this page.

## Policy v2 (`policy_version: 2`)

V2 keeps v1's guarantees (validated before evaluation, deterministic pure
function, INDETERMINATE on broken preconditions, never evaluated partially)
and adds boolean structure plus adjudication leaves. V1 policies parse and
verify byte-identically; v1 leaf names are frozen.

```json
{
  "policy_version": 2,
  "policy_id": "either_authority_v2",
  "expression": {"all": [
    {"type": "signature_valid"},
    {"any": [
      {"type": "issuer_trusted", "issuer": "key:ed25519:AAA"},
      {"type": "issuer_trusted", "issuer": "key:ed25519:BBB"}
    ]},
    {"type": "not_expired"}
  ]}
}
```

Connectives (children always evaluated, so explanations stay complete):

| Form | Shape | Passes when |
|------|-------|-------------|
| `all` | `{"all": [...]}` non-empty | every child passes |
| `any` | `{"any": [...]}` non-empty | some child passes |
| `not` | `{"not": {...}}` single child | child fails |
| `threshold` | `{"threshold": {"k": K, "of": [...]}}`, 1 ≤ K ≤ N | ≥ K children pass |

Empty `all`/`any`/`of`, `k = 0`, `k > N`, mixed connectives per object, and
unknown fields are `POLICY_INVALID` (no vacuous truth, no dead policy).
Total nodes (leaves + connectives) ≤ `max_policy_requirements` (32 default).

Adjudication leaves (v2-only; rejected under v1):

| Type | Fields | Passes when |
|------|--------|-------------|
| `delegated_authority` | `root`, `issuer`, optional `scope` | root trust-listed AND issuer has a verified attestation AND (issuer == root OR an active `delegate` chain root→issuer; every link matches `scope` when set) |
| `identity_bound` | `a`, `b` | a verifier-scoped path a≡b over `identity.bind` assertions and grounded EQUIVALENT edges from trust-listed asserters (reflexive) |
| `transparency_inclusion` | `log` (keyref) | a `transparency_receipt` is bound to a currently-valid `transparency.checkpoint` by `log` |
| `no_conflicting_evidence` | — | no conflict groups recorded |
| `vocabulary_accepted` | `ns`, `max_version` | every declaration of `ns` has version ≤ max AND `ns` is not used-while-undeclared-or-over-max (unused passes vacuously) |
| `evidence_usable` | `kind` | some evidence of kind has status AVAILABLE (strict counterpart to `evidence_present`) |
| `requires_reference` | `id` (`prf:v1:`, shape-checked at parse) | the direct composition linkage names `id` (what `proof_id` binds; transitive closure is the bundle layer) |
| `forbids_reference` | `id` (`prf:v1:`, shape-checked at parse) | the direct composition linkage omits `id` |

INDETERMINATE stays reserved for unevaluated policy (broken proof
preconditions), exactly like v1 — leaves evaluate boolean once the guard
passes. Canonical CBOR mirrors the JSON tree; content hashes read
`policy:v2:…` (v1 hashes unchanged).
