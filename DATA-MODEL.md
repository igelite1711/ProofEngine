# Proof Engine — Data Model (V1 draft — in development)

> V1 data-model authority (primitives, value objects, references). On protocol
> semantics `PROOF-ENGINE-SPEC.md` §3 wins.
> Five persisted primitives. Everything else is a value object, an
> evaluation input, or an attestation subtype (Phase 0 ambiguity #1).

## Primitives

| # | Type | Id prefix | Signed? | Role |
|---|------|-----------|---------|------|
| 1 | Event | `evt:v1:` | No | happening-record: type, subject, effective_at, payload digest, metadata |
| 2 | Attestation | `att:v1:` | Yes (COSE_Sign1) | issuer-bound claim over a subject + validity window |
| 3 | Evidence | `evd:v1:` | No (id-bound) | digest-bound external reference + optional attestation ref |
| 4 | Relationship | `rel:v1:` | No (id-bound) | typed edge from→to + optional evidence/attestation refs |
| 5 | Proof | `prf:v1:` | No (binds member ids) | proposition + sorted member id sets + optional `referenced_proofs` linkage + optional `vocabularies` declarations + created_at (informational) |

Non-persisted roles: `Proposition` (value object: kind/subject/predicate/
object/at_time/context), `Policy` (evaluation input), status objects
(`claim.type` revoke/supersede/withdraw/compromise attestation subtypes).

## Open vocabularies, closed fields

Types are open strings transported verbatim (neutrality); well-known labels
below carry pinned semantics. Unknown *fields* are rejected (fail closed).

- `EventType` well-known: `payment.created`, `payment.completed`,
  `invoice.issued`, `document.signed`, `package.shipped`,
  `sensor.measurement.recorded`, `ai.action.executed`, …
- `EvidenceKind` well-known: `signed_event`, `signed_document`, `receipt`,
  `credential`, `measurement`, `transaction_record`, `transparency_receipt`,
  `transparency_registration`, `transparency_checkpoint`,
  `device_attestation`, `external_reference`, …
- `RelType` well-known: `OWNS`, `CREATED`, `SETTLES`, `REFERENCES`,
  `CONTAINS`, `PRODUCED`, `EXECUTED`, `ISSUED`, `SUPERSEDES`, `REVOKES`,
  `EQUIVALENT`, `CONTRADICTS`, …
- Grounding required (trust-relevant): `OWNS`, `CREATED`, `SETTLES`,
  `EXECUTED`, `EQUIVALENT`, `CONTRADICTS` (PE-GRAPH-001). All others may
  ride bare (logged). Callers may declare additional trust-relevant kinds
  without a core change (`validate_graph_with_grounding`).
- `LifecycleStatus` (6): `ACTIVE`, `EXPIRED`, `REVOKED`, `SUPERSEDED`,
  `COMPROMISED`, `UNKNOWN` (see LIFECYCLE.md). Precedence:
  `COMPROMISED > REVOKED > SUPERSEDED > EXPIRED > UNKNOWN > ACTIVE`.
- `EvidenceStatus` (8, derived per evidence item): `AVAILABLE`,
  `WITHDRAWN`, `COMPROMISED`, `REVOKED`, `SUPERSEDED`, `EXPIRED`,
  `UNKNOWN`, `UNAVAILABLE` (adapter-reported only).
- Reserved claim types: `revoke`, `supersede`, `withdraw`, `compromise`
  (status, lifecycle-affecting); `delegate`, `identity.bind`,
  `transparency.checkpoint` (statement conventions, policy-projected);
  reserved field `denies` (opposition). All other claim types are plain
  statements.
- `MetaValue` (claim/metadata scalars): text, uint, bool only.

## Object rules (enforced)

- All objects carry `v: 1`; any other version → `UNSUPPORTED_VERSION`.
- Closed field sets: unknown fields → `SCHEMA_VIOLATION`.
- Self-edges (`from == to`) rejected.
- Relationship `relationship_id` covers both `evidence_ref` and
  `attestation_ref` (binding fix, Phase 3).
- `created_at` on Proof is informational and NOT covered by `proof_id`
  (FORMAT §3; pinned by soak tests both directions).
- Timestamps are uint Unix seconds; `expires_at` may be nil (unbounded).

Traceability: PE-FMT-008, PE-GRAPH-001, PE-LIFE-001
(`docs/requirements-matrix.md`).
