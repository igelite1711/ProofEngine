# Proof Engine — Data Model (V1 draft — in development)

> Five persisted primitives. Everything else is a value object, an
> evaluation input, or an attestation subtype (Phase 0 ambiguity #1).

## Primitives

| # | Type | Id prefix | Signed? | Role |
|---|------|-----------|---------|------|
| 1 | Event | `evt:v1:` | No | happening-record: type, subject, effective_at, payload digest, metadata |
| 2 | Attestation | `att:v1:` | Yes (COSE_Sign1) | issuer-bound claim over a subject + validity window |
| 3 | Evidence | `evd:v1:` | No (id-bound) | digest-bound external reference + optional attestation ref |
| 4 | Relationship | `rel:v1:` | No (id-bound) | typed edge from→to + optional evidence/attestation refs |
| 5 | Proof | `prf:v1:` | No (binds member ids) | proposition + sorted member id sets + created_at (informational) |

Non-persisted roles: `Proposition` (value object: kind/subject/predicate/
object/at_time/context), `Policy` (evaluation input), status objects
(`claim.type` revoke/supersede attestation subtypes).

## Closed enums (unknown values rejected)

- `EventType` (7): `payment.created`, `payment.completed`, `invoice.issued`,
  `document.signed`, `package.shipped`, `sensor.measurement.recorded`,
  `ai.action.executed`.
- `EvidenceKind` (9): `signed_event`, `signed_document`, `receipt`,
  `credential`, `measurement`, `transaction_record`, `transparency_receipt`,
  `device_attestation`, `external_reference`.
- `RelType` (10): `OWNS`, `CREATED`, `SETTLES`, `REFERENCES`, `CONTAINS`,
  `PRODUCED`, `EXECUTED`, `ISSUED`, `SUPERSEDES`, `REVOKES`.
- Grounding required (trust-relevant): `OWNS`, `CREATED`, `SETTLES`,
  `EXECUTED` (PE-GRAPH-001). All others may ride bare (logged).
- `LifecycleStatus` (5): `ACTIVE`, `EXPIRED`, `REVOKED`, `SUPERSEDED`,
  `UNKNOWN` (see LIFECYCLE.md).
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
