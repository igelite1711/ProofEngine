# Proof Engine — Versioning and Compatibility (V1 draft — in development)

> V1 versioning authority (carriers, mismatch behavior). Long-term view indexed
> in `COMPATIBILITY.md`; on semantics `PROOF-ENGINE-SPEC.md` §16 wins.

## Version carriers (all `v == 1` in V1.0; anything else fails closed)

| Layer | Field | On mismatch |
|-------|-------|-------------|
| Event / Attestation / Evidence / Relationship / Proposition / Proof | `v` | `UNSUPPORTED_VERSION` (SCHEMA) |
| Object ids | `:v1:` infix | id parse rejects (PARSE) |
| Policy | `policy_version` | `UNSUPPORTED_VERSION` (POLICY) |
| HashRef | `v` | `SCHEMA_VIOLATION` |
| COSE algs | registry numbers | unknown → `UNKNOWN_ALGORITHM`; deprecated → `DEPRECATED_ALGORITHM` |

## Rules

1. Unknown versions fail closed — never interpreted under current rules
   (blocks silent semantic change and downgrade-by-stripping when the
   verifier pins `min_version` by rejecting non-1).
2. Requirement type strings are stable: `not_superseded` and siblings keep
   their names and AND-semantics; adding a type is a minor version,
   changing semantics is major.
3. Error-code wire strings are stable (ERROR-MODEL.md); renaming is major.
4. Id prefixes and the `proof_id` construction (sorted member sets,
   `created_at` excluded) are stable; changing binding is major.
5. Hash agility: new digest algorithms arrive via `HashRef.alg` enum + (see `docs/LONGEVITY.md` §3 for the full dual-verify migration contract) -
   object `v` bump with a dual-verify migration window; verifiers MUST NOT
   assume SHA-256 forever (FORMAT §2).
6. Canonical CBOR subset only ever shrinks (new rejections are safe);
   widening it is major (would fork identifier/signature agreement).
7. Fixture vectors are append-only: once a vector ships in a release its semantics never change; new behavior gets new vectors. During development faulty vectors may be regenerated under review. Golden-19 covers `not_superseded`; golden-20..23 cover text/byte normalization and P-256; golden-24..26 cover composition linkage; golden-27 covers vocabulary declarations; golden-28 covers conflict quorum; golden-29/30 cover withdrawal/compromise; golden-31 covers the newest frozen behavior.

## Compatibility promise

Artifacts written by any V1.x verifier verify on any V1.y verifier for
unchanged major version, given the same explicit inputs (clock, status
objects, trust lists, policy). Determinism (same bytes + same inputs →
same report, byte-for-byte) is enforced by tests and CI.
