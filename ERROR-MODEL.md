# Proof Engine — Error Model (V1 draft — in development)

> 22 stable wire strings. Codes are part of the protocol: renaming or
> renumbering is a breaking change (see VERSIONING.md). Every failure is
> recorded with stage + object + code + message; failures are never repaired
> downstream and unknown is never converted into valid.

## Fail-closed rules

1. Every `Err` from parsing/decoding surfaces as a report failure or a
   caller error — never a silent PASS.
2. An `Invalid` verdict always carries ≥1 code (machine-checked by fuzz
   `proof_verify` and soak asserts).
3. Early exit (PARSE/SCHEMA/CANONICAL failure) reports `evidence_validity:
   invalid` — no vacuous Valid (PE-VERIFY-011).
4. CLI maps verdicts to exit 1 and usage/engine errors to exit 2; codes are
   identical in both paths (PE-CLI-001).

## Code table (stage = where first recorded)

| Code | Stage | Meaning |
|------|-------|---------|
| `NON_CANONICAL` | CANONICAL | re-encoded bytes differ from input |
| `DUPLICATE_MAP_KEY` | PARSE | repeated CBOR map key |
| `FORBIDDEN_CBOR_CONSTRUCT` | PARSE | float, tag, indefinite length, bignum, reserved ai |
| `ID_MISMATCH` | IDENTIFIERS | recomputed id ≠ stated id (tamper evidence) |
| `SIGNATURE_INVALID` | SIGNATURES | COSE verify failed or issuer ≠ envelope key |
| `UNKNOWN_ALGORITHM` | SIGNATURES | COSE alg unknown to this verifier |
| `DEPRECATED_ALGORITHM` | SIGNATURES | known but deprecated (-8/-7/-35/-36) |
| `UNSUPPORTED_VERSION` | SCHEMA | object/proof/policy version ≠ 1 |
| `LIMIT_EXCEEDED` | PARSE/SCHEMA/GRAPH | size/depth/entries/items bound hit |
| `MALFORMED` | PARSE | truncated input, trailing bytes, bad UTF-8 |
| `INVALID_BASE64URL` | PARSE | id component not valid base64url |
| `UNEXPECTED_HEADER_PARAM` | KEYS | COSE header label/value outside {1,4} |
| `ALGORITHM_CONFUSION` | KEYS | key shape does not match attestation alg |
| `SCHEMA_VIOLATION` | SCHEMA | unknown variant/field, missing field, closed-set breach |
| `RELATIONSHIP_UNGROUNDED` | RELATIONSHIPS | trust-relevant edge lacks backing evidence |
| `DANGLING_REFERENCE` | RELATIONSHIPS/EVIDENCE | endpoint/reference resolves to nothing |
| `CYCLE_DETECTED` | GRAPH | SUPERSEDES subgraph cyclic/branching/too deep |
| `POLICY_INVALID` | POLICY | policy rejected before evaluation (never partial) |
| `EXPIRED` | TIME | outside validity window at verifier clock |
| `REVOKED` | REVOCATION | covered by a valid signed revocation |
| `REVOCATION_UNKNOWN` | REVOCATION | no/stale revocation info (fail closed) |
| `UNAUTHORIZED_STATUS` | REVOCATION | status signer has no authority over target |

One-to-one with `proof-core/src/error.rs` (checked by audit; keep in sync —
renaming is breaking).
