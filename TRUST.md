# Proof Engine — Trust Model (V1 draft — in development)

> V1 trust-model authority. Answers: who is trusted, why, where configured,
> how revoked, what happens when trust is unknown. Companion:
> THREAT-MODEL.md (attackers), SECURITY.md (guarantees); consolidated view
> `SECURITY-MODEL.md`. On semantics `PROOF-ENGINE-SPEC.md` §12 wins.

## Trust roots (all caller-supplied)

| Root | Configured in | Semantics |
|------|---------------|-----------|
| Issuer trust list | `EvalInputs.trusted_issuers` / CLI `--trusted` | `issuer_trusted` passes only if listed AND a signature-verified attestation by that issuer exists in the proof |
| Revocation authorities | `VerifyCtx.revocation_authorities` / CLI `--authority` | keys empowered to sign status objects over ANY target (in addition to each target's original issuer) |
| Revocation set (policy layer) | `EvalInputs.revocations` / CLI `--revoked` | defense-in-depth `not_revoked`; pipeline lifecycle is authoritative |
| Clock | `verified_at` + `skew_leeway` / CLI `--clock` (+ `--skew`) | trustworthy reading required; `0` = no clock → EXPIRED |
| Revocation freshness | `revocations_known_at` / CLI `--revocations-known-at` | missing/stale → UNKNOWN → fail closed |

## Rules

1. **Valid signature alone never yields trust** (PE-TRUST-001). The pipeline
   reports `signature_valid` as a fact; only the policy's `issuer_trusted`
   (list + presence) confers trust.
2. **Attacker `kid` never establishes trust** (PE-TRUST-002). The COSE `kid`
   is a lookup hint; the issuer is derived from the verifying key and must
   equal the payload issuer. Cross-type `kid` swaps fail on length/shape.
3. **Defaults fail closed** (PE-TRUST-003): zero clock, empty trust list,
   no status objects, unknown freshness — every default refuses.
4. **Status attestations are not statements** (PE-TRUST-004): revoke/
   supersede/withdraw/compromise objects never satisfy `issuer_trusted` and
   never contribute validity intervals, even when signed by a trusted key.
5. **Authority is per-target and explicit**: a status object applies only if
   its signer is the target's original issuer (or bound-attestation issuer
   for evidence withdrawal, or the target itself for compromise
   self-report) or a configured authority, the claim is well-formed, and it
   is not future-dated. Anything else → `UNAUTHORIZED_STATUS` (or
   `EXPIRED`/`SCHEMA_VIOLATION`) and never applies.
6. **Delegation never mints trust from nothing**: `delegated_authority`
   requires the named root in the trust list plus an active chain to a
   verified attestation. An unlisted root, an unknown issuer, a broken
   (expired/revoked/compromised) link, or a scope mismatch fails closed.
7. **Equivalence is verifier-scoped**: `identity.bind`/EQUIVALENT assertions
   count only from trust-listed asserters and merge nothing globally; the
   core is never tricked into substituting identities across trust domains.

## Unknown trust

Unknown issuer, unknown revocation state, unknown freshness, unknown clock:
every one fails closed with a stable code (`..._UNKNOWN`,
`REVOCATION_UNKNOWN`, `EXPIRED`). UNKNOWN is never converted to PASS at any
layer (pipeline, policy, or CLI exit mapping).

Traceability: PE-TRUST-001..004 (`docs/requirements-matrix.md`).

## Key lifetime (rotation) — caller-side, V1 (normative guidance)

V1 trust lists carry **bare key refs** — the engine has no per-key
valid-from/valid-until machinery, deliberately (current surface — in development). Rotation
semantics belong to the caller that already owns the two time inputs:

- **Constrain the trust list by evaluation time.** When verifying, supply only
  the roots that were authoritative *at `verified_at`*; for historical
  evaluation of pre-rotation proofs, supply the historical root (this is the
  same explicit-input pattern as revocations + `revocations_known_at`). A key
  that is "trusted now" is therefore never automatically "trusted at any past
  or future instant" — the caller answers that per evaluation.
- **Constrain it by policy when the distinction matters.** `issuer_trusted`
  requires list membership + a signature-verified attestation in this proof;
  pairing it with `not_expired` / `not_revoked` bounds how long an issued
  statement can keep counting after its issuing key is retired.
- **Never infer authority from key age or possession.** A rotated-out key in
  the list is exactly as powerful as a current one — which is why pruning the
  list per evaluation time is the V1 contract, and why first-class per-key
  validity intervals are a documented V2 capability row
  (`docs/capability-map.md`, CAP-105), not a silent gap.
