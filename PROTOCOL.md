# Proof Engine — Protocol Overview (V1 draft — in development)

> Normative index for the V1 protocol (not the protocol authority itself:
> `PROOF-ENGINE-SPEC.md` wins on semantics, `docs/format.cddl` on wire bytes).
> Every statement here describes implemented behavior; each section points to
> the authoritative document, the code, and the tests
> (`docs/requirements-matrix.md` maps PE-xxx ids).

## Core invariant

> Cryptographic validity, evidence validity, currentness, authority, and
> policy compliance are distinct concepts and MUST NOT be silently conflated.

The pipeline reports the first three as separate outputs (`VerifyReport`:
`cryptographic_validity`, `evidence_validity`, per-attestation lifecycle)
plus feed health `status_inputs_valid` (STATUS-stage hygiene, never validity);
the policy engine turns them into a decision only under caller-supplied
requirements (notably `not_superseded` for currentness). See POLICY.md,
LIFECYCLE.md.

## Terminology (current — in development)

| Term | Meaning | Must not be confused with |
|------|---------|---------------------------|
| Event | Unsigned happening-record (only claim of occurrence) | Authenticated truth |
| Attestation | Issuer-signed claim over a subject | Proof of real-world truth |
| Evidence | Digest-bound external reference | Fetched/stored content |
| Relationship | Typed directed edge between member ids | Trust (needs grounding + policy) |
| Proof | Canonical container binding member id sets + proposition | Trust decision |
| Proposition | Value object stating what the proof is about | A persisted primitive |
| Status object | Signed revoke/supersede attestation subtype | An unsigned id list |
| Policy | Caller-supplied evaluation input (8 closed requirement types) | Engine behavior |
| Report | Pipeline output: validities + codes + lifecycle | Decision (policy output) |

## Document map

```text
PROTOCOL.md        this index + caller contracts (below)
DATA-MODEL.md      objects, fields, closed enums, id prefixes
FORMAT.md          wire bytes: CBOR subset, schemas, COSE, base64url
CRYPTO.md          algorithms, keys, hashes, domain separation
TRUST.md           who is trusted, issuer resolution, defaults
LIFECYCLE.md       states × validity/currentness/freshness, clocks, authority
POLICY.md          requirement types, decisions, trust inputs
ERROR-MODEL.md     24 stable codes, stage mapping, fail-closed rules
VERSIONING.md      v=1 rules, agility, compatibility promise
INTEROPERABILITY.md I1/I2/I3, golden vectors, second-verifier recipe
THREAT-MODEL.md    attackers, threats, mitigations, residuals
SECURITY.md        guarantees, non-guarantees, disclosure
VERIFICATION.md    how to check a checkout or release
```

## Caller contracts (normative)

These are protocol obligations on the verifier application, not engine
internals. Violating them produces garbage-in/garbage-out verdicts; the
engine cannot detect the violation.

1. **Clock.** All time checks use caller-supplied `verified_at` (+ skew
   leeway, default 300 s). `0` means "no trustworthy clock" → everything
   EXPIRED. The engine never reads a wall clock (PE-CLI-003).
2. **Revocation information.** The engine evaluates only status objects the
   caller supplies, as of caller-asserted `revocations_known_at`. Missing or
   stale info → `REVOCATION_UNKNOWN` → fail closed (PE-LIFE-004).
3. **Replay state.** The engine is stateless: it verifies integrity and
   bindings, never seen-ness. Replay-sensitive callers MUST keep a seen-set
   of `event_id`/`proof_id` per binding context, express validity windows
   via `issued_at`/`expires_at`, and carry binding context (nonce,
   transaction id, challenge) in claim fields or metadata. Re-presenting a
   valid proof is *expected* to verify; treating it as a *new* event without
   caller bookkeeping is caller misuse, not an engine PASS (Gate H).
4. **Storage.** No storage adapters exist in the V1 core. Persistence, transport encryption,
   and access control belong to the caller (artifacts are digest-only for
   external content; payloads stay outside the proof).
5. **Trust lists.** Policy trust (`trusted_issuers`, `revocation_authorities`)
   comes from the caller. A valid signature alone never confers trust
   (PE-TRUST-001).

## Second-verifier rule

An independent engineer with ONLY this document set plus `fixtures/` MUST be
able to reimplement id computation and signature verification and agree with
the engine on every golden vector (INTEROPERABILITY.md gives the recipe;
`interop/` proves it both directions).
