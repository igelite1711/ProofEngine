# Proof Engine V1.0 — Protocol Specification

> **Status:** Draft — V1 in development.
> **Companion docs:** `ARCHITECTURE.md`, `FORMAT.md`, `POLICY.md`, `LONGEVITY.md`
> **CDDL schema:** `docs/format.cddl`

This document defines the Proof Engine V1.0 protocol completely. A reader
should be able to build a compatible verifier in any language without
reference to the Rust implementation.

---

## 1. Overview

Proof Engine is a domain-independent protocol for creating and verifying
digital proofs. A proof is a portable, self-contained package that carries
everything needed to verify a claim: signed attestations, supporting
evidence, and typed relationships.

**Design principles:**

- **Portable:** Proofs are bytes. No database, no network, no state.
- **Deterministic:** Same bytes + same inputs = same verdict.
- **Fail-closed:** Unknown algorithms, unknown versions, unknown states
  all reject loudly. Never silently trust.
- **Neutral:** The protocol carries any domain vocabulary. Policy decides
  what is acceptable. The core never judges content.

**What this is not:**

- Not a blockchain, not a distributed ledger, not a consensus protocol.
- Not a trust framework. Trust is caller-supplied.
- Not an API. It is a wire format and verification procedure.

---

## 2. Protocol Model

### 2.1 Primitives

Exactly five persisted objects:

| Primitive | Purpose | ID prefix |
|-----------|---------|-----------|
| **Event** | Something happened | `evt` |
| **Attestation** | Signed claim by an issuer | `att` |
| **Evidence** | Material supporting a claim | `evd` |
| **Relationship** | Typed directed edge | `rel` |
| **Proof** | Portable verification package | `prf` |

### 2.2 Value Objects

| Object | Purpose |
|--------|---------|
| **Proposition** | Machine-readable claim the proof establishes |
| **StoredAttestation** | Attestation content + COSE_Sign1 envelope |

### 2.3 Lifecycle States

Every attestation has exactly one lifecycle state, computed by the
verification pipeline:

| State | Meaning |
|-------|---------|
| `ACTIVE` | Within validity, no valid revocation/supersession |
| `EXPIRED` | Outside validity window at verifier clock |
| `REVOKED` | Covered by a valid signed revocation |
| `SUPERSEDED` | Replaced by a newer signed supersession |
| `UNKNOWN` | Revocation status cannot be determined (fail closed) |

### 2.4 Open Vocabularies

`EventType`, `EvidenceKind`, and `RelType` are open string wrappers. The
protocol transports any string. Well-known V1 constants exist for
convenience but are not exhaustive. Policy decides which types are
acceptable.

**Well-known Event types (non-exhaustive):**
`payment.created`, `payment.completed`, `invoice.issued`,
`document.signed`, `package.shipped`, `sensor.measurement.recorded`,
`ai.action.executed`

**Well-known Evidence kinds (non-exhaustive):**
`signed_event`, `signed_document`, `receipt`, `credential`,
`measurement`, `transaction_record`, `transparency_receipt`,
`device_attestation`, `external_reference`

**Well-known Relationship types (non-exhaustive):**
`OWNS`, `CREATED`, `SETTLES`, `REFERENCES`, `CONTAINS`, `PRODUCED`,
`EXECUTED`, `ISSUED`, `SUPERSEDES`, `REVOKES`

**Trust-relevant relationships** (require backing evidence or attestation):
`OWNS`, `CREATED`, `SETTLES`, `EXECUTED`

---

## 3. Wire Format

### 3.1 Canonical Encoding

All protocol objects are encoded as **CBOR deterministic encoding** per
RFC 8949 §4.1 + §4.2.1.

Rules:
- **Integers:** Shortest form. No bignums.
- **Maps:** Keys sorted bytewise lexicographic order of deterministic
  encoding. No duplicate keys.
- **Strings:** UTF-8 only. No indefinite lengths. `text != bytes`.
- **Time:** `uint` seconds since Unix epoch. No fractional, no timezone.
- **Allowed types:** `uint`, `nint`, `text`, `bytes`, `array`, `map`,
  `bool`, `null`. Floats, bignums, indefinite items, and all CBOR tags
  are forbidden.
- **Length caps:** 1 MiB proof, 64 KiB single field, depth 16, array 256
  items (configurable).

Canonicalization validation: verifier re-encodes parsed value and
byte-compares to input. Mismatch = `NON_CANONICAL`.

### 3.2 Hash Abstraction

```
HashRef = { "v": 1, "alg": <enum>, "digest": <bytes> }
```

| alg | Algorithm | Digest length |
|-----|-----------|---------------|
| 0 | SHA-256 | 32 bytes |
| 1 | SHA-384 | 48 bytes |

Digests are computed over **canonical CBOR bytes** of the referenced
object. Display form: `hash:v1,sha-256:<hex>`.

Unknown algorithms are rejected with `UNKNOWN_ALGORITHM`.

### 3.3 Object Schemas

All objects are CBOR maps. Unknown fields cause rejection.

#### EventContent

```cbor
{
  "v": 1,
  "event_type": tstr,
  "subject": tstr,
  "effective_at": uint,
  "payload_ref": HashRef,
  "metadata": {* tstr => tstr / uint / bool}
}
```

`metadata` max 16 entries, keys max 64 chars, no nested maps.

#### AttestationContent

```cbor
{
  "v": 1,
  "issuer": tstr,
  "subject": tstr,
  "claim": { "type": tstr, * tstr => tstr / uint / bool },
  "issued_at": uint,
  "expires_at": uint / null,
  "evidence_ref": tstr / null
}
```

`claim` max 16 entries. `expires_at` null = unbounded validity.

#### Evidence

```cbor
{
  "v": 1,
  "kind": tstr,
  "digest": HashRef,
  "attestation_ref": tstr / null,
  "hint": tstr / null
}
```

#### Relationship

```cbor
{
  "v": 1,
  "from": tstr,
  "type": tstr,
  "to": tstr,
  "evidence_ref": tstr / null,
  "attestation_ref": tstr / null
}
```

Trust-relevant types (`OWNS`, `CREATED`, `SETTLES`, `EXECUTED`) require
one of `evidence_ref` or `attestation_ref`. Bare edges are rejected with
`RELATIONSHIP_UNGROUNDED`.

#### Proposition

```cbor
{
  "v": 1,
  "kind": tstr,
  "subject": tstr,
  "predicate": tstr,
  "object": tstr / null,
  "at_time": uint / null,
  "context": {* tstr => tstr / uint / bool}
}
```

#### Proof

```cbor
{
  "v": 1,
  "proof_id": tstr,
  "proposition": Proposition,
  "events": [EventContent+],
  "attestations": [AttestationEntry+],
  "evidence": [Evidence+],
  "relationships": [Relationship+],
  "created_at": uint
}
```

`AttestationEntry = { "content": AttestationContent, "sign1": bstr }`.

Arrays sorted by ID at build time. All relationship endpoints and
evidence references must resolve to member IDs within the same Proof
(portability rule). External payload content stays outside — digests only.

#### Revocation / Supersession

Revocation and supersession are signed attestations (not deletions):

- **Revocation:** `claim.type = "revoke"`, `claim.target = <id>`,
  `claim.reason = tstr`
- **Supersession:** `claim.type = "supersede"`, `claim.old = <id>`,
  `claim.new = <id>`

Must be signed by original issuer OR a key in `revocation_authorities`.

---

## 4. Identifiers

All IDs are deterministic, versioned, and hash-derived. Never
auto-increment. Format: `<prefix>:v1:<b64uNoPad(sha256(bytes))>`.

### 4.1 Per-Object Derivation

| Object | Input to hash |
|--------|---------------|
| Event | All EventContent fields except `event_id` |
| Attestation | All AttestationContent fields except `attestation_id` and `signature` |
| Evidence | All Evidence fields except `evidence_id` |
| Relationship | All RelationshipContent fields (`from`, `type`, `to`, `evidence_ref`, `attestation_ref`) except `rel_id` |
| Proof | Canonical CBOR map `{"v":1, "proposition":<p>, "events":[sorted ids], "attestations":[sorted ids], "evidence":[sorted ids], "relationships":[sorted ids]}` |

`b64uNoPad` = RFC 4648 base64url without padding.

### 4.2 Rules

- Verifier recomputes every ID. Mismatch = `ID_MISMATCH` (primary tamper signal).
- Full SHA-256 digest (32 bytes, 43 base64url chars). No truncation.
- No normalization (NFC/NFD produce different IDs). Applications normalize
  before object creation.

### 4.3 Key References

- Ed25519: `key:ed25519:<b64u(raw_pubkey)>`
- P-256: `key:p256:<b64u(uncompressed_without_0x04)>`

---

## 5. Signatures

### 5.1 COSE_Sign1

All attestations are signed with **COSE_Sign1** (RFC 9052 §4.2),
stored untagged (CBOR tag 18 forbidden).

**Protected header** (closed, no extensions in V1):
```cbor
{ 1: alg, 4: kid }
```

- Label `1`: Algorithm identifier
- Label `4`: Key identifier (raw pubkey bytes)
- Label `6` (Partial IV): MUST NOT be used

**External AAD:** `h'504531'` (ASCII `"PE1"`)

### 5.2 Signing Input

Per RFC 9052 §4.4:
```
Sig_structure = [
  "Signature1",
  body_protected_bytes,
  external_aad = h'504531',
  canonical(AttestationContent)
]
```

### 5.3 Algorithm Registry

| COSE alg | Algorithm | Status |
|----------|-----------|--------|
| -19 | Ed25519 (RFC 8032) | **REQUIRED** |
| -9 | ECDSA P-256 (RFC 6979) | Optional, default-off |

Deprecated algorithms (-8 EdDSA, -7 ES256, -35, -36) are rejected with
`DEPRECATED_ALGORITHM`. Unknown algorithms are rejected with
`UNKNOWN_ALGORITHM`.

### 5.4 Verification Procedure

1. Parse and validate protected header (closed set)
2. Recompute attestation content ID
3. Rebuild `Sig_structure` exactly
4. Verify with stated algorithm and key
5. Check `issued_at` / `expires_at` separately (signature does not imply timeliness)

Key algorithm must match attestation algorithm. Mismatch = `ALGORITHM_CONFUSION`.

---

## 6. Verification Pipeline

An 11-check-stage pipeline (plus caller POLICY evaluation and FINAL emission) processes every proof. Each stage returns typed
errors and never repairs input. Order is fixed.

### 6.1 Stages

| # | Stage | Responsibility |
|---|-------|---------------|
| 1 | PARSE | CBOR decode, size/depth limits, UTF-8 validation, duplicate map key rejection |
| 2 | SCHEMA | Version check (`v == 1`), required fields, field types |
| 3 | CANONICAL | Re-encode deterministically, byte-compare to input |
| 4 | IDENTIFIERS | Recompute every ID from canonical bytes |
| 5 | SIGNATURES | COSE_Sign1 verify with stated algorithm |
| 6 | KEYS | Key well-formedness, algorithm match |
| 7 | TIME | `issued_at ≤ verified_at ≤ expires_at` (with clock skew leeway) |
| 8 | REVOCATION | Join against revocation set, compute lifecycle state |
| 9 | EVIDENCE | Digest recompute, external ref validation |
| 10 | RELATIONSHIPS | Endpoint resolution, backing evidence check |
| 11 | GRAPH | Acyclic (SUPERSEDES chain), depth/node/edge limits, no dangling refs |
| 12 | POLICY | Caller-evaluated (the pipeline reports INDETERMINATE; `proof-policy` evaluates separately) |
| 13 | FINAL | Emit output triple + explanation |

### 6.2 Fail-Closed Rule

Any `UNKNOWN` in crypto or evidence validity forces `policy_decision ∈
{FAIL, INDETERMINATE}`, never `PASS`. `PASS` requires all required checks
`valid`.

### 6.3 Output

The pipeline emits a triple:

```
{
  cryptographic_validity: Valid | Invalid,
  evidence_validity: Valid | Invalid,
  policy_decision: Pass | Fail | Indeterminate
}
```

Plus `explanation[]` (human-readable audit trail) and stable error codes.

---

## 7. Policy Language

### 7.1 Structure

```json
{
  "policy_version": 1,
  "policy_id": "<string>",
  "requirements": [ ... ]
}
```

- Implicit AND (no OR, no NOT, no expressions, no code).
- Unknown requirement types, unknown fields, empty lists, and
  non-positive versions are rejected with `POLICY_INVALID`.

### 7.2 Requirement Types (Closed Set)

| Type | Fields | Passes when |
|------|--------|-------------|
| `signature_valid` | — | Pipeline established cryptographic validity |
| `issuer_trusted` | `issuer` | Key is in trust list AND has a verified attestation in this proof |
| `issuer_excluded` | `issuer` | No verified attestation by this issuer exists (deny-list) |
| `relationship_exists` | `relationship` | A validated edge of that type exists |
| `not_expired` | — | All verified attestations satisfy issued/expires vs. verifier clock |
| `not_revoked` | — | No verified attestation ID appears in revocation set |
| `not_superseded` | — | No verified attestation is superseded by a valid signed supersession |
| `evidence_present` | `kind` | Evidence of that kind is present (digest-bound) |
| `transparency_present` | — | A `transparency_receipt` evidence item is present |
| `proof_fresh` | `max_age_seconds` | Proof's `created_at` is within max_age_seconds of verifier clock |

### 7.3 Decisions

| Decision | Meaning |
|----------|---------|
| **PASS** | Proof is valid (crypto + evidence) and every requirement passed |
| **FAIL** | Proof is valid but at least one requirement failed |
| **INDETERMINATE** | Proof itself is not valid; policy was not evaluated |

### 7.4 Trust Inputs

All trust inputs are **caller-supplied**. The engine holds no global state:

- Trusted issuer list (key references)
- Revocation set (attestation IDs)
- Verifier clock + clock skew leeway (default 300s)
- Revocations known at timestamp

Zero clock fails time requirements (fail-closed default).

### 7.5 Revocation Authority

Embed status attestations (revoke/supersede) can never satisfy
`issuer_trusted`. A revocation authority is not a statement issuer.

---

## 8. Error Codes

22 stable error codes. Human messages may change; codes must not.

| Code | Wire String |
|------|-------------|
| NonCanonical | `NON_CANONICAL` |
| DuplicateMapKey | `DUPLICATE_MAP_KEY` |
| ForbiddenCborConstruct | `FORBIDDEN_CBOR_CONSTRUCT` |
| IdMismatch | `ID_MISMATCH` |
| SignatureInvalid | `SIGNATURE_INVALID` |
| UnknownAlgorithm | `UNKNOWN_ALGORITHM` |
| DeprecatedAlgorithm | `DEPRECATED_ALGORITHM` |
| UnsupportedVersion | `UNSUPPORTED_VERSION` |
| LimitExceeded | `LIMIT_EXCEEDED` |
| Malformed | `MALFORMED` |
| InvalidBase64Url | `INVALID_BASE64URL` |
| UnexpectedHeaderParam | `UNEXPECTED_HEADER_PARAM` |
| AlgorithmConfusion | `ALGORITHM_CONFUSION` |
| SchemaViolation | `SCHEMA_VIOLATION` |
| RelationshipUngrounded | `RELATIONSHIP_UNGROUNDED` |
| DanglingReference | `DANGLING_REFERENCE` |
| CycleDetected | `CYCLE_DETECTED` |
| PolicyInvalid | `POLICY_INVALID` |
| Expired | `EXPIRED` |
| Revoked | `REVOKED` |
| RevocationUnknown | `REVOCATION_UNKNOWN` |
| UnauthorizedStatus | `UNAUTHORIZED_STATUS` |

---

## 9. Extension Mechanism

### 9.1 Domain Neutrality

The protocol core is **domain-independent**. It transports any vocabulary
string for `EventType`, `EvidenceKind`, and `RelType`. It never judges
content — only structure.

Policy decides which types are acceptable. A proof carrying
`healthcare.surgery.scheduled` passes the schema stage (the core
transports vocabulary) but may fail a policy that requires
`payment.created`.

### 9.2 Adding New Types

New domain types are added **without modifying the protocol**:
1. Producer creates objects with new vocabulary strings
2. Policy is configured to accept or reject those strings
3. Core protocol is unchanged

### 9.3 Versioning

Every object carries a `v` field. `v == 1` dispatches to V1 parser.
Unknown version = `UNSUPPORTED_VERSION` (fail closed). Canonicalization,
hash display, and policy language are each independently versioned.

---

## 10. Migration Contract

### 10.1 Hash Migration

Trigger: SHA-256 collision/preimage attack becomes credible.

Procedure:
1. Add new digest + new ID version (`evt:v2:`, `prf:v2:`, etc.)
2. **Dual-verify window:** verifiers accept `:v1:` and `:v2:` for a
   transition period
3. **Cutover:** major release retires `:v1:`
4. Unknown versions always fail closed

### 10.2 Signature Migration (Post-Quantum)

PQ algorithms enter the existing closed registry:
- New COSE algorithm number + new key-ref prefix (`key:ml-dsa-44:...`)
- Default off in every verifier
- **Hybrid bridge:** issuers sign with both classical and PQ keys
  (two attestations, two `issuer_trusted` requirements — existing
  AND-of-issuers semantics)

### 10.3 Determinism

Byte-level reproducibility built on deterministic signature schemes
(RFC 8032 Ed25519, RFC 6979 ECDSA). Randomized algorithms allowed only
as documented MAJOR changes.

---

## 11. Security Invariants

1. **Fail-closed defaults:** Unknown algorithms, versions, states all
   reject loudly. Never silently trust.
2. **No global state:** Trust list, revocation set, and clock are
   caller-supplied. Engine holds nothing between calls.
3. **Zero network I/O:** Verifier performs no external fetches during
   verification.
4. **Canonical round-trip:** Re-encoding a parsed object produces
   byte-identical output. Violation = `NON_CANONICAL`.
5. **ID binding:** Every ID is derived from canonical bytes. Tamper
   detection is primary verification.
6. **Signature covers content:** Signatures are over canonical CBOR bytes,
   not JSON, not display form.
7. **Revocation is signed:** Status objects (revoke/supersede) are
   attestations, not database mutations.

---

## 12. Golden Vectors

Golden vectors are normative for interoperability. Record shape:

```json
{
  "name": "<test case name>",
  "input_json": { ... },
  "canonical_hex": "<hex of canonical CBOR>",
  "object_id": "<computed ID>",
  "cose_sign1_hex": "<hex of COSE_Sign1 bytes>",
  "verify_ctx": { "clock": ..., "trusted_issuers": [...] },
  "expected": {
    "crypto_validity": "Valid|Invalid",
    "evidence_validity": "Valid|Invalid",
    "policy_decision": "Pass|Fail|Indeterminate",
    "codes": [...]
  }
}
```

At least one vector per negative error case. Vectors are in `fixtures/`
and validated by the independent Python verifier in `interop/`.

---

## 13. Companion Documents

| Document | Scope |
|----------|-------|
| `ARCHITECTURE.md` | Repository layout, API surface, design rationale |
| `FORMAT.md` | Detailed CBOR rules, CDDL schema reference, golden vector details |
| `POLICY.md` | Policy evaluation details, CLI usage, machine-readable output |
| `LONGEVITY.md` | Migration procedures, risk register, crypto-agility evidence |
| `docs/format.cddl` | Machine-readable CDDL schema (authoritative for wire format) |

If this document conflicts with a companion document, this document wins
for protocol semantics; the CDDL schema wins for wire format.
