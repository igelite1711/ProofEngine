# EXTENSION-MODEL.md — Proof Engine Extension & Layering Contract

> **Status:** Normative (2026-09-10). Companion to `PROOF-ENGINE-SPEC.md` (protocol),
> `ECOSYSTEM-ARCHITECTURE.md` (target shape), `MIGRATION-PLAN.md` (sequencing).
> Where this document conflicts with the unified spec on protocol semantics,
> the spec wins.
>
> Answers §50: how future algorithms, domains, policies, identity,
> transparency, privacy, composition, and infrastructure enter without
> rewriting the core.

---

## 1. Core stability rule

The core contains only concepts whose absence would make the universal proof
model fundamentally incomplete:

`Event / Attestation (+Status subtype) / Evidence / Relationship / Proof /
Proposition (value) / VerificationContext (value) / lifecycle / verification
stages / closed policy v1 / error taxonomy / limits / canonical CBOR / ids /
COSE profile`.

Everything else is a **profile, adapter, extension, or application**.
Admission to the core requires passing both neutrality tests
(`docs/NEUTRALITY.md` §3) AND the removal-half test (remove half the proposal;
if the universal model still works, the removed half stays out).

```
STABLE SEMANTICS + REPLACEABLE MECHANISMS   (required)
STABLE SEMANTICS + PERMANENT TECH ASSUMPTION (forbidden)
```

## 2. Extension kinds

| Kind | Examples | Versioning | May touch core bytes? |
|---|---|---|---|
| Cryptographic suite | new COSE alg, new hash, PQ hybrid | closed registry row, default-off | No (new numbers + keyrefs only) |
| Policy language | `policy_version:2` OR/NOT/threshold | new `policy_version` + capability row | No (v1 frozen) |
| Artifact container | `ArtifactEnvelope`, bundles | container v1, advisory fields | No (consumers re-derive ids) |
| Composition | `referenced_proofs` | proof schema v2 additive field | Yes, additive only (v1 parser untouched) |
| Transparency adapter | logs, TSAs, receipts | adapter version, differential both ways | No (consumes `EvidenceKind`) |
| Identity mechanism | PKI, VC, device attestation | mapping layer version | No (opaque `keyref`/reference strings) |
| Privacy mechanism | inline-capped content, redaction, ZK seams | capability row, digest still required | Additive (digest never weakened) |
| Storage / transport | FS, SQL, CA-store, queues, webhooks | `ArtifactStore`/`StatusSource` trait impl | No (core stays stateless/offline) |
| Domain profile | banking, health, AI, logistics vocab + policies | profile version, caller-side | No (open labels + policy) |

## 3. Capability rows

Every extension lands as a versioned row in `docs/capability-map.md`:
`CAP-xxx {status: DEF→IMP, layer, spec section, tests, vectors, migration note}`.
No row ⇒ not shipped. V1 rows stay frozen forever.

## 4. No-feature-envy gate (§47)

For every proposal answer: 1) problem? 2) universal? 3) core need? 4) outside
possible? 5) complexity? 6) what future does it block? 7) independently
verifiable? 8) removable? If 2/3/7 fail, it lives outside the core.

## 5. One-more-update test (§48)

Foreseeable 6-month surprises (new alg, new serialization, new identity,
new transparency, ZK, new policy language, new storage/transport, new
industry) must be addable via extension/profile/adapter/policy/suite/infra —
never foundational surgery. If not, redesign the boundary, not the core.
