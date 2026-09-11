# ECOSYSTEM-ARCHITECTURE.md — Proof Engine Target Architecture

> **Status:** Target architecture (2026-09-10). Defines the final shape into
> which the audited V1 (`ARCHITECTURE-AUDIT.md`) evolves. Implementation
> sequencing and gates are in `MIGRATION-PLAN.md`; the normative protocol is
> `PROOF-ENGINE-SPEC.md`. This document is the answer to "what should Proof
> Engine be" from first principles.
>
> Governing priority order (unchanged): **correctness → security →
> neutrality → verifiability → interoperability → determinism →
> extensibility → privacy → developer experience → operational scale.**
> Feature count is never an objective.

---

## 1. Design goals and non-goals

**Goal:** a smallest universal foundation from which extremely powerful proof
systems can be built — portable, neutral, independently verifiable, survivable
across changes in technology, organizations, industries, cryptography, and
trust models.

**Non-goals (hard):** Proof Engine will not require a central server, a
blockchain, a token, Proof-Engine-owned identity, a Proof-Engine-owned trust
registry, a mandatory hosted SaaS, banking logic, AI licensing, royalties,
crypto-economics, NFT semantics, healthcare/government workflows, or any
single-vendor cloud. These belong in profiles, adapters, or applications.

**The architect's compass — one question per feature:**

> Does this make the universal proof model **stronger**, or merely make one
> application more **convenient**?
> If it only makes an application more convenient, it stays outside the core.

## 2. Layered architecture

```
┌───────────────────────────────────────────────┐
│              APPLICATIONS                     │
│   banks / AI / logistics / software / health  │
└───────────────────┬───────────────────────────┘
                    │  consume verdicts, facts, policies
┌───────────────────▼───────────────────────────┐
│        DOMAIN PROFILES / ADAPTERS             │
│   C2PA · W3C VC · SCITT · X.509/PKI · logs ·  │
│   device attestation · signed HTTP · events   │
└───────────────────┬───────────────────────────┘
                    │  normalized, mapped, differential-tested
┌───────────────────▼───────────────────────────┐
│        INTEGRATION / API / SDK                │
│   reference API · Rust/TS/Python/Go · CLI ·   │
│   ingestion · batch · web reference UI        │
└───────────────────┬───────────────────────────┘
                    │  same spec, same vectors
┌───────────────────▼───────────────────────────┐
│            PROOF ENGINE CORE                  │
│  Event/Evidence/Attestation/Relationship/Proof│
│  canonicalization · crypto · identifiers      │
│  verification · context · lifecycle · policy  │
└───────────────────┬───────────────────────────┘
                    │  facts in, context in, verdicts out
┌───────────────────▼───────────────────────────┐
│         EXTERNAL TRUST SYSTEMS                │
│  PKI · VCs · C2PA · SCITT · transparency logs │
└───────────────────────────────────────────────┘
```

**Layering rules (strict):**

1. Each layer may depend only on layers below. The core depends on nothing
   but its own crates and the audited cryptography stack.
2. The core is the **smallest and most stable** layer; every versioned change
   to it requires a capability row + migration note (change control, §13).
3. Nothing above the core may redefine core semantics; nothing in the core
   may require any layer above.
4. Adapters translate **in and out** and are verified by differential tests
   in both directions — an adapter that only "reads" is half an adapter.

## 3. Core boundary and admission rules

The core is the audited V1 surface: canonical CBOR, content-derived ids,
COSE_Sign1 profile, five primitives + two value objects, lifecycle state
machine, closed policy interface, error taxonomy, limits. Admission to the
core requires passing **both** neutrality tests (industry test + core-stability
test, `NEUTRALITY.md` §3) AND the removal-half test (§10.1). Everything else
is a profile, adapter, or application.

Explicitly admitted core responsibilities:

- representation of facts (claims, evidence, attestations, relationships,
  proofs) with deterministic, versioned, content-addressed integrity;
- verification of structure, cryptography, evidence, lifecycle, and
  policy-under-caller-context;
- explanation that is a pure projection of state;
- migration machinery (algorithm/hash/version) that never rewrites history;
- fail-closed, resource-bounded, offline-first behavior.

## 4. What must never enter the core (rejected layer-1 features)

| Rejected | Reason |
|---|---|
| Banking logic, payment rails, settlements | §35 economics stay outside; the engine may prove `ownership/authorization/transaction`, never be the payment system |
| AI/creator royalties, licensing semantics | domain-specific meaning → domain profile/policy |
| Tokens, staking, slashing, consensus | §2 non-goals |
| NF T/oracle semantics | domain meaning |
| Proof-Engine identity / DID system | §22: identifiers and external identity mechanisms only |
| Proof-Engine trust score | §36: trust is contextual, per verifier |
| HSM/keystore integration | host security, caller-side |
| Storage/DB/service implementations | §37: interfaces only |
| Networking | §38: adapters only |
| ZK as a default | §23: mechanism when the problem demands it, never a mandate |

## 5. Verification context as a first-class object

The single most architecturally important idea after the model itself: **a
proof contains facts; the verifier supplies context.** The consolidated
`VerificationContext` (`PROOF-ENGINE-SPEC.md` §14) replaces the v1
`VerifyCtx`/`EvalInputs` split (AUDIT F6) and gains (v2, additive):
`min_version`, jurisdictions, security profile, trust anchors, transparency
requirements. Context is echoed, never stored, and never trusted. Historical
validity vs current acceptance is a *report* distinction computed from
context — not a property rewritten into history.

## 6. Interoperability model (integrate, don't replace)

Adapter interface contract for an external standard S:

1. `S → model`: parse S bytes, map to Events/Attestations/Evidence/
   Relationships/Proofs, preserving a cryptographic binding that survives
   the mapping (digest of canonical S bytes in a mapped Evidence item).
2. `model → S`: reverse path with the same binding so round-trips are
   detectably faithful (differential tests, both directions).
3. Unmappable constructs must fail with a stable code, never approximate.

| Standard | Adapter responsibility (V2 rows) |
|---|---|
| C2PA | manifest → evidence/attestation mapping; claim binding |
| W3C Verifiable Credentials | VC/VP → attestation+evidence; key binding |
| SCITT | signed statements/receipts → attestation; transparency receipts → evidence |
| X.509 / PKI | certificate chains → trust anchors + issuer evidence |
| Transparency logs (CT-style / sigstore) | inclusion/consistency proofs → evidence; receipts |
| Device attestation (TPM/Android/iOS) | attestation statements → evidence+attestation |
| Signed HTTP records / webhooks | request signatures → event evidence |
| Enterprise event systems | normalized events → Event + batch proofs |

Core neutrality is preserved: adapters live in their own crates, consume the
public core API, and are exercised by the domain-suite harness — exactly like
`domains/proof-domains` today.

## 7. Integration layer

**Reference API (V2).** A thin HTTP/async boundary around the same core; an
*interface, never a trust root*. Capabilities mirror the lifecycle:
`create-event, submit-evidence, attest, build-proof, verify, evaluate,
explain, inspect, retrieve-referenced-evidence`. The API MUST support
synchronous verification and asynchronous jobs, idempotency, streaming,
webhooks, pagination, structured errors, stable versions, authN/Z, rate
limits, and audit logs — and MUST never make a proof valid merely because the
API returned "valid" (verification is always re-derived from bytes + context).

**SDK strategy.** Priority: Rust (native), TypeScript, Python, Go. SDKs bind
to this specification + golden vectors; they MUST NOT reimplement semantics —
they compile to the same canonical bytes and verify against the same
test-vector corpus. The existing `interop/` Python package is the seed for
the Python SDK's verification core.

**CLI (exceptional reference implementation).** Already strong (23 commands,
0/1/2 contract, JSON, stdin/stdout, completion). Extend toward the full
mental model (`proof create/attest/evidence/relate/build/verify/evaluate/
inspect/explain/export/import/convert/doctor`) keeping: human-readable by
default, stable JSON for automation, deterministic output, stable exit codes,
machine-readable errors, shell completion, examples. The CLI is the laboratory
for the architecture, not the architecture.

**Reference UI (V2).** The offline browser demo (`demo/web/index.html`) is
the seed. Evolve it to visualize Claim → Evidence → Attestation →
Relationships → Proof → Verification → Policy Decision with the provenance
graph and per-dimension verdicts. It must stay runnable locally, offline,
with no account, no server, no telemetry.

## 8. Ingestion and scale

**Event-driven ingestion (V2, outside the core).** Generic ingestion layer:
ExistingSystem → Adapter → normalization → evidence creation → attestation →
relations → proof builder → proof store → verification/policy. Adapters may
consume APIs, webhooks, queues, event streams, files, databases, logs, and
signed messages — none of which may redefine core semantics.

**Proof granularities (V2):** event evidence ⇄ transaction proof ⇄ batch
proof ⇄ aggregate/checkpoint ⇄ portable external proof. Batching and
cryptographic aggregation must not compromise independent verification —
a batch proof still reduces to per-member verifiable elements with digests.

## 9. Storage and networking neutrality

Storage = interfaces, never implementations: filesystem, object storage, SQL,
document stores, content-addressed stores, external repositories — behind one
`ArtifactStore` interface; no database in the core. Networking = adapters:
the semantic core is offline-capable, embedded, server-side, on-premises, and
browser-ready; network services are separate layers that can only feed the
core through caller code.

## 10. The five architectural tests (applied at every phase gate)

### 10.1 Remove-half test
Remove half the proposed features at design time. If the core is not weaker,
those features don't belong in the core. Re-run at every proposal review.

### 10.2 100-year test
For every core decision answer three questions:
1. Could an independent engineer in 2126 understand what this object meant?
2. Could a verifier reproduce its historical cryptographic interpretation?
3. Could current policy reject obsolete cryptography **without rewriting
   history**?
The V1 format (self-describing, versioned, deterministic, documented,
cross-implemented) already passes; the test becomes a gate for every future
change.

### 10.3 No-internet test
Take a proof, disconnect the machine, delete every Proof Engine server, hand
the bytes to an independent verifier. If its meaning and cryptographic
integrity cannot be established, explain exactly why — or redesign. V1 passes
(the interop package verifies offline); bundles must preserve this.

### 10.4 No-Proof-Engine-trust test
A skeptical third party verifies without trusting Proof Engine because the
protocol spec + vectors + independent implementation are the authority. The
engine never says "trust this because Proof Engine says so". V1 passes; the
accompanying property is that neither the API nor the UI may ever add a trust
shortcut.

### 10.5 Ten-domains test
Represent meaningful workflows across **at least ten** unrelated domains —
landed as twelve journeys in `domains/proof-domains/tests/` (payment,
credential, media, AI, sensor, logistics, legal, supply-chain/manufacturing,
health, government, science, cybersecurity), all traversing the same core
with zero domain-specific modification. If the core ever requires
domain-specific modification, document why; repeated core modifications are
evidence the abstraction is wrong. The domain suite
(`domains/proof-domains`) remains the harness for every future industry.

## 11. Proof lifecycle (target state)

```
OBJECT / EVENT ── CLAIM ── EVIDENCE ── ATTESTATION ── RELATIONSHIPS ── PROOF
    │                │         │            │               │            │
    ▼                ▼         ▼            ▼               ▼            ▼
 independent verifier + verification context + policy
    │
    ▼
 dimensioned report: structural / cryptographic / evidence / provenance /
 temporal / revocation / policy / overall   (each VALID | INVALID |
 INDETERMINATE | NOT_APPLICABLE) + lifecycle + explanation
    │
    ▼
 another system acts on the result. Proof Engine owns the machinery, not the
 truth, identity, trust, economics, or domain.
```

Lifecycle responsibilities by layer:

- **Producers** create Events, sign Attestations, bind Evidence, express
  Relationships, assemble Proofs (and v2: compose them).
- **The core** verifies and explains; it never adjudicates.
- **The verifier/caller** supplies context, chooses policy, decides what to do.
- **Status/registry services** (V2: transparency logs, StatusSource) feed the
  verifier with signed inputs it still re-verifies.

## 12. Definition of Done (mapped to the program §59)

| Area | Done when |
|---|---|
| Protocol | consolidated spec (`PROOF-ENGINE-SPEC.md`) normative; canonical format frozen; versioning + compatibility rules enforced; artifact container standardized (§15) |
| Core | universal model coherent (open vocabularies, §3); domain neutrality demonstrated (12 journeys); deterministic serialization; cryptographic agility; composition semantics (§7); provenance graph traversal APIs |
| Verification | dimensioned verdicts; contextual, partial (`NOT_APPLICABLE`), historical/current distinction; explainable; one-shot `verify+decide` |
| Security | SECURITY-MODEL.md register green (T1–T18); fuzz on every parser surface; adversarial matrices; supply-chain controls (SBOM/signed releases/provenance); no-panic grep gate; resource limits enforced |
| Interoperability | adapters (C2PA/VC/SCITT/PKI/logs) with differential tests both directions; offline verification; container interop across Rust/TS/Python/Go |
| Integration | reference API; SDKs (Rust/TS/Python/Go) bound to vectors; ingestion + batch; observability for services with privacy-preserving logs |
| DX | CLI meets §31 contract; reference UI offline; docs excellent; golden-vector corpus comprehensive |
| Neutrality | ≥10 radically different domains in the proof-suite, zero core modifications |

## 13. Change control and governance of the architecture

- **Versioned capability rows** (`docs/capability-map.md`) are the only route
  for new behavior; a row notes IMP/DOC/PRT/DEF + evidence.
- **Core changes** require: neutrality tests (§3), remove-half test (§10.1),
  100-year review (§10.2), a capability row, a migration note, and golden
  vector updates (append-only).
- **Dual-verify windows** for hash/signature/format migration
  (`LONGEVITY.md`) — never a silent cutover.
- **Doc-code sync** remains a release gate (VERIFICATION.md rule): any
  conflict between this document family and code is a defect, not an opinion.
- **The five tests (§10) are re-run at every phase gate** in MIGRATION-PLAN.

---

*Companions: `ARCHITECTURE-AUDIT.md` (as-built state), `PROOF-ENGINE-SPEC.md`
(normative protocol), `SECURITY-MODEL.md` (threats), `MIGRATION-PLAN.md`
(sequenced transition).*