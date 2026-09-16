# Proof Engine — Core Neutrality (V1)

> Governing principle. This document is normative: every V1 feature is
> admitted to the core only if it survives the neutrality test below. The
> domain suites (`docs/domains/`, `domains/proof-domains/tests/`) exist to
> *prove* the principle by construction, not to claim it.

## 1. What neutrality means here

The core of Proof Engine is **industry-agnostic**: it does not know what a
claim is *about*. It answers one universal question:

> Given a claim about something that happened, exists, was authorized, was
> performed, or is supposed to be true — can I package the relevant evidence,
> establish its relationships and provenance, verify its integrity and
> authority, evaluate explicit rules against it, and explain the decision?

The same engine therefore works for payments, healthcare, identity, media,
AI, supply chains, education, software, government, insurance, scientific
research, IoT, compliance — **without knowing those industries exist**.

The engine cares about *structure*, never *semantics*:

```
CLAIM → EVIDENCE → ATTESTATION → RELATIONSHIPS → PROOF → VERIFICATION → POLICY → DECISION
```

Each hop is a mechanism. What fills the holes is supplied by the caller.

## 2. The boundary

The core (mechanism crates `proof-core`/`proof-format`/`proof-crypto`/
`proof-graph`/`proof-verify`/`proof-policy`) MUST contain only the neutral
primitives and their mechanics:

```
Entity   → Event, Attestation, Evidence, Relationship, Proof, Proposition
Identity → public keys, keyrefs, external identity references
Time     → event/observation/issuance/expiry/revocation/supersession/verification clocks
Status   → ACTIVE / EXPIRED / REVOKED / SUPERSEDED / COMPROMISED / UNKNOWN (fail closed on UNKNOWN)
Policy   → a closed, caller-supplied requirement language (never executed as code)
```

The core MUST NOT contain as fundamental types or hard-coded logic:

```
payment · invoice · merchant · patient · shipment · student · employee · loan
insurance · contract · vehicle · customer · media · deepfake · AI model · sensor telemetry
```

Domain words MAY appear only as (a) wire *vocabulary labels* in the
closed enums (`model.rs`), (b) test/fixture/demo material, or (c)
`docs/domains/` mappings. They MUST NOT appear as branches, filters, checks,
or policy logic in mechanism sources. This is enforced mechanically by
`tools/check_neutrality.py` (CAP-NEUT-001).

## 3. The neutrality tests (both mandatory)

Before any V1 feature is accepted into a mechanism crate, answer **both**:

> **Test 1 — the industry test.**
> Could this feature exist unchanged if Proof Engine were being used by a
> completely different industry tomorrow?

> **Test 2 — the core-stability test.**
> If we froze the entire core API today, could radically different systems
> (finance, healthcare, media, AI, global trade, forensics…) be built on top
> of it **without modifying the core** — that is, adding only domain tests,
> domain schemas/vocabularies above the boundary, and domain policies?

- **Yes to both** → it belongs in the core.
- **No to either** → it belongs in an application, a domain schema, a
  vocabulary, a policy, or the caller layer — never in the engine.

Test 1 guards the *shipping* boundary; Test 2 is the stronger, constructive
form: it treats the shipped API as immutable and demands that radically
different systems are *statically expressible* over it. A core that passes
Test 2 needs no feature-motivated churn to serve a new industry — interop
stability (VERSIONING.md) and neutrality are the same property. This is the
question the domain proof-suite (`PE-NEUT-003`) answers with running code,
not prose.

## 4. What the engine proves vs. what it does not

The engine establishes, as separate output dimensions (never collapsed):

| The engine establishes | It does NOT automatically establish |
|------------------------|-------------------------------------|
| Integrity (canonical bytes, digests) | Physical-world truth |
| Authenticity (valid signatures, key binding) | Honesty of an issuer |
| Structural validity (schema, references, graph) | Correctness of an observation |
| Attestation/signature validity | Legal or business legitimacy |
| Lifecycle state at the verifier clock | Human intent |
| Policy decision under *caller-supplied* rules | That a claim is genuinely true |

A valid signature is not trust; a trusted issuer is not truth; PASS under one
policy is not universal truth. These fences are the engine's integrity
(PE-NEUT-002, §5 of this doc; see also TRUST.md, THREAT-MODEL.md).

## 5. Neutrality requirements (traceable)

Machine-checked in `docs/requirements-matrix.md` (`PE-NEUT-*`) and enforced by
`make trace`, `make neutrality`, and CI:

| ID | Requirement |
|----|-------------|
| PE-NEUT-001 | No domain vocabulary in mechanism crate sources (grep gate) |
| PE-NEUT-002 | Valid signature / trusted issuer / PASS are never conflated |
| PE-NEUT-003 | Same core traversed by ≥3 unrelated domains (differential test) |
| PE-NEUT-004 | Domain vocabulary lives only in tests/fixtures/docs/demos |
| PE-NEUT-005 | A neutral capability spec + domain-mapping guide exist |

## 6. The thirteen domain journeys

See `docs/domains/` and `domains/proof-domains/tests/`. The same pipeline and
policy code — with zero domain branches — runs all thirteen:

1. **Payment** (reference) — settlement chain; the existing demo/goldens.
2. **Credential lifecycle** — issuance, verification, *expiry*, *supersession*,
   deny-list screening (identity domain).
3. **Media provenance** — licensing, deepfake-response, transcode chaining.
4. **AI-action provenance** — request → tool-call → attestation chain.
5. **Sensor calibration** — device registration, measurement, NIST-traceable
   calibration certificate.
6. **Logistics** — dispatch → custody → delivery chain.
7. **Legal** — draft → sign → authorization chain.
8. **Supply-chain / manufacturing** — batch production → shipment.
9. **Health** — clinical record provenance.
10. **Government** — permit/attestation workflow.
11. **Science** — experiment → independent replication with dataset backing.
12. **Cybersecurity** — alert → patch mitigation with vulnerability-report
    backing.
13. **Election** — ballot batch cast → counted → tally certified (three-event
    chain, pollbook evidence, `evidence_present` leaf).

The differential test (`PE-NEUT-003`) proves the engine's verdict shape is a
pure function of the artifacts' structure, identical across unrelated
industries. Neutrality is therefore *demonstrated by construction*, not
asserted in prose.
