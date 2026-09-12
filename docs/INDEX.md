# Documentation Index

One map for all 35 documents. **Authority rule:** on protocol semantics
`PROOF-ENGINE-SPEC.md` wins; on wire bytes `docs/format.cddl` wins.
`SPEC.md` is the historical full-text draft (kept, not extended).

## Start here

| Document | Authority | Who should read it |
|----------|-----------|-------------------|
| [README](../README.md) | Overview (spec wins on conflict) | Everyone — overview and quick start |
| [Architecture](../ARCHITECTURE.md) | As-built implementation guide | How the engine works |
| [Extending](../EXTENDING.md) | Domain-extension how-to | Adding your own industry/domain |
| [Architecture Audit](../ARCHITECTURE-AUDIT.md) | Point-in-time audit (2026-09-10) | As-built audit: what survives/changes |
| [Architecture Freeze](../ARCHITECTURE-FREEZE.md) | Frozen foundation (PE-FREEZE-001) | What is frozen and why |
| [Protocol Spec](../PROOF-ENGINE-SPEC.md) | **Protocol authority** | Unified normative protocol |
| [Full-text draft](../SPEC.md) | Historical (superseded where it differs) | Historical V1.0 text |
| [Ecosystem Architecture](../ECOSYSTEM-ARCHITECTURE.md) | Target layering | Target layering and boundaries |
| [Extension Model](../EXTENSION-MODEL.md) | Extension intake | How extensions enter without rewrites |
| [Cryptography](../CRYPTOGRAPHY.md) | Normative sub-reference (§§5–6) | Suites, agility, lifecycle |
| [Verification Model](../VERIFICATION-MODEL.md) | Normative sub-reference (§§9–11,14) | Stages, context, verdicts |
| [Policy Model](../POLICY-MODEL.md) | Normative sub-reference (§12) | Decisions, conflicts, v2 path |
| [Compatibility](../COMPATIBILITY.md) | Normative consolidation | Versioning, migration, longevity |
| [Security Model](../SECURITY-MODEL.md) | Consolidated (supersedes/extends threat model) | Threats, mitigations, residuals |
| [Migration Plan](../MIGRATION-PLAN.md) | Plan for review | Sequenced P0–P12 transition |

## Using Proof Engine

| Document | Authority | What it covers |
|----------|-----------|----------------|
| [Format](../FORMAT.md) | Wire-format authority (with CDDL) | How proofs are stored (file format) |
| [Crypto](../CRYPTO.md) | V1 wire details (agility → Cryptography) | Signatures and algorithms |
| [Data Model](../DATA-MODEL.md) | V1 data-model authority (§3) | Core data types |
| [Protocol](../PROTOCOL.md) | Normative index (not the authority) | Protocol specification |
| [Policy](../POLICY.md) | V1 language authority (future → Policy Model) | Writing verification rules |
| [Lifecycle](../LIFECYCLE.md) | V1 lifecycle authority (§§10–11) | Proof states (active, expired, revoked) |
| [Trust](../TRUST.md) | V1 trust-model authority (§12) | How trust works |
| [Error Model](../ERROR-MODEL.md) | V1 code authority (§13) | Error codes and meanings |
| [Versioning](../VERSIONING.md) | V1 versioning authority (§16) | Version numbers and compatibility |
| [Interoperability](../INTEROPERABILITY.md) | V1 interop authority (§17) | Working with other implementations |
| [Longevity](LONGEVITY.md) | Migration contract | Long-term viability and migration |

## Security

| Document | Authority | What it covers |
|----------|-----------|----------------|
| [Threat Model](../THREAT-MODEL.md) | V1.0 attackers (consolidated view → Security Model) | What attacks are considered |
| [Security](../SECURITY.md) | V1 guarantees (consolidated view → Security Model) | Guarantees and limitations |
| [Verification](../VERIFICATION.md) | Checkout/release how-to (stages → Verification Model) | How to verify a release |
| [Audit Brief](THIRD-PARTY-AUDIT-BRIEF.md) | Commissioning pack (no external review yet) | Scope + evidence for auditors |

## Contributing

| Document | Authority | What it covers |
|----------|-----------|----------------|
| [Contributing](../CONTRIBUTING.md) | Process | How to contribute |
| [Changelog](../CHANGELOG.md) | Record | What changed between versions |
| [Neutrality](NEUTRALITY.md) | Domain independence proof | Domain independence proof |
| [Governance](../GOVERNANCE.md) | Social layer | Protocol governance |
| [Release](../RELEASE.md) | Release gate | V1 release checklist |

## Domain guides

| Document | What it covers |
|----------|----------------|
| [Payment](domains/payment.md) | Payment proofs |
| [Credential](domains/credential.md) | Credential proofs |
| [Media](domains/media.md) | Media/content proofs |
| [AI](domains/ai.md) | AI action proofs |
| [Sensor](domains/sensor.md) | Sensor calibration proofs |
| [Logistics](domains/logistics.md) | Chain-of-custody proofs |
| [Legal](domains/legal.md) | Document execution proofs |
| [Supply-chain](domains/supplychain.md) | Batch production proofs |
| [Health](domains/health.md) | Consent-gated record proofs |
| [Gov](domains/gov.md) | Permit workflow proofs |
| [Science](domains/science.md) | Replication proofs |
| [Cyber](domains/cyber.md) | Incident response proofs |

## Technical details

| Document | Authority | What it covers |
|----------|-----------|----------------|
| [CDDL Schema](format.cddl) | **Wire-bytes authority** | Formal wire format definition |
| [Policy Grammar](policy-grammar.ebnf) | Policy language authority | Formal policy language |
| [Standards References](standards-refs.md) | Anchors | RFCs and standards used |
| [Requirements Matrix](requirements-matrix.md) | Traceability (90 ids, CI-checked) | Traced requirements |
| [Capability Map](capability-map.md) | Feature overview | Feature overview |

---

**Reading order for newcomers:**
1. README (what is this?)
2. Architecture (how does it work?)
3. Extending (how do I use it for my domain?)
4. Policy (how do I write rules?)
