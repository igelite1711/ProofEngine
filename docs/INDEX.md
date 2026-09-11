# Documentation Index

Everything you need to understand, use, and contribute to Proof Engine.

## Start here

| Document | Who should read it |
|----------|-------------------|
| [README](../README.md) | Everyone — overview and quick start |
| [Architecture](../ARCHITECTURE.md) | How the engine works |
| [Extending](../EXTENDING.md) | Adding your own industry/domain |
| [Architecture Audit](../ARCHITECTURE-AUDIT.md) | As-built audit: what survives/changes |
| [Protocol Spec](../PROOF-ENGINE-SPEC.md) | Unified normative protocol |
| [Ecosystem Architecture](../ECOSYSTEM-ARCHITECTURE.md) | Target layering and boundaries |
| [Extension Model](../EXTENSION-MODEL.md) | How extensions enter without rewrites |
| [Cryptography](../CRYPTOGRAPHY.md) | Suites, agility, lifecycle |
| [Verification Model](../VERIFICATION-MODEL.md) | Stages, context, verdicts |
| [Policy Model](../POLICY-MODEL.md) | Decisions, conflicts, v2 path |
| [Compatibility](../COMPATIBILITY.md) | Versioning, migration, longevity |
| [Security Model](../SECURITY-MODEL.md) | Threats, mitigations, residuals |
| [Migration Plan](../MIGRATION-PLAN.md) | Sequenced P0–P12 transition |

## Using Proof Engine

| Document | What it covers |
|----------|----------------|
| [Format](../FORMAT.md) | How proofs are stored (file format) |
| [Policy](../POLICY.md) | Writing verification rules |
| [Lifecycle](../LIFECYCLE.md) | Proof states (active, expired, revoked) |
| [Trust](../TRUST.md) | How trust works |
| [Error Model](../ERROR-MODEL.md) | Error codes and meanings |
| [Versioning](../VERSIONING.md) | Version numbers and compatibility |
| [Interoperability](../INTEROPERABILITY.md) | Working with other implementations |

## For developers

| Document | What it covers |
|----------|----------------|
| [Crypto](../CRYPTO.md) | Signatures and algorithms |
| [Data Model](../DATA-MODEL.md) | Core data types |
| [Protocol](../PROTOCOL.md) | Protocol specification |
| [Longevity](LONGEVITY.md) | Long-term viability and migration |

## Security

| Document | What it covers |
|----------|----------------|
| [Threat Model](../THREAT-MODEL.md) | What attacks are considered |
| [Security](../SECURITY.md) | Guarantees and limitations |
| [Verification](../VERIFICATION.md) | How to verify a release |

## Contributing

| Document | What it covers |
|----------|----------------|
| [Contributing](../CONTRIBUTING.md) | How to contribute |
| [Changelog](../CHANGELOG.md) | What changed between versions |
| [Neutrality](NEUTRALITY.md) | Domain independence proof |

## Domain guides

| Document | What it covers |
|----------|----------------|
| [Payment](domains/payment.md) | Payment proofs |
| [Credential](domains/credential.md) | Credential proofs |
| [Media](domains/media.md) | Media/content proofs |
| [AI](domains/ai.md) | AI action proofs |
| Sensor / Logistics / Legal / Supply-chain / Health / Gov | Test-only journeys in `domains/proof-domains/tests/` (same core, same verdict shape; guides land with P12) |

## Technical details

| Document | What it covers |
|----------|----------------|
| [CDDL Schema](format.cddl) | Formal wire format definition |
| [Policy Grammar](policy-grammar.ebnf) | Formal policy language |
| [Standards References](standards-refs.md) | RFCs and standards used |
| [Requirements Matrix](requirements-matrix.md) | 69 traced requirements |
| [Capability Map](capability-map.md) | Feature overview |

---

**Reading order for newcomers:**
1. README (what is this?)
2. Architecture (how does it work?)
3. Extending (how do I use it for my domain?)
4. Policy (how do I write rules?)
