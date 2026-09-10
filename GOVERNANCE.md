# GOVERNANCE.md — Protocol Governance

> This document defines how the Proof Engine protocol evolves, who decides
> what, and how external contributors participate. It is the social layer
> on top of the technical specification.

## 1. Protocol Ownership

The Proof Engine protocol is owned by the **Proof Engine Contributors**.
The reference implementation lives at `github.com/igelite1711/ProofEngine`.

- **V1 is in development.** Protocol semantics, wire format, ID construction, verification pipeline, lifecycle states, policy model, and error codes evolve on `main` via standard PRs (spec, code, tests, and golden vectors move together). When V1 freezes, §3.2–§3.3 PE-PROP gates apply from that point on.
- **V1.0 is not "owned" by any single person.** It is a published standard.
  The Contributors maintain it; they do not control it.

## 2. Roles

| Role | Authority | Responsibility |
|------|-----------|----------------|
| **Protocol Author** | Final say on protocol changes | Maintains spec integrity, resolves disputes |
| **Maintainer** | Review and merge code changes | Enforce quality standards, CI requirements |
| **Contributor** | Propose changes via PE-PROP | Submit PRs, build adapters, report issues |
| **Implementer** | Build independent implementations | Prove the protocol is language-independent |

Anyone can be a Contributor. Anyone can be an Implementer. Maintainership
is earned through sustained, high-quality contributions.

## 3. Change Categories

### 3.1 Changes during development

Any change — bug fixes, docs, or protocol semantics — lands via standard PR → review → merge, provided spec, code, tests, and golden vectors move together. No PE-PROP required while V1 is in development.

### 3.2 Future Protocol Extensions

New optional features that are backward compatible.

Process: standard PR while V1 is in development (see §4 for the process
that applies once V1 is released).

### 3.3 Future Breaking Changes

Changes to wire format, ID construction, or verification semantics that
break backward compatibility.

Process: standard PR with the same evidence while V1 is in development
(see §4 for the process that applies once V1 is released).

## 4. The PE-PROP Process (applies once V1 is released)

A PE-PROP (Proof Engine Proposal) will be the mechanism for protocol changes
after release. During development, §3.1 applies instead.

### 4.1 Structure

Each PE-PROP is a markdown file `PE-PROP-NNN.md` in `docs/pe-props/`
containing:

```markdown
# PE-PROP-NNN: <title>

## Summary
One paragraph: what changes and why.

## Motivation
Why is this needed? What problem does it solve?

## Detailed Design
Complete specification of the change.

## Compatibility
Is this backward compatible? Migration path?

## Alternatives Considered
What else was considered and why it was rejected.

## Implementations
Which independent implementations support this? (Required for V1.1+/V2.0)
```

### 4.2 Lifecycle

```
Propose → Discuss (30 days min) → Implementability check → Author decision → Merge/Reject/Defer
```

1. **Propose:** Open a GitHub issue or PR with the PE-PROP.
2. **Discuss:** Minimum 30 days of public discussion. Anyone can comment.
3. **Implementability check:** For backward-compatible changes, at least 2 independent
   implementations must express support. For breaking changes, they must demonstrate
   working code.
4. **Author decision:** The Protocol Author accepts, rejects, or defers.
   All decisions are documented with rationale.
5. **Merge:** Accepted PE-PROPs are merged into the spec and reference
   implementation.

### 4.3 Emergency Patches

If a security vulnerability is discovered in the reference implementation
(not the protocol itself), the Author may expedite a patch with a 7-day
discussion window. The vulnerability must be disclosed after the patch
is released.

## 5. Consensus Model

Proof Engine uses **consensus-first decision making**, not voting.

- **Goal:** Find a proposal that everyone can live with, even if it's
  not their first choice.
- **Process:** Discuss until objections are addressed or acknowledged.
- **Escalation:** If consensus fails, the Author decides with a written
  rationale that is permanently recorded in the PE-PROP.
- **Reversal:** An Author decision can be reversed only if 2/3 of active
  Maintainers agree and a new PE-PROP demonstrates the reversal is correct.

There are no formal votes. "Consensus" means no one has a sustained,
unaddressed objection.

## 6. Versioning Rules

Proof Engine follows **semantic versioning** for the protocol:

| Change | Version bump | Example |
|--------|-------------|---------|
| Wire format break | MAJOR | V1 → V2 |
| New optional feature | MINOR | V1.0 → V1.1 |
| Bug fix / documentation | PATCH | V1.0.0 → V1.0.1 |

(The V1.0.x numbers above illustrate the scheme; no release cut yet.)

**Important distinctions:**

- **Protocol version** (V1): the wire format, semantics, and verification rules.
- **Crate version** (e.g. 1.x.y): the Rust reference implementation.
- **These are independent.** The crate can be at 1.3.7 while the protocol is still at V1.1.

## 7. External Contributions

### 7.1 Domain Adapters

Anyone can build a domain adapter. The `domains/` directory demonstrates
this with 5 independent industries. To add your domain:

1. Create a test file in `domains/proof-domains/tests/`
2. Follow the pattern: vocabulary + journey builder + policy + inputs
3. Verify it passes the differential tests
4. Submit a PR

Domain adapters **should not** require changes to the core. If your
domain needs a new primitive, open an issue — that's a protocol change, not an adapter.

### 7.2 Independent Implementations

Independent implementations are the **primary signal** of protocol health.
They are more valuable than any test suite.

If you build an independent verifier in another language:

1. Open an issue announcing it
2. Run it against the golden vectors in `fixtures/`
3. Report results (pass/fail + details)
4. Your implementation is listed in `README.md` as a verified implementation

### 7.3 Golden Vectors

Golden vectors in `fixtures/` are normative for interoperability. If a
change adds features, it must include corresponding golden vectors.
Vectors are generated by self-checking generators in `crates/*/examples/`.

## 8. Conflict Resolution

### 8.1 Implementation Disagreement

If two implementations produce different results for the same input:

1. Check the spec (`SPEC.md` and `FORMAT.md`)
2. If the spec is unambiguous, the conforming implementation is correct
3. If the spec is ambiguous, the Author issues a clarification
4. The clarification is recorded in the spec and changelog

**The spec is authoritative, not the reference implementation.**
The reference implementation may have bugs. The spec defines truth.

### 8.2 Disputed Changes

If the community disagrees on a proposal:

1. Discuss for minimum 30 days
2. If no consensus, the Author decides
3. The decision and rationale are recorded
4. Dissenters may fork (the license allows it)

### 8.3 Scope Disputes

If someone proposes a change that others consider out of scope:

1. Ask: "Does this require modifying the core?"
2. If yes: it's a protocol change (standard PR with spec+tests+vectors)
3. If no: it's an adapter or tool (standard PR)

## 9. Transparency

All of the following are public:

- All proposals and decisions with rationale
- All discussions (GitHub issues and discussions)
- All test results (CI is public)
- All golden vectors and test generators

There are no private channels for protocol decisions. If it's not public,
it's not official.

## 10. What This Governance Does NOT Cover

- **Trademark usage:** Controlled separately (see `TRADEMARK.md` if it exists)
- **Security vulnerabilities:** Reported privately via `SECURITY.md`
- **Crate publishing:** A technical process, not a governance decision
- **Domain-specific vocabularies:** Not governed — anyone can define their own
- **Business decisions:** The protocol is neutral; business strategy is not
  a governance concern

---

**This governance model evolves with the project.**
Changes to governance require the same consensus and documentation as
protocol changes.
