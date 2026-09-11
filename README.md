<img width="1254" height="1254" alt="file_00000000a9548211a34607705ea8a597" src="https://github.com/user-attachments/assets/2d7f1358-533f-4a83-97fd-a24fb0f64927" />
// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

# Proof Engine

[![CI](https://github.com/igelite1711/ProofEngine/actions/workflows/ci.yml/badge.svg)](https://github.com/igelite1711/ProofEngine/actions/workflows/ci.yml)
[![Interop](https://github.com/igelite1711/ProofEngine/actions/workflows/interop.yml/badge.svg)](https://github.com/igelite1711/ProofEngine/actions/workflows/interop.yml)
[![Fuzz](https://github.com/igelite1711/ProofEngine/actions/workflows/fuzz.yml/badge.svg)](https://github.com/igelite1711/ProofEngine/actions/workflows/fuzz.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

**V1 in development · 4 fuzz targets · 10 industries · 2 independent implementations (Ed25519 + P-256) · 26 golden vectors**

---

**Proof Engine** is a neutral, portable, independently verifiable proof infrastructure for representing claims, evidence, attestations, provenance, relationships, and policy-based decisions.

It is **not** a payment system, identity system, blockchain, database, or application framework.

It is a **protocol-level foundation** that applications and industries can build upon.

---

## Contents

| Section | What you'll find |
|---------|-----------------|
| [The Problem](#the-problem) | Why Proof Engine exists |
| [Core Model](#core-model) | The verification pipeline |
| [Five Primitives](#the-five-core-primitives) | Event, Attestation, Evidence, Relationship, Proof |
| [Verification](#verification) | The 11-stage deterministic pipeline |
| [Policy](#policy) | Caller-supplied trust decisions |
| [Neutral by Design](#neutral-by-design) | 10 industries, zero core changes |
| [Quick Start](#quick-start) | Get running in 30 seconds |
| [For Developers](#for-developers) | Cargo dependency + code example |
| [Repository](#repository) | 7 focused crates |
| [Specification](#specification) | Authoritative protocol docs |

---

## The Problem

Digital systems generate enormous numbers of claims:

- something happened;
- someone authorized something;
- a document was signed;
- a measurement was recorded;
- an artifact was produced;
- an action was performed;
- an event occurred at a particular time;
- one object is related to another;
- an earlier assertion was revoked or superseded.

The problem is that these claims are frequently trapped inside databases, APIs, organizations, and proprietary systems.

A verifier may be forced to ask:

> "Why should I believe this?"

Proof Engine provides a machine-verifiable answer:

> "Here is the claim, here is the evidence, here is its provenance, here are the relationships, here are the attestations, and here is exactly how the proof was verified."

---

## Core Model

Proof Engine separates five fundamental concepts:

```
              CLAIM / PROPOSITION
                       │
                       ▼
                    EVIDENCE
                       │
                       ▼
                  ATTESTATION
                       │
                       ▼
                 RELATIONSHIPS
                       │
                       ▼
                     PROOF
                       │
                       ▼
                 VERIFICATION
                       │
                       ▼
                    POLICY
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
           PASS      FAIL     UNKNOWN
```

The protocol deliberately separates:

**Cryptographic validity** ≠ **Evidence validity** ≠ **Issuer authority** ≠ **Policy acceptance** ≠ **Application decision**

A cryptographically valid statement is not automatically a trusted statement.

A trusted statement is not automatically acceptable under every policy.

A valid historical statement is not necessarily currently applicable.

These distinctions are fundamental to Proof Engine.

---

## The Five Core Primitives

### 1. Event

An Event represents something that happened or was recorded.

Examples include:

- `document.created`
- `measurement.recorded`
- `artifact.produced`
- `action.executed`
- `transaction.completed`

The protocol does not require a particular industry or event vocabulary.

Applications define their own domain vocabulary on top of the neutral model.

### 2. Attestation

An Attestation is a signed assertion made by an issuer.

It allows a system to represent:

> "Issuer X attests to proposition Y."

The cryptographic signature establishes integrity and authorship according to the applicable verification rules.

It does not, by itself, establish that the issuer should be trusted.

### 3. Evidence

Evidence supports a claim.

Evidence may represent or reference things such as:

- signed records;
- documents;
- measurements;
- receipts;
- credentials;
- transaction records;
- device attestations;
- transparency records;
- external references.

Proof Engine does not assume that one evidence type is universally authoritative.

Evidence is evaluated within an explicit verification and policy context.

### 4. Relationship

Relationships connect objects and events into a typed proof graph.

For example:

```
A ──CREATED──► B
B ──REFERENCES──► C
C ──SUPERSEDES──► D
```

Relationships allow a proof to represent not only isolated facts, but the structure and provenance surrounding those facts.

### 5. Proof

A Proof is the portable verification object.

Conceptually:

```
Proof
├── Proposition
├── Events
├── Evidence
├── Attestations
├── Relationships
├── Requirements
└── Verification context / metadata
```

A Proof can therefore travel independently of the system that originally produced it.

---

## Verification

Proof Engine is designed around deterministic verification.

A verifier should be able to take a Proof and determine, according to the applicable rules:

```
Can it be parsed?
        ↓
Is its structure valid?
        ↓
Is its serialization canonical?
        ↓
Are its identifiers correct?
        ↓
Are signatures valid?
        ↓
Are issuers authoritative?
        ↓
Is the evidence valid?
        ↓
Are relationships consistent?
        ↓
Are lifecycle rules satisfied?
        ↓
Does the supplied policy accept it?
```

Verification results are explicit.

A verifier must not silently convert uncertainty into trust.

---

## Policy

Proof Engine does not define universal trust.

Instead, the caller supplies explicit requirements.

Conceptually:

```
PROOF
  +
POLICY
  =
DECISION
```

Different verifiers can therefore evaluate the same Proof differently without changing the underlying Proof.

For example:

**Policy A:**
- signature valid
- issuer trusted
- evidence present

→ **PASS**

**Policy B:**
- signature valid
- issuer trusted
- evidence present
- current status required
- transparency required

→ **FAIL**

The Proof itself has not changed.

The decision policy has.

This separation is intentional.

---

## Historical Validity vs Current Trust

Proof Engine preserves an important distinction between:

- **Was this assertion valid?**
- **Should I rely on this assertion now?**

An attestation can remain historically verifiable while being:

- revoked;
- expired;
- superseded;
- outside the current policy;
- associated with an issuer that is no longer trusted.

This allows Proof Engine to represent history without confusing historical truth with present applicability.

---

## Neutral by Design

Proof Engine is deliberately industry-neutral.

The core does **not** belong to:

- finance;
- healthcare;
- government;
- artificial intelligence;
- logistics;
- identity;
- legal systems;
- software supply chains;
- manufacturing;
- science.

Those are **applications** of the protocol.

**The proof:** 10 radically different industries traverse the same core, producing identical verdict shapes. The differential tests in `domains/proof-domains/` prove this:

| Domain | Industry | What it proves |
|--------|----------|----------------|
| Payment | Financial | Invoice → Payment → Settlement with transaction record evidence |
| Credential | Identity | Credential grant → Issuance → Revocation lifecycle |
| Media | Content | Work → License → Rights with license certificate evidence |
| AI | Software | Request → Tool call → Execution with training log evidence |
| **Sensor** | **Physical** | Device → Calibration → Measurement with calibration certificate evidence |
| Logistics | Transport | Dispatch → Delivery with receipt evidence |
| Legal | Law | Draft → Signature with execution record |
| Supply-chain | Manufacturing | Batch → Shipment with production record |
| Health | Healthcare | Record → Consent with consent receipt |
| Gov | Government | Application → Permit with issuance record |

All 10 use the **same** builder, **same** 11-stage pipeline, **same** policy engine. The verdict shape is a pure function of artifact structure, never of domain vocabulary.

The core remains the same.

---

## Architecture

Proof Engine is organized as a layered system.

```
┌─────────────────────────────────────────────┐
│                Applications                 │
├─────────────────────────────────────────────┤
│       Domain Schemas / Vocabularies         │
├─────────────────────────────────────────────┤
│        Adapters / Integrations / SDKs        │
├─────────────────────────────────────────────┤
│              Proof Engine API               │
├─────────────────────────────────────────────┤
│      Proof / Graph / Policy / Verify        │
├─────────────────────────────────────────────┤
│        Format / Serialization / Crypto       │
└─────────────────────────────────────────────┘
```

The lower layers remain generic.

Domain-specific behavior belongs above the neutral protocol boundary.

---

## Cryptography

Proof Engine uses established cryptographic standards rather than inventing cryptography.

The cryptographic layer is intentionally separated from the semantic proof model.

This allows the protocol to distinguish:

```
Proof semantics
    │
    ├── Cryptographic suite A
    ├── Cryptographic suite B
    └── Future cryptographic suites
```

The protocol therefore does not depend on the assumption that one cryptographic algorithm will remain secure forever.

Historical proofs remain precisely defined according to their original cryptographic context, while future verification policies can evolve.

Cryptographic agility is a protocol requirement, not an afterthought.

---

## Determinism

Proof Engine is designed for deterministic representation and verification.

Equivalent logical objects must have precisely defined representations.

This enables:

- reproducibility;
- stable identifiers;
- content addressing;
- golden vectors;
- independent implementations;
- cross-language verification;
- reliable tamper detection.

A Proof should **not** depend on:

- database ordering;
- network location;
- implementation-specific serialization;
- local machine state;
- hidden mutable state.

---

## Independence

A central design goal is:

> "A verifier should not need to trust the system that created the Proof."

The verifier should be able to independently examine the Proof and its supporting material according to the applicable rules.

**This is not theoretical.** An independent Python verifier (`interop/pengine.py`) implements the full verification pipeline from the specification alone — no Rust imports, stdlib-only. It verifies golden vectors produced by the Rust implementation and creates proofs that the Rust CLI verifies.

The ultimate interoperability test is therefore:

```
Implementation A (Rust)     Implementation B (Python)
       │                            │
       │ creates                     │ creates
       ▼                            ▼
     Proof  ◄── same spec ──►     Proof
       │                            │
       │ verifies                   │ verifies
       ▼                            ▼
   VERIFIED                      VERIFIED
```

The implementations do not share a codebase. They agree on the protocol.

---

## Security Philosophy

Proof Engine follows several fundamental security principles:

**Fail closed** — Invalid or unverifiable material must not silently become trusted.

**Explicit trust** — Trust must come from explicit policy and authority configuration.

**No implicit authority** — Possessing a key identifier or transport location does not automatically establish authority.

**Separation of concerns** — Cryptographic validity, evidence validity, authority, and policy acceptance remain distinct.

**Deterministic verification** — The same Proof and verification context should produce the same result.

**Adversarial testing** — The system must be tested against malformed, modified, contradictory, replayed, unauthorized, expired, revoked, and superseded material.

---

## What Proof Engine Is Not

Proof Engine is intentionally **not**:

- a blockchain;
- a cryptocurrency;
- a token;
- a consensus protocol;
- a database;
- a payment network;
- a wallet;
- an identity provider;
- a certificate authority;
- a custom cryptographic system;
- a universal trust authority;
- an application-specific workflow engine;
- an AI decision-maker.

Proof Engine provides **infrastructure for proofs**.

Applications decide how that infrastructure is used.

---

## Current V1 Boundary

V1 defines the core protocol and its verification model.

The following belong **outside** the immutable core unless explicitly defined by the protocol:

- industry-specific schemas;
- application workflows;
- databases;
- HTTP services;
- cloud infrastructure;
- key-management platforms;
- domain-specific vocabularies;
- industry-specific policies;
- user interfaces;
- business logic.

This boundary protects neutrality and long-term stability.

---

## V1 Design Principle

The most important architectural test is:

> "Could this feature exist unchanged if Proof Engine were used by a completely different industry tomorrow?"

If yes, it may belong in the neutral core.

If no, it should normally be implemented as:

```
Schema → Vocabulary → Adapter → Integration → Policy → Application
```

rather than modifying the core.

---

## Repository

The repository is organized into focused crates:

```
proof-core       Domain types, error codes, limits, hash/id value objects
proof-format     Canonical CBOR encode/decode, schema validation
proof-crypto     Hash abstraction, COSE_Sign1 sign/verify, key types
proof-graph      Typed DAG validation, cycle/depth checks
proof-verify     Staged verification pipeline and error codes
proof-policy     Policy schema, validator, deterministic evaluator
proof-cli        Command-line interface
```

Each layer has a defined responsibility, allowing the protocol to remain understandable, testable, and independently verifiable.

---

## Verification and Testing

V1 is designed to be verified rather than trusted by assertion.

The verification strategy includes:

- unit tests;
- integration tests;
- property-based testing;
- fuzz testing;
- golden vectors;
- tamper testing;
- negative-path testing;
- deterministic verification;
- independent verification (Python interop);
- cross-implementation interoperability;
- clean-build verification;
- dependency/security review.

The goal is not merely:

> "The tests pass."

The goal is:

> "An adversary should have difficulty making an invalid claim appear valid."

---

## Long-Term Compatibility

Proof Engine distinguishes between what should remain stable and what must be allowed to evolve.

**Stable:**
- proof semantics;
- core primitives;
- verification model;
- canonical representation rules;
- identifiers;
- compatibility principles;
- security boundaries.

**Evolvable:**
- cryptographic algorithms;
- implementations;
- SDKs;
- adapters;
- domain vocabularies;
- infrastructure;
- policies;
- transport mechanisms.

The objective is not to freeze every technology forever.

The objective is to preserve the meaning of a Proof while allowing the surrounding ecosystem to evolve.

---

## Documentation

All docs are in the [docs index](docs/INDEX.md). The most important ones:

| Document | What it covers |
|----------|----------------|
| [SPEC.md](SPEC.md) | Protocol specification (authoritative) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design and repository layout |
| [FORMAT.md](FORMAT.md) | Wire format details |
| [POLICY.md](POLICY.md) | Policy language |
| [LONGEVITY.md](docs/LONGEVITY.md) | Migration contract |
| [GOVERNANCE.md](GOVERNANCE.md) | Protocol governance |
| [RELEASE.md](RELEASE.md) | V1 release checklist and gate |

---

## Quick Start

**Prerequisites:** [Rust](https://rustup.rs/) (stable), `make`, `python3` (optional, for interop validation)

```bash
git clone https://github.com/igelite1711/ProofEngine.git
cd ProofEngine
make demo
```

Run `make help` to see all available commands.

### Command Reference

| Command | What it does |
|---------|-------------|
| `make demo` | Run the full demo (create → verify → tamper → fail → revoke → fail) |
| `make test` | Run all workspace tests |
| `make install` | Install `proof-cli` to `~/.cargo/bin` |
| `make help` | Show all available commands |
| `make neutrality` | Verify no domain vocabulary in mechanism sources |
| `make trace` | Verify requirement traceability matrix |
| `make domain-tests` | Run all 10 industry domain differential tests |

### CLI Commands (V1.1)

| Command | What it does |
|---------|-------------|
| `proof-cli verify` | Verify a proof (positional path or stdin with `-`) |
| `proof-cli evaluate` | Verify a proof and evaluate a policy |
| `proof-cli explain` | Explain a verification result (requires `--policy`) |
| `proof-cli inspect` | Inspect a proof (read-only, no trust decisions) |
| `proof-cli graph` | Visualize proof relationships (text/dot/mermaid) |
| `proof-cli export` | Export an artifact to the standard envelope (validated) |
| `proof-cli import` | Import a standard envelope (validated) |
| `proof-cli convert` | Normalize a legacy artifact file idempotently |
| `proof-cli compose` | Compose proofs by union of members (linkage recorded) |
| `proof-cli withdraw` | Withdraw reliance on an artifact (history preserved) |
| `proof-cli compromise` | Mark an identity compromised from an instant (taints) |
| `proof-cli doctor` | Diagnose the local environment |
| `proof-cli version` | Show version information |
| `proof-cli completion` | Print shell completion (bash/zsh/fish/powershell) |
| `proof-cli help <command>` | Per-command help (or `<command> --help`) |
| `proof-cli demo` | Run the end-to-end demonstration (`--interactive` for the guided 60-second tour: build → verify → policy → tamper → revoke → supersede → second domain) |
| `make web-demo` | Generate the browser demo (`demo/web/index.html`; every verdict computed by the real CLI) |
| `make web-check` | Honesty gate: fail if page data differs from fresh core output |
| `make web-serve` | Serve the browser demo locally (static files, no app server) |

**Short flag aliases:** `-o` (out), `-q` (quiet), `-j` (json), `-p` (proof),
`-c` (clock), `-k` (skew), `-s` (subject), `-t` (type)

**Output contract:** `verify` prints the machine-readable JSON report on
stdout and a human summary (✓/✗ per stage, RESULT) on stderr. Colors are
used only on terminals and honor `NO_COLOR`. `--quiet` silences all
nonessential stderr, including `loaded …` progress notes.

**Streaming:** `--proof -` reads a proof from stdin; `--out -` writes an
artifact or report to stdout (`proof-cli build … --out - | proof-cli verify
--proof - --clock …`).

**Field order:** `--claim`/`--meta`/`--context` pairs are canonicalized
automatically — `--claim b=1,a=2` and `--claim a=2,b=1` produce identical
bytes.

**Using proof-cli directly:**

```bash
# After make install, or use: cargo run -p proof-cli --
PAYLOAD=$(python3 -c "print('ab'*32)")

proof-cli create-event --type payment.created --subject payment:p1 \
    --effective-at 1700000000 --payload-hex $PAYLOAD --out ev1.json
# → event evt:v1:… -> ev1.json (use this id below, not the bare label)

proof-cli attest --seed test --subject payment:p1 --claim-type payment.settled \
    --claim amount=4200 --issued-at 1700000150 --out att.json
# → attest att:v1:… (issuer key:ed25519:…) -> att.json (copy the issuer!)

# Grounding evidence (digest of the payload above) + invoice event, so the
# SETTLES edge below resolves to proof members (bare labels never resolve).
DIGEST=$(python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$PAYLOAD')).hexdigest())")
ATT=$(python3 -c "import json; print(json.load(open('att.json'))['id'])")
proof-cli add-evidence --kind transaction_record --digest-hex $DIGEST \
    --attestation-ref $ATT --out evd.json
proof-cli create-event --type invoice.issued --subject invoice:i9 \
    --effective-at 1700000000 --payload-hex $(python3 -c "print('cd'*32)") --out inv1.json

# --from/--to/--object take artifact ids (evt:v1:…), NOT bare labels.
EVT=$(python3 -c "import json; print(json.load(open('ev1.json'))['id'])")
INV=$(python3 -c "import json; print(json.load(open('inv1.json'))['id'])")
EVD=$(python3 -c "import json; print(json.load(open('evd.json'))['id'])")
proof-cli relate --from $EVT --type SETTLES --to $INV \
    --evidence-ref $EVD --attestation-ref $ATT --out rel.json

proof-cli build --kind payment.settles-invoice --subject $EVT \
    --predicate settles --object $INV --at-time 1700000150 \
    --created-at 1700000200 --events ev1.json,inv1.json --attestations att.json \
    --evidence evd.json --relationships rel.json --out proof.json

# --revocations-known-at is required for a PASS: without it lifecycle is
# UNKNOWN and verify fails closed (exit 1) with a hint.
proof-cli verify --proof proof.json --clock 1700000300 --revocations-known-at 1700000300

# Policy: copy examples/policies/settlement.json, replace ONLY the suffix
# after `key:ed25519:` with the issuer from `attest` above (prefix exactly once).
ISSUER=$(python3 -c "import json; print(json.load(open('att.json'))['issuer'])")
python3 -c "import json; p=json.load(open('examples/policies/settlement.json')); [r.__setitem__('issuer','$ISSUER') for r in p['requirements'] if r.get('type')=='issuer_trusted']; json.dump(p, open('policy.json','w'), indent=2)"
proof-cli evaluate --proof proof.json --policy policy.json --clock 1700000300 \
    --revocations-known-at 1700000300 --trusted $ISSUER
proof-cli explain --proof proof.json --policy policy.json --clock 1700000300 \
    --revocations-known-at 1700000300 --trusted $ISSUER

# New in V1.1: DX improvements
proof-cli version                          # Show version information
proof-cli doctor                           # Diagnose environment
proof-cli inspect --proof proof.json       # Inspect proof (read-only, no trust)
proof-cli graph --proof proof.json         # Visualize relationships (text)
proof-cli graph --proof proof.json --format dot    # Graphviz output
proof-cli graph --proof proof.json --format mermaid # Mermaid output

# Stdin support: read proof from stdin
cat proof.json | proof-cli verify --proof - --clock 1700000300

# Short flag aliases
proof-cli verify -p proof.json -c 1700000300 -o report.json
```

---

## For Developers

Add Proof Engine to your `Cargo.toml`:

```toml
[dependencies]
proof-verify = "1.0"
proof-policy = "1.0"
```

Then verify a proof in your code:

```rust,ignore
use proof_verify::{verify_proof, VerifyCtx};
use proof_policy::{evaluate_policy, parse_policy, EvalInputs, state_from_report_and_proof};

// Step 1: Check the proof (signatures, structure, timing)
let report = verify_proof(&proof_bytes, &VerifyCtx {
    verified_at: 1_700_000_300,
    ..VerifyCtx::default()
})?;

// Step 2: Apply your rules
let policy = parse_policy(&your_rules_json, &limits)?;
let state = state_from_report_and_proof(&report, &proof)?;
let outcome = evaluate_policy(&state, &policy, &EvalInputs {
    trusted_issuers: vec![issuer_keyref],
    ..EvalInputs::default()
});

// Step 3: Get a clear answer
println!("{}", proof_policy::explain_full(&report, &outcome));
```

### Available Crates

| Crate | Purpose | Dependency |
|-------|---------|------------|
| `proof-core` | Domain types, error codes, limits | Foundation |
| `proof-format` | Canonical CBOR encode/decode | Depends on core |
| `proof-crypto` | Ed25519/P-256 sign/verify | Depends on core, format |
| `proof-graph` | DAG validation, cycle checks | Depends on core |
| `proof-verify` | 11-stage verification pipeline | Depends on all above |
| `proof-policy` | Policy evaluation engine | Depends on verify |
| `proof-cli` | Command-line tool | Depends on all above |

### Creating a Proof

```bash
# Create payment + invoice events (--payload-hex: 64 hex chars = 32 bytes)
PAYLOAD=$(python3 -c "print('ab'*32)")
proof-cli create-event --type payment.created --subject payment:p1 \
    --effective-at 1700000000 --payload-hex $PAYLOAD --out ev1.json
proof-cli create-event --type invoice.issued --subject invoice:i9 \
    --effective-at 1700000000 --payload-hex $(python3 -c "print('cd'*32)") --out inv1.json

# Sign an attestation (note the issuer key:ed25519:… — needed for the policy)
proof-cli attest --seed test --subject payment:p1 --claim-type payment.settled \
    --claim amount=4200 --issued-at 1700000150 --out att.json

# Grounding evidence + edge: --from/--to/--object take artifact ids
# (evt:v1:…), NOT bare labels like `invoice:i9` (those never resolve —
# `relate` fails fast with a hint, and `verify` reports DANGLING_REFERENCE).
DIGEST=$(python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$PAYLOAD')).hexdigest())")
ATT=$(python3 -c "import json; print(json.load(open('att.json'))['id'])")
proof-cli add-evidence --kind transaction_record --digest-hex $DIGEST \
    --attestation-ref $ATT --out evd.json
EVT=$(python3 -c "import json; print(json.load(open('ev1.json'))['id'])")
INV=$(python3 -c "import json; print(json.load(open('inv1.json'))['id'])")
EVD=$(python3 -c "import json; print(json.load(open('evd.json'))['id'])")
proof-cli relate --from $EVT --type SETTLES --to $INV \
    --evidence-ref $EVD --attestation-ref $ATT --out rel.json

# Build the proof (--evidence "" if the proof genuinely has no evidence)
proof-cli build --kind payment.settles-invoice --subject $EVT \
    --predicate settles --object $INV --at-time 1700000150 \
    --created-at 1700000200 --events ev1.json,inv1.json --attestations att.json \
    --evidence evd.json --relationships rel.json --out proof.json

# Verify (--revocations-known-at required for PASS; without it lifecycle is
# UNKNOWN and verify fails closed with a re-run hint)
proof-cli verify --proof proof.json --clock 1700000300 --revocations-known-at 1700000300

# Policy: replace ONLY the suffix after `key:ed25519:` (prefix exactly once)
ISSUER=$(python3 -c "import json; print(json.load(open('att.json'))['issuer'])")
python3 -c "import json; p=json.load(open('examples/policies/settlement.json')); [r.__setitem__('issuer','$ISSUER') for r in p['requirements'] if r.get('type')=='issuer_trusted']; json.dump(p, open('policy.json','w'), indent=2)"
proof-cli evaluate --proof proof.json --policy policy.json --clock 1700000300 \
    --revocations-known-at 1700000300 --trusted $ISSUER
proof-cli explain --proof proof.json --policy policy.json --clock 1700000300 \
    --revocations-known-at 1700000300 --trusted $ISSUER
```

---

## Status

**Proof Engine V1 — In Development**

The V1 core evolves on `main`: spec, code, tests, and golden vectors move together in every change.

Development priorities:

1. independent implementations;
2. interoperability;
3. domain adapters;
4. ecosystem tooling;
5. real-world validation;
6. security research;
7. long-term compatibility.

Even in development, the core should **not** be modified merely to accommodate individual application requirements — domain needs belong in adapters, vocabularies, and policies (see NEUTRALITY.md).

---

## Specification

The protocol is defined by these documents:

| Document | Scope | Authority |
|----------|-------|-----------|
| [SPEC.md](SPEC.md) | Complete V1.0 protocol specification | **Protocol authority** |
| [FORMAT.md](FORMAT.md) | CBOR wire format, CDDL schema, ID construction | Wire format authority |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Repository layout, API surface, design rationale | Implementation guide |
| [POLICY.md](POLICY.md) | Policy language, requirement types, evaluation | Policy authority |
| [LONGEVITY.md](docs/LONGEVITY.md) | Migration contract, crypto-agility | Long-term plan |
| [GOVERNANCE.md](GOVERNANCE.md) | PE-PROP process, decision making | Governance authority |
| [RELEASE.md](RELEASE.md) | V1 release checklist and gate | Release record |
| [docs/format.cddl](docs/format.cddl) | Machine-readable CDDL schema | Schema authority |

If this README conflicts with a specification document, the specification wins.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

See [GOVERNANCE.md](GOVERNANCE.md) for the PE-PROP process and decision model.

**Ground rules:**
- Implemented behavior only (no "coming soon")
- Fail closed (reject unknowns, never guess)
- Deterministic (same inputs → same bytes)
- Every failure has a stable error code
- CI must be green: build, test, fmt, clippy, demo determinism

---

## Security

Found a problem? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for private reporting.

---

## License

Dual-licensed under MIT or Apache 2.0. See [LICENSE](LICENSE).

---

## The Principle

```
             CLAIM
               │
               ▼
            EVIDENCE
               │
               ▼
          ATTESTATION
               │
               ▼
         RELATIONSHIPS
               │
               ▼
             PROOF
               │
               ▼
         INDEPENDENT
         VERIFICATION
               │
               ▼
            POLICY
               │
        ┌──────┼──────┐
        ▼      ▼      ▼
      PASS    FAIL  UNKNOWN
```

**Proof Engine** — *Make digital claims independently verifiable.*
