# Proof Engine — Architecture (V1 draft — in development)

> Status: as-built draft. Describes ONLY what the code implements today.
> Companion docs: `FORMAT.md`, `THREAT-MODEL.md`, `IMPLEMENTATION_PLAN.md`.
> Rule: if this doc conflicts with code, file an issue; doc and code must be
> reconciled before the next release (see VERIFICATION.md).

## 1. Primitive

> Any important digital claim SHOULD be representable as a Proof whose evidence can be independently verified.

A Proof is a portable, cryptographically bound package of assertions and
their supporting evidence and provenance, evaluated by a verifier under an
explicit context. The engine is a claim/evidence/provenance/verification
engine — not a truth engine, trust authority, or decision maker.

Governing equation:

```
CLAIMS + EVIDENCE + ATTESTATIONS + PROVENANCE + CRYPTOGRAPHIC BINDINGS
       + TRANSPARENCY EVIDENCE
                    │
                    ▼
                  PROOF + VERIFICATION CONTEXT → VERIFICATION RESULT
                    + POLICY → DECISION
```

Pipeline:

```
OBJECT / EVENT → EVIDENCE → ATTESTATION → RELATIONSHIPS → PROOF → VERIFICATION → TRUST/POLICY DECISION
```

Hard separation (never collapsed):

- **Cryptographic validity** — are bytes, hashes, signatures internally valid?
- **Evidence validity** — is evidence consistent, timely, connected, unrevoked?
- **Policy decision** — does valid evidence satisfy the requested policy? (`PASS`/`FAIL`/`INDETERMINATE`)

## 2. Proposed repository layout

```
proof-engine/
├── Cargo.toml              # workspace, locked deps
├── crates/
│   ├── proof-core/         # domain types: Event, Attestation, Evidence, Relationship, Proof, Proposition, IDs, time, status
│   ├── proof-format/       # canonical CBOR encode/decode, schema validation, versioned parsers
│   ├── proof-crypto/       # hash abstraction, COSE_Sign1 sign/verify, key types, alg registry
│   ├── proof-graph/        # typed DAG validation, limits, cycle/depth checks
│   ├── proof-verify/       # staged verification pipeline + error codes + explain
│   ├── proof-policy/       # policy schema, validator, deterministic evaluator
│   └── proof-cli/          # create-event/attest/add-evidence/relate/build/verify/evaluate/explain/revoke/supersede + demo
├── tests/                  # reserved (empty in V1; e2e + negative + golden harnesses live in crates/*/tests)
├── fixtures/               # golden vectors (input, canonical bytes, id, sig, expected result)
├── demo/                   # deterministic killer use-case 1 (payment settles invoice), run via `make demo`
├── docs/                   # this file + FORMAT + THREAT-MODEL + POLICY + VERIFICATION excerpts
└── README.md
```

No new crate without a real boundary. No HTTP server, no DB, no blockchain in V1.
No storage adapters exist in V1: the engine is stateless (portable bytes in,
report out); persistence is the caller's job.

Layering (strict, one-way deps):

```
domain (proof-core) → serialization (proof-format) → crypto (proof-crypto)
  → graph (proof-graph) → verification (proof-verify) → policy (proof-policy) → app (cli)
```

- Business objects never call crypto directly; they hand canonical bytes to `proof-crypto`.
- Crypto never knows about policy or graph semantics.
- Policy never implements signatures; it consumes the verified state struct.

## 3. Minimal domain model

Exactly five persisted primitives + two value objects (Proposition, Policy is input not stored in Proof except by reference).

### 3.1 Event

Something happened. Not trusted by default.

```
Event { event_id, event_type, subject, effective_at, payload_ref (HashRef), metadata }
```

- `event_type`: open string type in V1 with well-known labels, e.g. `payment.created|payment.completed|invoice.issued|document.signed|package.shipped|sensor.measurement.recorded|ai.action.executed`. Unknown types are transported verbatim and accepted at the core layer; acceptance is the policy's judgment, never a core rejection (open-vocabulary, PE-FMT-008).
- `payload_ref`: `HashRef` to external payload, never raw large blob inline (enforces size limits, privacy by digest).
- `event_id`: deterministic: `evt:v1:<b64u(sha256(canonical(Event without id)))>`. See FORMAT.md.

### 3.2 Attestation

Signed assertion by an issuer about an Event/Object/Evidence.

```
Attestation { attestation_id, issuer (KeyRef), subject (ObjectRef), claim (ClaimRef), issued_at, expires_at?, evidence_ref?, signature (COSE_Sign1) }
```

- One signature per attestation in V1 (multi-sig = multiple attestations + AND-of-issuers policy).
- `claim`: small structured value, e.g. `{ "type": "payment.settled", "payment": "<id>", "invoice": "<id>" }`, not free text as authority.
- Revocation/supersession/withdrawal/compromise are separate signed objects
  referencing artifact ids, not deletions (see LIFECYCLE.md, FORMAT §4.7).

### 3.3 Evidence

Material supporting a claim. V1 open `EvidenceKind` strings with well-known labels:

`signed_event | signed_document | receipt | credential | measurement | transaction_record | transparency_receipt | device_attestation | external_reference`

Each item: `{ evidence_id, kind, digest (HashRef), attestation_ref?, media_hints?, retrieved? }`.
External refs carry `fetch_policy: { allow_remote_fetch: false }` by default — verifier never silently fetches.

### 3.4 Relationship

Typed directed edge. V1 open `RelType` strings with well-known labels:

`OWNS | CREATED | SETTLES | REFERENCES | CONTAINS | PRODUCED | EXECUTED | ISSUED | SUPERSEDES | REVOKES | EQUIVALENT | CONTRADICTS`

```
Relationship { rel_id, from (ObjectRef), type, to (ObjectRef), evidence_ref?, attestation_ref? }
```

Edges that establish trust-relevant facts (`OWNS | CREATED | SETTLES | EXECUTED | EQUIVALENT | CONTRADICTS`) MUST carry `evidence_ref` or `attestation_ref`; bare edges are rejected at graph-validation stage for those types. Extra future kinds plug in via `extra_grounded` without a core change (default strict).

### 3.5 Proof

Portable package: proposition + everything needed to verify it.

```
Proof {
  proof_id, proof_format_version: 1,
  proposition: Proposition,
  events: [], attestations: [], evidence: [], relationships: [],
  referenced_proofs: [] (optional composition linkage, SPEC §7),
  requirements_ref? (policy id, informational only),
  created_at
}
```

- Immutable once built: `proof_id = prf:v1:<b64uNoPad(sha256(canonical({proof_format_version, proposition, sorted member id sets})))>` — single definition in FORMAT.md §3 (member-set binding). Non-empty `referenced_proofs` adds one sorted key to the binding; empty linkage binds byte-identically to V1. Optional bound `vocabularies` declarations behave the same (absent in V1 bytes → byte-identical).
- Portable: verifier needs only Proof bytes + trust inputs (trusted issuer list, verifier clock, revocation set, policy). No DB access. Reports echo linkage (`referenced_proofs[]`) and divergence (`conflicts[]`, representation only).
- Limits enforced on parse: `max_proof_size (default 1 MiB)`, `max_evidence_items (64)`, `max_nodes (128)`, `max_edges (256)`, `max_depth (16)`, `max_referenced_proofs (16)`, etc.

### 3.6 Proposition (value object)

Machine-readable claim. V1 struct:

```
Proposition { kind, subject, predicate, object?, at_time?, context? }
```

e.g. `{ kind: "payment.settles-invoice", payment: "evt:…", invoice: "evt:…", at_time: 1717… }`.
`description` (human string) allowed but never evaluated.

## 4. Verification state machine

Explicit stages, each returns typed errors, never repairs input. Order fixed:

```
INPUT → PARSE → SCHEMA → CANONICAL → IDENTIFIERS → SIGNATURES → KEYS
 → TIME → REVOCATION/SUPERSESSION/WITHDRAWAL/COMPROMISE → EVIDENCE
 → RELATIONSHIPS → GRAPH → POLICY (caller hand-off) → FINAL
```

11 check stages (PARSE…GRAPH) + STATUS feed-hygiene stage (V1.1; excluded
from validity) + caller POLICY evaluation + FINAL emission.
Stage names are normative (see PROOF-ENGINE-SPEC §9.1).

Stage responsibilities:

1. PARSE: CBOR decode, size/depth limits, UTF-8, duplicate-map-key reject.
2. SCHEMA: version check (`proof_format_version==1` else `UNSUPPORTED_VERSION`), required fields, enums closed.
3. CANONICAL: re-encode deterministically, compare `canonical_bytes`; mismatch → `NON_CANONICAL`.
4. IDENTIFIERS: recompute every id from canonical bytes; mismatch → `ID_MISMATCH` (tamper signal).
5. SIGNATURES: COSE_Sign1 verify with stated alg; deprecated (-8/-7) or unknown alg → `DEPRECATED_ALGORITHM`/`UNKNOWN_ALGORITHM` (fail, not negotiate).
6. KEYS: key well-formed, alg matches attestation, no confusion (Ed25519 key only verifies EdDSA).
7. TIME: `issued_at ≤ verified_at ≤ expires_at` (with explicit `clock_skew_leeway`, default 300s); distinguish `issued/observed/effective/expires/verified`.
8. REVOCATION/SUPERSESSION/WITHDRAWAL/COMPROMISE: join against verifier-supplied signed status objects + `revocation_authorities`; states `ACTIVE|EXPIRED|REVOKED|SUPERSEDED|COMPROMISED|UNKNOWN` (`COMPROMISED>REVOKED>SUPERSEDED>EXPIRED>UNKNOWN>ACTIVE`) + 8 evidence states (see LIFECYCLE.md). Missing/stale info → `UNKNOWN` → fail closed.
9. EVIDENCE: digest recompute where content is embedded; external refs are digest-only — the engine never fetches, and digests are re-validated as ids/binding.
10. RELATIONSHIPS: endpoints resolve, types known, required backing evidence present.
11. GRAPH: derivation subgraph always acyclic (REFERENCES/EQUIVALENT linkage excluded; `CYCLE_DETECTED` → evidence invalid), SUPERSEDES chain linear acyclic, depth/node/edge limits, no dangling refs. Opt-in full-DAG profile (`require_acyclic_provenance` / `--require-acyclic` / `--production`) additionally rejects REFERENCES cycles; default keeps REFERENCES citations linkage-valid.
11b. STATUS (V1.1): caller-feed hygiene — malformed/unauthorized/future-dated/supplied-signature problems. Never flips validity; exposed via `status_inputs_valid`.
12. POLICY (caller-evaluated, reported INDETERMINATE by the pipeline).
13. FINAL: emit `{ cryptographic_validity, evidence_validity, policy_decision, status_inputs_valid }` + dimensioned projection (structural/crypto/evidence/provenance/temporal/revocation/policy/overall) + `explanation[]` + stable error codes (24).

Fail-closed rule: any `UNKNOWN` in crypto or evidence validity forces `policy_decision ∈ {FAIL, INDETERMINATE}`, never `PASS`. `PASS` requires all required checks `valid`.

## 5. Minimal policy model

Declarative JSON, versioned, validated before eval. V1 requirement types (closed, ten):

`signature_valid | issuer_trusted | issuer_excluded | relationship_exists | not_expired | not_revoked | not_superseded | evidence_present | transparency_present | proof_fresh` (see POLICY.md § Requirement types)

Example:

```json
{ "policy_version": 1, "policy_id": "merchant_payment_v1",
  "requirements": [
    { "type": "signature_valid" },
    { "type": "issuer_trusted", "issuer": "key:ed25519:…" },
    { "type": "relationship_exists", "relationship": "SETTLES" },
    { "type": "not_expired" },
    { "type": "not_revoked" }
  ] }
```

Semantics: implicit AND in V1 (no OR/NOT — avoids policy-injection complexity). Same evidence under different policies may yield different decisions. Policy syntax errors → `POLICY_INVALID`, never evaluated.

## 6. Trust boundaries

- **Crypto boundary**: canonical bytes ↔ COSE. Everything outside is untrusted input.
- **Verification boundary**: portable Proof in; triple-result out. Local state (trusted keys, clock, revocation set) is explicit input, logged in explanation.
- **Storage boundary**: stores are indexes over immutable artifacts; mutating a row never redefines a `proof_id`.
- **Network boundary**: V1 verifier performs zero network I/O during `verify_proof()`. External evidence must be supplied by caller.
- **AI boundary**: AI sits above engine, consumes the `proof-policy::explain_*` output; cannot override `FAIL`.

## 7. Minimal API (library-first)

```rust
create_event(e: UnsignedEvent) -> Event
create_attestation(a: UnsignedAttestation, key: &Key) -> Attestation  // COSE_Sign1 inside proof-crypto
add_evidence(p: &mut ProofBuilder, e: Evidence)
add_relationship(p: &mut ProofBuilder, r: Relationship)
build_proof(b: ProofBuilder) -> Proof            // assigns ids, canonicalizes, size-checks
verify_proof(p: &Proof, ctx: &VerifyCtx) -> VerifyReport  // staged, deterministic
evaluate_policy(state: &VerifiedState, pol: &Policy, inputs: &EvalInputs) -> PolicyOutcome
explain_full(report: &VerifyReport, outcome: &PolicyOutcome) -> String  // derived from state, no new logic
revoke(id: &str, by: &Key, reason) -> RevocationAttestation
supersede(old: &str, new: &str, by: &Key) -> SupersessionAttestation
```

`VerifyCtx { verified_at, clock_skew_leeway, trusted_issuers, allow_remote: false, allowed_algs, limits, status_objects, revocation_authorities, revocations_known_at, report_all_failures, accepted_vocabularies, extra_grounded }`.
The single normative shape is `VerificationContext` (`proof-verify/src/context.rs`); `VerifyCtx` and policy `EvalInputs` are thin projections (`From` impls) so pipeline and policy can never diverge. `report_all_failures: true` continues past CANONICAL collecting diagnostics (PARSE/SCHEMA always fail fast); status may also arrive via a `StatusSource` adapter (`with_status_source`).
All objects immutable after build; `revoke`/`supersede` create new objects.

## 8. Killer use-case 1 (V1 demo)

Company→Account→Payment→Invoice chain answering: "Did Payment P legitimately settle Invoice I under policy merchant_payment_v1?" Demo constructs events + 2 attestations (payment issuer, invoice issuer) + SETTLES edge with backing attestation, verifies PASS, tampers one byte, verifies FAIL.

## 9. Non-goals for V1

No blockchain/token/consensus/VM/ZK/custom-DID/custom-sig-alg/governance/AI-trust. No HTTP server (Phase 8 deferred). No PostgreSQL semantics in crypto path.
