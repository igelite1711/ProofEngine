# MIGRATION-PLAN.md — Sequenced Transition from V1 to the Target Architecture

> **Status:** Plan for review (2026-09-10), derived from the audited as-built
> state (`ARCHITECTURE-AUDIT.md`), the normative protocol
> (`PROOF-ENGINE-SPEC.md`), the threat model (`SECURITY-MODEL.md`), and the
> target shape (`ECOSYSTEM-ARCHITECTURE.md`).
>
> **Prime rule — no destructive implementation until this document, the
> audit, the spec, the security model, and the ecosystem architecture are
> internally consistent.** The program is *additive, versioned, fail-closed*,
> and preserves the V1 invariants at every commit.

---

## 0. Guiding principles (all non-negotiable)

1. **Never rewrite the working core.** V1's canonicalization/ids/COSE/
   pipeline/policy are correct, cross-implemented, fuzzed. They are extended,
   not replaced.
2. **Additive-only semantics.** New behavior arrives as versioned capability
   rows. Existing artifacts never change meaning; unknown stays fail-closed.
3. **Small core, thick perimeters.** Every feature gets an explicit
   architectural layer (ECOSYSTEM §3–4) or it is rejected.
4. **Verification before implementation.** Every phase has a gate that is
   executable: tests + vectors + a differential check. A phase that cannot
   prove its claim is not complete (§59).
5. **Docs are code.** Capability rows, migration notes, and doc-code sync are
   release gates (VERIFICATION.md rule).
6. **Shipability at every step.** `main` remains green (build, test, fmt,
   clippy, deny, trace, neutrality, demo-determinism) in every commit.

## 1. Baseline (audited 2026-09-10)

- 7 workspace crates + excluded domain suite and fuzz crate; 16,546 Rust
  lines; 163 tests green; build/test/fmt/clippy/deny/trace/neutrality gates
  all green; interop differential I2/I3 green; fuzz CI smoke green.
- Ten findings (AUDIT §4, F1–F10) — severity-ranked disposition in
  AUDIT §10.

## 2. Phase map (dependency-ordered)

| Phase | Name | Outcome | Depends on |
|---|---|---|---|
| P0 | Audit | `ARCHITECTURE-AUDIT.md` | — |
| P1 | Spec consolidation & P0 fixes | consolidated spec + drift repair | P0 |
| P2 | Context unification & report dimensions | `VerificationContext`, dimensioned verdicts | P1 |
| P3 | Artifact container + bundles | standardized envelope + bundle format | P1, P2 |
| P4 | Composition & provenance | `referenced_proofs`, traversal APIs | P3 |
| P5 | Crypto maturity | PQ seams, hash migration drills, bench suite | P1 |
| P6 | Policy v2 | OR/NOT/threshold/temporal/external | P2 |
| P7 | Adapters | C2PA/VC/SCITT/PKI/logs mapping + differential | P1, P4 |
| P8 | Language parity | TS/Python SDKs bound to vectors | P3, P5 |
| P9 | Integration | ingestion, reference API, batch | P6, P7 |
| P10 | DX & release hygiene | CLI polish, UI, SBOM/signed releases | P8 |
| P11 | Adversarial validation | independent impl parity, fuzz everywhere, security review | P5–P10 |
| P12 | Domain validation | ≥10 domains, zero core changes | P7, P11 |

Phases P1–P2 are the *consolidation* track (no protocol impact). Phases P3–P9
are the *extension* track (versioned capability rows). Phases P10–P12 are the
*validation* track.

## 3. Phase details (scope, gate, exit criteria)

### P1 — Spec consolidation & P0 fixes *(consolidation, no wire changes)*
**Scope**
- Land the five doc deliverables and reconcile: `ARCHITECTURE.md` §3.1
  open-vocabulary sentence (F2), `FORMAT.md` nint-range amendment (F8),
  `interop/README.md` P-256 wording (F7), `ARCHITECTURE.md` layout/tests
  claim (F3), `certification-report.md` wording (F10).
- Fix `report_all_failures` (F1): implement fail-collect mode **or** deprecate
  the field; either way docs must match code.
- Panic hygiene (F5): replace `unwrap/expect/panic!` in production paths
  (`keys.rs`, `proof-graph`, `proof-cli`) with `?`/`map_err`; add the
  no-panic grep gate to CI alongside the neutrality gate.
- Hygiene (F4, F9): relocate root scratch JSONs to `examples/` (or delete),
  move `refactor_enums_to_strings.sh` to `tools/archive/`, add `.gitignore`
  rules.
- Consolidate the protocol doc family; keep `FORMAT.md`/`SPEC.md` as
  sub-references of `PROOF-ENGINE-SPEC.md` (no semantic drift).

**Gate (executable)**
- `cargo test --locked` green; `make neutrality` and `make trace` green;
  new grep gate passes; docs-lint (links to real files/rows) green.

**Exit criteria**
- Zero AUDIT F1–F10 open items; `make docs`-style consistency check (script)
  proves every normative reference in the five docs resolves.

### P2 — Context unification & report dimensions *(additive API, no wire change — landed)*
**Scope (landed: `VerificationContext` normative, `VerifyCtx`/`EvalInputs`
`From` projections, `dimensions()`, `verify_and_evaluate`, `StatusSource`,
`extra_grounded`)**
- Introduce a single `VerificationContext` value object (PROOF-ENGINE-SPEC
  §14); make `VerifyCtx` and `EvalInputs` thin projections (retain their
  names and signatures — no breaking change).
- Add the dimensioned-verdict projection: `Verdict { Valid, Invalid,
  Indeterminate, NotApplicable }` per dimension (structural, cryptographic,
  evidence, provenance, temporal, revocation, policy, overall) derived from
  existing stage records, with the v1 triple preserved as the default
  projection (golden vectors unchanged).
- Add `verify_and_evaluate(bytes, ctx, policy)` convenience (typed combined
  output) so pipeline/policy pairing errors are impossible at compile time.

**Gate**
- All golden vectors byte-identical; new dimensioned projections covered by
  a dedicated test matrix; `NOT_APPLICABLE` semantics pinned (no evidence →
  not applicable, never a fail).

**Exit criteria**
- A proof that today yields `{valid, valid, indeterminate}` yields the same
  triple **and** a dimensioned report whose aggregation reproduces it.

### P3 — Artifact container & bundles *(new format row; v1 wire untouched)*
**Scope**
- Standardize `ArtifactEnvelope` (PROOF-ENGINE-SPEC §15): `kind`/`id`/
  `cbor`/optional `sign1`; advisory fields; consumers re-derive.
- Define the **bundle** container: ordered list of proofs + optional evidence
  blobs + status objects, with a reference-availability matrix report
  (PROOF-ENGINE-SPEC §8).
- Implement in `proof-format` (new crate `proof-bundle` or module) + CLI
  `export`/`import`/`convert` when the format rows land.
- Extend `interop/` so the Python verifier consumes the envelope and bundle
  shapes (not just raw vectors).

**Gate**
- Cross-language differential over envelope/bundle fixtures (Rust↔Python);
  tampered envelope fails closed; missing evidence reported, never assumed.

**Exit criteria**
- `proof export/import` round-trips byte-identically; bundle verify reports
  the full availability matrix; capability row CAP-120 (envelope) + CAP-121
  (bundle) marked IMP.

### P4 — Composition & provenance *(v2 proof semantics)*
**Scope**
- `referenced_proofs` per PROOF-ENGINE-SPEC §7 / SPEC §7 is landed as
  linkage-only (additive: sorted/deduped/bound/self-checked, reported
  REFERENCED never VERIFIED; missing content is bundle-layer INDETERMINATE,
  never a new core refusal code). Transitive resolution is landed as a
  bundle-layer helper (`proof_verify::resolve`: BFS over linkage against an
  `ArtifactStore`, same-context re-verification, depth accounting, diamond
  dedupe, `UNAVAILABLE`/`ID_MISMATCH`/`DEPTH_EXCEEDED`/`OVER_BUDGET` matrix,
  root verdict reproduced verbatim) + `resolve` CLI command. Remaining:
  ancestry/descendant traversal APIs, policy hooks (require/forbid
  references).
- Add graph traversal APIs: ancestry, descendants, dependency analysis,
  provenance explanation, partial-graph verification, cycle detection policy
  per edge kind (membership now extensible via `extra_grounded` — AUDIT §8
  mechanism landed; defaults unchanged).
- Keep the v1 flat-proof parser untouched; compose only among v2 objects.

**Gate**
- Differential both directions over composed proofs (A+B → C checker);
  missing referenced proof fails closed; cycles across composition rejected.

**Exit criteria**
- CAP-045 (nested-proof) IMP with vectors (valid composition, broken
  reference, cycle); provenance traversal matrix tests green.

### P5 — Crypto maturity *(registry work; no default changes)*
**Scope**
- Spell out the algorithm-registry lifecycle in code tables (additive:
  PQ row scaffolding, keyref prefix registry, `AllowedAlgs` per family).
- Drill the hash-migration window (`:v1:`→`:v2:` dual-verify) with a
  simulated cutover test and migration fixtures.
- Bench suite (`proof-bench`, landed): creation, canonicalization, hashing,
  signing, verification (small/large/deep), graph traversal, policy
  evaluation, serialization — with throughput/latency/memory and a JSON
  baseline regression gate (`--write-baseline`/`--check-baseline`).
- Keep Ed25519 required/default and ESP256 opt-in; no silent enable.

**Gate**
- Registry rows tested (PQ numbers parse + fail closed); migration drill
  fixtures byte-stable; bench numbers recorded in the changelog.

### P6 — Policy v2 *(closed language v2)*
**Scope**
- New `policy_version: 2` with OR/NOT groups, k-of-N thresholds/quorum,
  temporal windows, relationship/provenance constraints, optional external
  state via explicit input hooks. Evaluation remains a pure function; no code
  execution ever.
- Cross-version determinism: v1 policies evaluated by v1 rules byte-for-byte
  today and forever; v2 is additive and version-tagged.
- Translator/format layer stays data-only; `policy_id` + canonical policy
  hash bound to proofs when the caller requests it.

**Gate**
- v2 grammar per `docs/policy-grammar.ebnf` + golden vectors per new
  operator; no regression on all v1 policy vectors.

### P7 — Adapters (standards mapping)
**Scope (SCITT landed: `crates/proof-adapter-scitt`)**
- Implement the mapping layers of ECOSYSTEM §6 for C2PA, W3C VC, SCITT,
  X.509/PKI, transparency logs, device attestation, signed HTTP records,
  enterprise events — each its own crate, differential-tested both
  directions, with canonical-source digest binding.
- Deliver adapter conformance docs: what maps, what fails, what is
  explicitly out of adapter scope.

**Gate**
- Every adapter ships ≥1 inbound + 1 outbound differential fixture validated
  by the independent verifier; unmappable input fails with a stable code.

### P8 — Language parity (TS/Python/Go SDKs)
**Scope**
- TypeScript and Python SDKs (Go later) bound to `PROOF-ENGINE-SPEC` +
  golden vectors; they implement the same canonicalization/ids/COSE subset,
  share the vector corpus, and never invent semantics.
- Python SDK reuses the verified `interop/` core; TS SDK gets its own minimal
  CBOR subset (with the same re-encode-and-compare discipline).
- CI: SDK lanes run the golden corpus and the artifact-container fixtures.

**Gate**
- All SDKs pass the golden corpus and differential suite (same verdicts as
  Rust) on CI.

### P9 — Integration (ingestion, reference API, batch)
**Scope (batch verification landed: `proof_verify::verify_batch` +
`batch-verify` CLI + bench dimension; API/ingestion remain)**
- Reference API (ECOSYSTEM §7) as a thin adapter-owned service: idempotent
  job model, stable versions, structured errors, authN/Z, rate limits,
  audit logs; verification always re-derived, never cached-as-authoritative.
- Ingestion layer (ECOSYSTEM §8): adapters for APIs/webhooks/queues/streams/
  files/DBs/logs/signed messages → canonical Event/Evidence production;
  proof granularities incl. batch and checkpoint with per-member digests.
- Observability: metrics/structured logs/traces for services only, no proof
  contents, no secrets, no PII (SECURITY-MODEL §8).

**Gate**
- End-to-end fixture: an ingested event stream produces batch proofs that
  verify independently (a downstream verifier with only the batch + digests
  can re-derive every member verdict); API never returns "valid" without the
  core re-deriving it.

### P10 — DX & release hygiene
**Scope**
- CLI completes the §31 mental model (`export/import/convert`, `doctor`
  hardening, machine-readable errors everywhere, examples).
- Reference UI evolves to the full Claim→Evidence→Attestation→Relationships→
  Proof→Verification→Policy visualization, offline and servable locally.
- Release hygiene: SBOM generation, signed release artifacts, provenance
  attestations (SLSA-style), `cargo vet`-style audit adoption, secret
  scanning, hardened CI isolation. Honest status in SECURITY-MODEL §5 flips
  from "gap" to "implemented" only when the evidence exists.

**Gate**
- Release checklist (SECURITY-MODEL §10) automated as `make release-check`.

### P11 — Adversarial validation
**Scope**
- Fuzz every parser surface (add: envelope, bundle, policy-v2, adapter
  mappers) — no panic, no unbounded memory, no accidental acceptance, no
  uncontrolled recursion (CI nightly 600 s/target floor).
- Adversarial matrices for every trust-influencing field: deletion, insertion,
  substitution, replay, duplication, reordering, truncation, type confusion,
  boundary values, malformed encodings, algorithm downgrade, identity
  substitution, relationship manipulation, evidence swapping (extend the
  mutation-soak harness).
- Independent-verifier parity audit across all implementations + a hostile
  review loop on the consolidated spec.

**Gate**
- New fuzz targets ≥600 s green; adversarial matrix green; parity report
  green; zero outstanding P0/P1 findings.

### P12 — Domain validation (ten domains)
**Scope**
- Extend `domains/proof-domains` to ten unrelated industries (next five:
  software supply-chain, clinical/health, IoT/fleet, legal contracts,
  education). Each domain: vocabulary, policy, journey, differential test —
  zero mechanism changes.
- Record any core modification *as a defect* in the abstraction, with a
  documented redesign or explicit rationale (ECOSYSTEM §10.5).

**Gate**
- `make neutrality` green with ten domains; core-diff count == 0 (enforced
  by the neutrality gate + traceability).

## 4. Consensus gate before destructive work begins

Per §61 of the program, alignment is required on all of the following, and
**no core code is modified until P1's exit criteria are met and this plan is
accepted**:

1. Proposed final architecture → `ECOSYSTEM-ARCHITECTURE.md` (target shape
   accepted as-direction).
2. Current architecture weaknesses → AUDIT §4 findings F1–F10 (disposition
   approved).
3. Proposed data model → PROOF-ENGINE-SPEC §3 (five primitives + v2 additive
   rows) — approved-as-contract.
4. Proposed proof lifecycle → PROOF-ENGINE-SPEC §9 + ECOSYSTEM §11.
5. Proposed verification lifecycle → PROOF-ENGINE-SPEC §9 (stages, dimensioned
   verdicts, historical/current).
6. Proposed cryptographic abstraction → PROOF-ENGINE-SPEC §6 + P5.
7. Proposed versioning model → PROOF-ENGINE-SPEC §16.
8. Proposed graph model → PROOF-ENGINE-SPEC §7/§9.1 + P4.
9. Proposed policy architecture → PROOF-ENGINE-SPEC §12 + P6.
10. Proposed API boundary → ECOSYSTEM §7 + P9.
11. Proposed extension mechanism → capability rows + neutrality tests
    (ECOSYSTEM §13).
12. Proposed interoperability model → ECOSYSTEM §6 + P7.
13. Proposed test strategy → SECURITY-MODEL §10 + P11.
14. Proposed migration strategy → this document (accept the phasing).

Approval rule: a phase may begin only when its dependencies are green and its
gate is executable. Any change to the five documents' semantics requires a
change-control note in `docs/phase*-report.md` (append-only pattern
established by the V1 phasing).

## 5. Immediate next actions (first cycle, all additive)

| # | Action | Owner | Est. |
|---|---|---|---|
| 1 | Land the five deliverables (this commit) | arch | done |
| 2 | P1: F2/F8/F7/F3/F10 doc rewrites | docs | 1d |
| 3 | P1: F1 `report_all_failures` implement-or-remove | core | 1d |
| 4 | P1: F5 panic hygiene + CI grep gate | core | 1d |
| 5 | P1: F4/F9 hygiene + `.gitignore` | ops | 0.5d |
| 6 | P2: `VerificationContext` + dimensioned projection spike | core | 3d |
| 7 | Review cycle: hostile review of the five docs (spec §53 loop) | external | 1w |
| 8 | Capability-map rows for the v2 addenda (CAP-045/120/121, policy v2, StatusSource, ten-domain roadmap) | docs | 1d |

## 6. Risk register

| Risk | Exposure | Mitigation | Phase |
|---|---|---|---|
| Spec drift during consolidation | wallet-broken docs | doc-code sync gate; five-docs lint script | P1 |
| Dimensioned verdicts change binary semantics silently | verdict misread | triple preserved as default projection; golden byte-pin | P2 |
| v2 schema addition splits implementations | interop fork | dual-verify windows; only additive fields; vector append-only | P3/P4 |
| Adapter mappings over-interpret standards | false claims | differential both directions; conformance docs | P7 |
| SDKs drift from spec | cross-lang mismatch | shared vector corpus gate on CI | P8 |
| Scope creep toward convenience features | core bloat | neutrality + remove-half + layer contract for every feature | all |
| Revocation freshness gap undermines trust | stale acceptance | StatusSource + transparency first (P9/P4), never silent | P4/P9 |

## 7. Explicit non-goals for this program (re-commitment)

No banking rails, no token, no consensus, no NFT semantics, no
Proof-Engine-owned identity/trust score, no mandatory server/SaaS, no
rewriting V1 crypto or format, no silent semantic changes, no ZK mandate, no
feature added without an identified architectural layer (§58.18), and no
declaration of completion merely because tests pass (§58.20).

---

*Status hook: when this plan is accepted, mark P0 complete and open P1. Until
then, the five deliverables stand as the alignment checkpoint.*