# Proof Engine V1 — Capability & Neutrality Specification

> **Source of truth for what Proof Engine V1 is.** This document audits the
> full neutral-capability map against the implementation. Statuses:
> **IMP** = implemented + tested · **DOC** = documented contract/hand-off ·
> **PRT** = partially implemented (gap noted) · **V2** = deliberately deferred
> (never silently "done").
>
> Companion: `NEUTRALITY.md` (governing principle + the mandatory neutrality
> test), `docs/domains/` (how any industry maps onto the core), and the
> domain suite in `domains/proof-domains/tests/` that *proves* these rows.

## 0. The universal question (source §0, §1, §81, §82)

> **Given a claim about something that happened, exists, was authorized, was
> performed, or is supposed to be true — can I package the relevant evidence,
> establish its relationships and provenance, verify its integrity and
> authority, evaluate explicit rules against it, and explain the decision?**

Proof Engine is **neutral, portable, independently verifiable infrastructure**
for claims, evidence, attestations, provenance, relationships, and
policy-based decisions. "Proof Engine turns claims about the world into
independently verifiable proofs." Everything else is an application.

> **The core-stability test (defining property).** If the entire core API were
> fixed today, radically different systems — finance, healthcare, media, AI,
> global trade, forensics — must be constructible on top of it **without
> modifying the core**: only domain tests, domain schemas/vocabularies above
> the boundary, and domain policies. (NEUTRALITY.md §3, Test 2; proven by
> `PE-NEUT-003`.)

## A. Core model & identity

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-001 | Five persisted primitives (Event, Attestation, Evidence, Relationship, Proof) + value objects (Proposition, Policy-as-input) | 1.1, 2, 3, 12 | IMP | `proof-core/src/model.rs`, DATA-MODEL.md, PE-FMT-008 |
| CAP-002 | Claim = structured content inside Attestation (`claim_type` + scalar fields), not a sixth persisted primitive | 1.1 | IMP | `model.rs::Claim` |
| CAP-003 | Entity/Subject = stable references only (no inferred business meaning) | 3 | IMP | subject fields on Event/Attestation/Proposition |
| CAP-004 | Closed vocabularies as *labels*, never semantics (unknown → fail closed) | 2, 8–9 | IMP | model.rs closed enums; PE-FMT-008 |
| CAP-005 | **Neutrality test (industry)**: new core feature must survive "different industry tomorrow?" | 76, 82 | DOC | NEUTRALITY.md §3 Test 1 |
| CAP-006 | No hard-coded domain semantics as logic | 45 | IMP+gated | `tools/check_neutrality.py` (PE-NEUT-001) |
| CAP-007 | **Core-stability test**: radically different systems constructible above a stable core (tests/schemas/policies only) | 82 | IMP | NEUTRALITY.md §3 Test 2; `PE-NEUT-003`, 10 domain journeys |

## B. Event / time / status

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-010 | Generic event: happened-record with type, subject, effective time, payload digest, metadata | 2, 47–50 | IMP | `model.rs::EventContent`; schema tests |
| CAP-011 | Temporal separation: event time ≠ observation/issuance ≠ verification ≠ status time | 18 | IMP | `effective_at`, `issued_at`/`expires_at`, `VerifyCtx.verified_at`, `revocations_known_at` |
| CAP-012 | Historical validity ≠ current applicability (VALID ≠ CURRENT, SUPERSEDED ≠ invalid; `currently_acceptable` split + `--production`/`--strict-current` overlay) | 19, 21–22 | IMP | Lifecycle: SUPERSEDED keeps evidence valid; `not_superseded`; `is_currently_acceptable`; golden-19; `production_overlays_currency_on_evaluate_and_batch` |
| CAP-013 | Expiration / revocation / supersession / withdrawal / compromise as separate signed status events | 20–22 | IMP | Phase 6 + lifecycle elevation; `lifecycle.rs`; golden-29/30; PE-LIFE-001/004 |
| CAP-014 | Unknown status must never convert to PASS | 27 | IMP | `revocations_known_at=None` → UNKNOWN → invalid |

## C. Evidence & provenance

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-020 | Evidence integrity (digest-bound, canonical, id-bound, tamper-evident; opt-in claim `evidence_digest` semantic binding, fail-fast at attest) |  §6 | IMP | `make_evidence`; EVIDENCE `evidence_digest` check; golden-02–05; `evidence_digest_*` |
| CAP-021 | Evidence kinds (generic incl. transparency_registration/receipt/checkpoint) | 4 | IMP | `model.rs::EvidenceKind` (open vocabulary, well-known labels) |
| CAP-022 | Embedded vs referenced vs unavailable evidence distinguished — never silently treated as verified | 23, 26 | IMP/DOC | digest+ref model; fetch is caller duty (contract #4) |
| CAP-023 | Evidence provenance (source/creator/time/hint) expressible without core semantics | 5 | PRT | `attestation_ref` + `hint` + claim fields; full provenance graph is caller-side |
| CAP-024 | Contradictory evidence representable; core does not arbitrate truth; policy decides | 25 | IMP | `report.conflicts` (divergent/denial/contradiction) + notes; v2 adjudication (`any`/`threshold`/`no_conflicting_evidence`, CAP-057, golden-28); dedicated CONFLICT verdict stays V2 |
| CAP-025 | Missing ≠ invalid ≠ unavailable ≠ unverifiable | 26 | IMP | distinct failure paths/codes; fail-closed suite |

## D. Attestation / signature / trust

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-030 | Attestation = issuer-signed claim over subject with validity window, id, context | 7 | IMP | `AttestationContent`; builder + goldens |
| CAP-031 | Sign/verify, key id, alg id, canonical payload, wrong-key/alg/tamper handling |  §8 | IMP | PE-CRYPTO-001..006; goldens 04/05 |
| CAP-032 | **Signature valid ≠ trusted ≠ true** (three boundaries never collapsed) | 9, 40, 73 | IMP | `issuer_trusted` needs caller trust list; PE-TRUST-001 |
| CAP-033 | Identity neutrality: keyrefs + external id references; no proprietary identity system | 41 | DOC/IMP | `key:ed25519:`/`key:p256:`; TRUST.md |
| CAP-034 | Multi-party proof (independent attesters/evidence, one package) |  §51 | IMP | builder accepts many; suites use ≥2 keys |
| CAP-035 | Delegation / authorization representable; authorization evidence ≠ execution evidence |  §52, 53 | PRT | vocabulary + policy can express; explicit split is caller policy (DOC) |

## E. Relationships / graph / proof

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-040 | Generic typed relationship model (12 well-known edge types incl. EQUIVALENT/CONTRADICTS, domain-neutral) |  §9, 10 | IMP | `model.rs::RelType`; PE-GRAPH-001 grounding (EQUIVALENT identity-ref endpoints) |
| CAP-041 | Proof graph validation: refs resolve, grounding (fail-fast at relate), derivation always acyclic + full-DAG opt-in, depth/size limits, no dangling/duplicate members |  §11, 64 | IMP | `proof-graph` (`check_derivation_acyclic` + `check_acyclic_provenance`); PE-FMT-006; cycle/limit tests |
| CAP-042 | Portable Proof: proposition + sorted member id sets + canonical bytes |  §12 | IMP | `ProofBuilder`; self-check round-trip |
| CAP-043 | Proof creation journey (claim → subjects → evidence → attestations → relationships → build → sign → export) |  §13 | IMP | CLI journey + builder; `cli_e2e` |
| CAP-044 | Proof verification journey (parse → schema → canonical → ids → sigs → keys → time → revocation → evidence → relationships → graph → decision outcome) |  §14 | IMP | 11-stage pipeline (`pipeline.rs`) |
| CAP-045 | Nested proofs (Proof as evidence for a Proof)with depth/cycle protection |  §24 | V2 | representable via `external_reference`; first-class nesting **V2**; v1 union-composition via `compose` IMP |
| CAP-046 | Proof composition by member-set union (dedup by id, provenance preserved; union graph validated at compose: grounding, dangling, SUPERSEDES linearity, derivation acyclicity; currency stays verify-time) | §12 | IMP | `proof-cli compose`; union is content-addressed, new proof_id binds union; golden-32 |
| CAP-047 | Standard artifact envelope (`container_version/kind/id/cbor/sign1`) | §15 | IMP | `proof-format::envelope` + `proof-crypto::verify_envelope`; `export/import/convert` |
| CAP-048 | Composition linkage (`referenced_proofs`: sorted/deduped/bounded, bound when present, byte-identical V1 when empty; self-links refused) | §12 | IMP | `proof_id_with_refs`; builder/pipeline/schema; golden-24/25/26; `compose` records sources |
| CAP-049 | Bundle convention + blob authentication (digests mandatory, blobs also carried; store seam with memory/filesystem backends) | §12 | IMP | `proof-format::{bundle,store}`; `FileStore`; `bundle_store` test |
## F. Policy engine

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-050 | Generic closed requirement language (AND), validated before eval, never executed as code | §17, §34 | IMP | `policy.rs` (10 v1 types incl. `issuer_excluded`); PE-POLICY-008 |
| CAP-051 | Same evidence under different policies → different decisions (Evidence ≠ Policy; Proof ≠ decision) | §61, §62 | IMP | golden-13/14 (A5); domain suites |
| CAP-052 | Policy portability: proof need not be regenerated when the policy changes | §62 | IMP | `evaluate_policy` is pure state × policy |
| CAP-053 | Policy v2 expressions (`all`/`any`/`not`/`threshold{k,of}` over leaves; INDETERMINATE reserved for unevaluated policy; v1 frozen) | §17 | IMP | `expr.rs`; `policy_v2` tests; golden-28; EBNF v2 |
| CAP-054 | Delegation chains (active `delegate` links, trusted roots, optional scope; cycle-safe) | §22 | IMP | `delegation_chain`; `delegated_authority` leaf; chain tests |
| CAP-055 | Verifier-scoped identity paths (`identity.bind` + grounded EQUIVALENT edges from trusted asserters; never global, never transitive-by-core) | §22 | IMP | `identity_path`; `identity_bound` leaf |
| CAP-056 | Transparency inclusion (receipt bound to active checkpoint by log; adapters beneath) | §24 | IMP | `transparency_binding`; `transparency_inclusion` leaf |
| CAP-057 | Conflict adjudication leaves (`no_conflicting_evidence`, threshold/or composition) | §25 | IMP | v2 tests; golden-28 |
| CAP-058 | Vocabulary acceptance (declared/used namespaces vs accepted max versions) | §39 | IMP | `vocabulary_accepted` leaf; golden-27 |
| CAP-059 | Evidence usability (AVAILABLE-only strict counterpart to presence) | §21 | IMP | `evidence_usable` leaf; evidence-status projection |
| CAP-059b | Evidence binding requirement (cryptographic claim-to-content binding: `evidence_digest` match over AVAILABLE evidence; lets policy *require* the opt-in binding) | §21 | IMP | `evidence_bound` leaf; `evidence_bindings` projection; golden-33 |

## G. Verification context, verdict & explanation

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-060 | Explicit verification context (clock, trust lists, status, limits, algs); no global state | §35 | IMP | `VerifyCtx`; PE-TRUST-003 |
| CAP-060b | Unified `VerificationContext` (single object; VerifyCtx/EvalInputs are projections) + one-shot `verify_and_evaluate` | §35 | IMP | `proof-verify::context`; `proof-policy::combine` |
| CAP-061 | Multi-dimensional verdicts (crypto / evidence / policy + stage checks + lifecycle) | §15, §39 | IMP | `VerifyReport` |
| CAP-061b | Dimensioned `Verdict` projection (8 dimensions × VALID/INVALID/INDETERMINATE/NOT_APPLICABLE, v1 triple preserved) | §15 | IMP | `VerifyReport::dimensions`; `dimensions` test |
| CAP-064 | Status-source registry contract (offline default + file/log/callback adapters) | §20 | IMP | `proof-verify::StatusSource/VecStatusSource` |
| CAP-065 | Configurable trust-relevant edge set (protocol default + caller additions, no core change) | §9 | IMP | `validate_graph_with_grounding` |
| CAP-066 | Divergence representation (`conflicts[]`: same type+subject, differing fields; validity unchanged, policy adjudicates) | §25 | IMP | `ConflictRecord`; composition tests; CLI JSON surfaces it |
| CAP-067 | Historical crypto mode (`allow_deprecated`: `-8`→Ed25519, `-7`→P-256; labeled historical-only; `-35`/`-36` never verifiable) | §19 | IMP | `AllowedAlgs::with_deprecated`; cose/pipeline tests |
| CAP-062 | Why-answers: PASS/FAIL/INDETERMINATE with requirement-level results and provenance | §16, §56 | IMP | `explain_*`; requirement results; PE-CLI-006 |
| CAP-063 | Reproducibility: same bytes + same context ⇒ same report, byte-for-byte | §36, §68 | IMP | determinism tests; PE-OPS-004; soak |

## H. Serialization / ids / interop

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-070 | Deterministic canonical serialization (same object → same bytes) | §29, §31 | IMP | PE-FMT-001..007 |
| CAP-071 | Stable collision-resistant deterministic ids | §30 | IMP | PE-CRYPTO-006; VERIFICATION.md |
| CAP-072 | Independent implementation verifies with FORMAT + crypto + golden vectors only | §32, §33, §66 | IMP | `interop/` Python verifier (Ed25519 + secp256r1); 28-check differential; PE-INTEROP-001..003 |
| CAP-073 | Golden vectors: valid + invalid + policy + lifecycle + composition coverage | §33 | IMP | golden-01..31 |
| CAP-074 | Machine + human interoperability (structured report + prose explanation) | §71, §72 | IMP | report structs/JSON + `explain_*` |
## I. Security & resource safety

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-080 | Fail closed everywhere: unknown version/alg/field → cannot-verify, never guess | §74, §75 | IMP | VERSIONING.md; closed-schema tests |
| CAP-081 | Negative verification matrix (tamper/wrong-key/expired/revoked/superseded/cyclic/oversized/…) | §28, §67 | IMP | negative suite + fuzz + soak |
| CAP-082 | Resource safety: depth/size/entry limits, bounded traversal, no pathological blowups | §64 | IMP | `Limits`; PE-FMT-006; fuzz targets |
| CAP-083 | Failure safety: error/unknown/missing-evidence → never PASS never assumed valid | §65 | IMP | evaluator INDETERMINATE guard; fail-closed suite |
| CAP-084 | Replay distinguishable from invalidity; replay policy is caller's | §69 | DOC | PROTOCOL.md caller contract #3 |
| CAP-105 | Key lifetime/rotation: caller constrains trust roots by evaluation time (per-key intervals = V2 row) | TRUST.md | DOC | TRUST.md §Key lifetime; rotation caller contract |
| CAP-085 | Security transparency: what is proven vs. not proven, in writing | §73 | IMP | SECURITY.md, THREAT-MODEL.md |

## J. Storage / transport / infrastructure neutrality

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-090 | Storage-neutral core (no DB/FS/blockchain/IPFS dependency) | §42 | IMP | zero storage deps; A12 deny gate |
| CAP-091 | Transport-neutral core (files/HTTP/messaging… are adapters; zero network I/O in verifier) | §43 | IMP | PE-SEC-003 |
| CAP-092 | Infrastructure-neutral (offline/online/local/server/edge/batch) | §44 | DOC | documented; no infra-specific code |

## K. Extension layer

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-100 | Domain extension without core modification (schema+vocabulary+policy above engine) | §46 | IMP | domain suites (4 industries, one core) |
| CAP-101 | Extensible algs / identity / storage / status / policy without rewriting the model | §76 | PRT | alg registry open; numbers stable in V1 (VERSIONING); storage adapters **V2** |
| CAP-106 | Longevity / post-quantum migration contract (hash → id `v2`, dual-verify window; PQ sigs on registry) | §future | DOC | `docs/LONGEVITY.md`, PE-LONG-001/002 |
| CAP-107 | Deterministic signatures enforced (RFC 8032 Ed25519 + RFC 6979 ECDSA), byte-identical repro | §determinism | IMP | PE-CRYPTO-010 + golden-21..23 |
| CAP-108 | Hybrid dual-sign bridging (classical+PQ attestations, AND-of-issuers) | §future | DOC/IMP | LONGEVITY §4 + POLICY.md multi-issuer |
| CAP-102 | Adapter architecture: applications → domain adapters → core → format/crypto/verify | §77 | DOC | ARCHITECTURE layering + NEUTRALITY.md |
| CAP-103 | Compliance enablement, not compliance implementation | §57 | DOC | policy-per-regime; POLICY.md |

## L. Journeys & application support

| ID | Capability | Source § | Status | Evidence |
|----|-----------|----------|--------|----------|
| CAP-110 | CLI journey: create / attest / add-evidence / relate / build / verify / evaluate / explain / revoke / supersede | §37 | IMP | `proof-cli`; cli_e2e |
| CAP-111 | Exit-code contract 0/1/2 (PASS / verdict / usage-engine error) | §37 | IMP | PE-CLI-001 |
| CAP-112 | Library journey for creators and verifiers | §38 | IMP | README "using as a library" |
| CAP-113 | Structured programmatic results for applications | §39 | IMP | `VerifyReport` + `PolicyOutcome` |
| CAP-114 | Audit/history support: what happened, when, who asserted, what changed, under which policy | §55, §60 | PRT/DOC | lifecycle + supersession history retained; timeline reconstruction is caller analysis (**V2** first-class) |
| CAP-115 | Dispute-resolution support (verifiable shares, independent verification) | §58, §59 | DOC/IMP | portable proofs + interop verifier; engine never adjudicates legal truth |
| CAP-116 | The five questions (WHAT / WHY / WHO / WHEN-HOW / RELY) answered in one API shape | §81 | IMP | proof → report → policy → explain pipeline |

## What V1 explicitly is NOT

Not a payment processor, banking/identity/compliance platform, blockchain,
wallet, ERP/CRM, AI platform, document manager, supply-chain system,
surveillance platform, legal adjudicator, or proprietary database/identity/
crypto system. All of those may **consume** Proof Engine; none of them
**defines** it (source §79–§80).

## Compliance summary

- **IMP**: 66 capability items (+1 gated) · **DOC**: 7 · **DOC/IMP**: 3 · **IMP/DOC**: 1 · **PRT**: 3 · **PRT/DOC**: 1 · **V2**: 1
- **V2**: transitive bundle resolution across proofs, CONFLICT verdict +
  threshold/quorum requirements, storage/transport adapters beyond the seam,
  ZK/selective-disclosure mechanisms, batch/aggregate proofs.
- Machine gates: `make neutrality` (PE-NEUT-001), `make trace` (all PE-* rows incl. PE-NEUT-*), `cargo test --locked`, CI.
