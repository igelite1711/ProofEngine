# Architecture Freeze Candidate — Convergence Review

> **Status:** Historical — promoted to `ARCHITECTURE-FREEZE.md` after the §53 gate.
> Freeze candidate (this pass). Records the six elevations, the
> minimal core deltas that implement them, and the break attempts used to
> prove the boundaries. The standard applied is not "works" but: *the design
> explicitly anticipates the major classes of change that would otherwise
> force a rewrite.*
>
> Governing abstraction: **a Proof is a portable, cryptographically bound
> package of assertions and their supporting evidence and provenance,
> evaluated by a verifier under an explicit context.** The engine is a
> claim/evidence/provenance/verification engine — not a truth engine.

---

## 1. Core layer map (implementation pointers)

| Mandate layer | Implementation | Boundary |
|---|---|---|
| Entity / Identity Binding | Opaque reference strings + `identity.bind` claims + EQUIVALENT edges; honored only from trusted asserters with ACTIVE assertions, never transitive-by-core (expired/superseded bindings merge nothing — tested both layers) | Core transports + grounds; merging is policy |
| Event / Activity | `EventContent` (unsigned happening-record) | Core binds digests; meaning is domain |
| Claim / Proposition | `Claim` maps + `Proposition` value object; reserved `denies` field | Core binds bytes; truth is out of scope |
| Evidence | Digest-bound items + derived `EvidenceStatus` (8 states) | Core binds + derives; content lives outside |
| Attestation / Delegation | COSE_Sign1 attestations; `delegate` convention + chain resolution over ACTIVE links | Core verifies signatures/windows; roots are context |
| Relationship / Provenance | Typed edges (12 well-known + open); grounding; CONTRADICTS opposition | Core validates topology; semantics are policy |
| Proof / Composition | Member-set binding + `referenced_proofs` linkage + bundles | Core binds; resolution is adapter/bundle work (transitive V2) |
| Canonicalization | Deterministic CBOR subset, re-encode-and-compare everywhere | Frozen; subset only shrinks |
| Crypto Abstraction | Closed registry, default-off additions, historical mode | Numbers versioned; ops replaceable |
| Verification | 13 fixed stages, fail-closed, collect-all diagnostics | Order fixed; verdicts never collapsed |
| Verification Context | Single `VerificationContext` object (clocks, trust, algs, limits, vocab acceptance) | Echoed, never stored/trusted |
| Transparency Evidence | Abstract model (§8b): registration → receipt → inclusion → consistency/ordering; checkpoint attestations | Core checks presence/binding/issuer/freshness; log crypto in adapters |
| Policy Interface | V1 frozen AND-list; v2 boolean/threshold expressions + adjudication leaves | Syntax versioned; never code |
| Lifecycle / Status | 6 attestation states + 8 evidence states; revoke/supersede/withdraw/compromise | Additive kinds only; old proofs byte-identical |
| Versioning / Extension | Open labels + closed fields + namespaces + bound declarations + `v` gates | New meaning needs no core change; new structure needs new `v` |

External systems plug in below the core without redefining it: PKI
(identity/key material), VC/C2PA (credential/assertion profiles above
attestations), SCITT (transparency adapters beneath receipts).

---

## 2. The six elevations → deltas → proof

1. **Identity/equivalence.** Delta: `EQUIVALENT` edge (identity-ref
   endpoints allowed, shaped ids must resolve, grounding required) +
   `identity.bind` convention + `identity_bound` policy leaf (BFS over
   trusted-asserter bindings/edges). Proven by: graph tests (grounding,
   dangling-shaped, no node inflation), v2 identity tests (trusted path,
   untrusted asserter fails, reflexivity).
2. **Delegation/authority chains.** Delta: `delegate` convention (subject =
   grantee, opaque scope) + chain resolution over ACTIVE links from listed
   roots (cycle-safe BFS, scope-exact when required). Proven by: 3-link
   chain test, cycle-termination test, scope tests, unknown-issuer/root
   failures.
3. **Transparency first-class.** Delta: abstract model in SPEC §8b,
   `transparency_registration`/`transparency_checkpoint` kinds,
   `transparency.checkpoint` convention, `transparency_inclusion` leaf
   (receipt bound to active checkpoint by log). Proven by: v2 transparency
   test (wrong-log fails), golden policy shape.
4. **Evidence lifecycle/status.** Delta: `withdraw`/`compromise` status
   kinds with kind-appropriate authority, `COMPROMISED` lifecycle state
   (dominates, history not preserved), 8-state evidence derivation,
   `WITHDRAWN`/`COMPROMISED` codes (append-only 22→24). Proven by:
   golden-29/30, renewal-pattern preservation test, restamp analysis.
5. **Conflict as native states.** Delta: `denies` fields (external denials
   noted, never failed) + grounded CONTRADICTS edges → typed conflict
   records (`divergent_claims`/`denial`/`contradiction`), validity
   unchanged, v2 adjudication (`any`/`threshold`/`no_conflicting_evidence`).
   Proven by: composition conflict tests, golden-28 (conflict → quorum PASS).
6. **Schema/vocabulary evolution.** Delta: `ns:label` convention + optional
   bound `vocabularies` declarations + `accepted_vocabularies` context +
   informational notes + `vocabulary_accepted` leaf. Proven by: golden-27
   (binding covers declarations; V1 regen byte-identical), Python binding
   parity, over-max/budget rejections.

No new persisted primitives were added in this pass. Every delta is
additive: all pre-existing golden vectors regenerate byte-identically (all
four generators re-run, zero diffs across the full 31-vector corpus) and
all pre-existing verdicts hold. Closed-schema parity is proven both
directions: unknown member fields are rejected by Rust (SCHEMA_VIOLATION)
and Python alike (differential Part 5), so the second implementation
cannot silently accept what the first rejects.

---

## 3. Boundary-break attempts and outcomes

**Competing standards (mapping, no competition):**
- *W3C VC 2.0*: controller→key authorization = `delegate` chain;
  credentialSubject claims = attestations; VC proof = COSE envelope;
  verification split (crypto vs policy) mirrors the core invariant. No core
  change; a VC adapter is a mapping layer (differential-tested both ways
  per adapter rules).
- *W3C PROV*: agents/activities/entities = issuers/events/subjects;
  derivation = open relationship labels; bundles/collections = `Bundle` +
  CONTAINS; identity/equivalence = EQUIVALENT + `identity.bind`. Covered.
- *C2PA*: assertions = attestations; claims = member-set binding;
  trusted time = authority clocks + transparency checkpoints; "provenance ≠
  trust decision" is already the core invariant. Covered.
- *SCITT (2026)*: signed statements = attestations; registration/receipts
  = transparency model (§8b); non-equivocation/consistency = checkpoint
  claims + adapters; trust decisions and storage stay outside — exactly the
  core boundary. Covered.
- *NIST crypto-agility (2026)*: closed registry + default-off + historical
  mode + deterministic-signature gate = replacement designed in, not bolted
  on. Covered.

**Future technologies:**
- *Post-quantum signatures*: new COSE number + keyref prefix + default-off
  + hybrid dual-attestation via existing AND; parser already
  algorithm-number-neutral (pq_ tests). No core change.
- *Zero-knowledge / selective disclosure*: digests already carry
  commitments opaquely; redaction = member subset + `referenced_proofs`
  back to the source (new id, member signatures still verify) — executed
  as `redacted_subset_with_back_reference_verifies` (withheld members
  absent from disclosed bytes, linkage names the source). Path proven
  additive; ZK mechanisms live in adapters.
- *New identity system (e.g. DID method)*: issuers are opaque strings;
  `key:*` verification ops sit behind the closed keyref registry
  (`KEYREF_PREFIXES` — the single plug-point) + `AllowedAlgs`-style
  switches — additive prefix + op, versioned. All three policy keyref
  checks funnel through `is_supported_keyref` (one function), so `did:key:`
  and unknown prefixes fail closed today and plug in at exactly one place
  tomorrow (tested: `keyref_prefix_registry_accepts_shapes`).

**Adversarial cases (executed as tests, not asserted):**
- Rogue delegation (unlisted root, unknown issuer) → Fail; delegation
  cycles terminate (visited-set BFS); scope mismatch fails while match
  passes; expired/revoked links break chains fail-closed.
- Malicious equivalence (attacker-grounded merger) → honored only from
  trusted asserters; shaped-but-unknown ids → DANGLING; bare edges rejected.
- Vocabulary bombs (16-declaration/16-ref limits, 32-node policy budget,
  128-char namespaces) fail closed with LIMIT_EXCEEDED/SCHEMA_VIOLATION.
- `created_at` restamp → binding survives AND freshness flips: pinned by
  test with advisory labeling in code, messages, and three docs (honest
  about what `proof_fresh` is).
- Threshold manipulation (`k=0`, `k>n`, empty branches, mixed connectives)
  rejected at parse; expression bombs cut by node budget.
- Stale self-links refused with explicit CYCLE_DETECTED (golden-25);
  malformed references fail at SCHEMA (golden-26).

**Unrelated domains:** autonomous systems (device→decision chains are
delegation + transparency), education (credential lifecycle exists),
compliance (policy-per-regime exists) — all compose from current machinery.

---

## 4. Deliberately remaining V2/perimeter (with why-no-core-change)

- Transitive cross-bundle resolution (fetch-and-verify chains, depth
  accounting): traverses the now-specified linkage; needs resolver traits
  + transport, not new semantics.
- Dedicated CONFLICT verdict + richer temporal/relationship policy leaves:
  new `policy_version`, same engine (v2 boolean/threshold machinery already
  carries them).
- ZK mechanisms, storage/transport adapters, SDKs/API/ingestion/UI, batch
  proofs: thick perimeter around the proven seams (`ArtifactStore`,
  `StatusSource`, `Bundle`, envelope standard).

## 5. Open risks acknowledged (not hidden)

- Scope strings are opaque equality: domains define meaning; misuse is a
  domain coordination failure, documented as such.
- Python leaves lifecycle/policy *verdicts* engine-side (binding-level
  cross-checks only) — full semantic parity is Rust + goldens.
- Fuzzing executes on nightly CI; the workspace gate pins vectors,
  determinism, and no-panic statically.
- `proof_fresh` remains advisory by design (see restamp analysis above).

---

*Conformance note: this document changes no code. Every claim above traces
to a named test, vector, or gate in this repository.*
