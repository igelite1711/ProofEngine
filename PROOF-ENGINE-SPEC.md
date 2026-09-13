# PROOF-ENGINE-SPEC.md — Unified Protocol Specification (v1 consolidated)

> **Status:** Phase-1 consolidation of the audited V1 protocol
> (ARCHITECTURE-AUDIT.md). Normative sources: `FORMAT.md`, `SPEC.md`,
> `CRYPTO.md`, `POLICY.md`, `LIFECYCLE.md`, `TRUST.md`, `ERROR-MODEL.md`,
> `docs/format.cddl`, `docs/policy-grammar.ebnf`. This document is the
> single-entry consolidation: where this document and a companion differ on
> **protocol semantics**, this document wins; where the CDDL schema and this
> document differ on **wire bytes**, the CDDL wins.
>
> Conformance clauses use RFC 2119 MUST / SHOULD / MAY. Every clause is
> implemented (IMP) or explicitly deferred (DEF) with a capability row.

---

## 1. Purpose and design contract

Proof Engine is a **domain-independent, offline-first, portable protocol for
representing and independently verifying digitally-attested claims.** A Proof
is a portable, cryptographically bound package of assertions and their
supporting evidence and provenance, evaluated by a verifier under an explicit
context. The engine establishes facts that downstream systems may use as
inputs to decisions; it never makes the decision itself, and it is not a
truth engine: cryptographic validity, evidence support, issuer authority,
and policy acceptance remain distinct, and coexistence with VCs, C2PA,
SCITT, PKI, provenance systems, and future identity and ZK systems is a
design goal, not an afterthought.

**Non-goals (hard boundaries):** no blockchain, no token, no central server,
no Proof-Engine-owned identity or trust registry, no mandatory network, no
persistent state in the core, no universal trust score, no legal/economic
system. Any feature that requires a specific industry assumption is
out of scope of this specification.

**Core invariant (must never be collapsed):**

```
structural validity  ≠  cryptographic validity  ≠  evidence validity
                     ≠  provenance validity     ≠  policy satisfaction
                     ≠  trust decision
```

## 2. Terminology

| Term | Definition | Never confused with |
|---|---|---|
| Event | Unsigned happening-record (type, subject, effective time, payload digest, metadata) | Authenticated truth |
| Attestation | Issuer-signed statement over a subject (content = issuer, subject, claim, issued/expires, optional evidence_ref) | Truth; a valid signature is a fact, not trust |
| Status object | Signed attestation sub-type with claim.type ∈ {`revoke`, `supersede`, `withdraw`, `compromise`} | Unsigned status lists (never trusted) |
| Delegation | Assertion (`claim.type="delegate"`, subject = grantee) by which an issuer grants authority; chains resolve in policy over active links | Identity ownership; a delegation without a trusted root is nothing |
| Identity binding | Assertion (`claim.type="identity.bind"` or grounded EQUIVALENT edge) that two identifiers name one subject *as far as the asserter is concerned* | Global same-as; honored only from trusted asserters, never transitive-by-core |
| Evidence | Digest-bound material supporting a claim (kind, digest, hint, optional attestation_ref) | Fetched/stored content (digest-only in v1) |
| Relationship | Typed directed edge between member ids (from, type, to, optional evidence_ref + attestation_ref) | Trust (needs grounding + policy) |
| Proof | Portable container binding a Proposition + exact sorted member id sets | The trust decision |
| Proposition | Value object: kind, subject, predicate, object?, at_time?, context? — states what the proof is about | A persisted primitive |
| Verification context | Everything the verdict depends on that is not in the proof bytes (clock, trust list, revocation data, algorithm policy, limits) | Proof content |
| Policy | Caller-supplied evaluation input: closed requirement set over verification state | Engine behavior |
| Report | Pipeline output: per-dimension verdicts + lifecycle + checks | Decision (policy output) |

## 3. Object model

### 3.1 Persisted primitives (wire schema per `docs/format.cddl`)

| Primitive | Required fields (v=1) | Optional |
|---|---|---|
| Event | `event_type` (open label), `subject` (reference string), `effective_at` (uint seconds), `payload_ref` (HashRef) | `metadata` (flat string→scalar, ≤16 entries) |
| Attestation | `issuer` (keyref), `subject`, `claim` (type + fields), `issued_at` | `expires_at`, `evidence_ref` |
| Evidence | `kind` (open label), `digest` (HashRef) | `attestation_ref`, `hint` (≤256 B) |
| Relationship | `from`, `rel_type` (open label), `to`; self-edges forbidden | `evidence_ref`, `attestation_ref` |
| Proof | `proposition`, sorted member arrays (events/attestations/evidence/relationships), `created_at` (informational) | — |

Definitions:

- **Entity** (conceptual primitive, represented by reference): any named
  thing — person, organization, device, document, transaction, package,
  software artifact, AI model, dataset, credential, location, account — is
  addressed by an **opaque reference string** (`subject`, `object`,
  relationship endpoints). The core MUST NOT interpret reference semantics.
  Reference-syntax recommendation (SHOULD): `ref:<namespace>:<kind>:<id>`;
  the core transports the string verbatim (DEF: namespace registry).
- **Claim**: structured map `{"type": tstr, "fields": {* tstr => text|uint|bool}}`.
  `type` is an open namespace; the reserved types `revoke`, `supersede`,
  `withdraw`, and `compromise` carry lifecycle semantics and MUST NOT be
  used for statements.
- **Event type / Evidence kind / Relationship type**: open label strings.
  Unknown labels are transported verbatim (IMP); acceptance is the policy's
  judgment (IMP), never a core decision.

### 3.2 Versioning of objects

Every persisted object carries `v`. `v==1` dispatches to the v1 parser;
any other value MUST produce `UNSUPPORTED_VERSION` (fail closed, IMP).
Canonicalization rules, id scheme (`:vN:`), hash display, and the policy
language are each independently versioned.

## 4. Canonical serialization (normative subset)

All signed content and all identifiers are computed over **deterministic CBOR
bytes** per RFC 8949 preferred serialization + core deterministic encoding
(`FORMAT.md` §1; `PE-FMT-001..009`; IMP).

| Rule | Norm |
|---|---|
| Allowed values | `uint`, `nint`, `text`, `bytes`, `array`, `map`, `bool`, `null` only |
| Forbidden constructs | floats, tags (incl. 0/1/18), indefinite lengths, bignums, simple values, reserved ai — MUST reject `FORBIDDEN_CBOR_CONSTRUCT` |
| Integers | shortest-form only; non-minimal → `NON_CANONICAL` |
| Maps | keys sorted bytewise-lexicographic by encoded key; duplicate keys → `DUPLICATE_MAP_KEY`; map order is NOT input-relative |
| Text vs bytes | distinct major types, never conflated; UTF-8 validated |
| Text normalization | **none**: ids and signatures bind exact UTF-8 bytes as given; no NFC/NFD folding/trimming anywhere in the engine (golden-20) |
| Time | `uint` seconds since Unix epoch; no fractional, no implicit timezone; human display converts separately |
| Limits | 1 MiB proof, 64 KiB field, depth 16, 256 array items, 64 map entries (configurable downward via `Limits`) |
| Canonicality check | decode MUST re-encode and byte-compare; mismatch → `NON_CANONICAL` |

**nint range constraint (imp.):** the v1 subset restricts nint to `i64`
(`-2^63..-1`). Implementers MUST enforce the same rejection (interop
requirement). Landed in `FORMAT.md` §1 (AUDIT F8 closed).

## 5. Identifiers and content addressing

- **Form:** `<prefix>:v1:<b64uNoPad(sha256(canonical))+>` where canonical is
  the deterministic CBOR of the object content (all fields except the id and,
  for attestations, the signature). Prefixes: `evt` `att` `evd` `rel` `prf`.
- **`proof_id`** binds the proposition, `created_at`, plus the **exact sorted** member id
  sets, constructed as the canonical CBOR map
  `{"v":1,"proposition":<prop>,"created_at":<uint>,"events":[sorted],"attestations":[sorted],
  "evidence":[sorted],"relationships":[sorted]}`. `created_at` IS covered by the binding
  (V1 CORE freeze deviation, pre-V1.0 wire fix — ARCHITECTURE-FREEZE.md §2 F2, FORMAT.md §3):
  a holder re-stamping `created_at` recomputes to a different id and fails `ID_MISMATCH`
  at IDENTIFIERS, so `proof_fresh` cannot be forged by rewrites. Composition linkage:
  when `referenced_proofs` is non-empty the binding gains one more sorted key
  `"referenced_proofs":[sorted prf ids]`; empty linkage encodes the identical map as V1
  (byte-identical ids). Optional bound `vocabularies` declarations behave the same
  (absent → byte-identical).
- **Verification** MUST recompute ids from bytes and reject mismatch with
  `ID_MISMATCH` (tamper evidence).
- **Base64url canonical spelling:** only the no-pad canonical re-encoding of
  a digest is accepted; pad-bit variant spellings MUST be rejected
  (PE-SEC-005, IMP).
- **Content digests** (`HashRef`): `{"v":1,"alg":0|1,"digest":bytes}` where
  `0=sha-256, 1=sha-384`; digest length MUST equal the algorithm length
  (32/48). Unknown alg → `UNKNOWN_ALGORITHM`.

---

## 6. Signatures and cryptographic suites

### 6.1 COSE_Sign1 profile (RFC 9052 §4.2; IMP)

- Envelope: untagged 4-element array `[protected, {}, payload, signature]`.
  Tag 18 MUST NOT be used (all tags forbidden).
- Protected header: exactly `{1: alg:int, 4: kid:bstr}` where `kid` is the
  raw public key bytes (32 B Ed25519, 64 B X||Y P-256). Any other label
  (including 6/Partial-IV) → `UNEXPECTED_HEADER_PARAM`.
- Unprotected header MUST be the empty map.
- Payload MUST be embedded (detached `null` rejected); payload is the
  canonical `AttestationContent` bytes.
- `Sig_structure = ["Signature1", body_protected, external_aad, payload]`
  with `external_aad = h'504531'` ("PE1"). Custom AAD is permitted only
  where both parties agree out-of-band (cross-domain isolation; default
  remains "PE1").

### 6.2 Algorithm registry (versioned, closed, fail-closed)

| COSE alg | Meaning | Policy |
|---|---|---|
| -19 | Ed25519 (RFC 8032 §5.1) | REQUIRED, default-on |
| -9 | ESP256 (ECDSA P-256 + SHA-256, RFC 6979 deterministic) | OPTIONAL, default-off |
| -8, -7, -35, -36 | deprecated polymorphic ids | MUST reject `DEPRECATED_ALGORITHM`, except explicit historical verification (below) |
| other | unknown | MUST reject `UNKNOWN_ALGORITHM` |

Historical verification (IMP, explicit opt-in via
`AllowedAlgs::allow_deprecated`): `-8` verifies through the Ed25519 op and
`-7` through the P-256 op (which additionally requires P-256 enabled),
answering "was this cryptographically valid then?". Acceptances are labeled
historical-only in SIGNATURES records; current acceptance stays a policy
decision, and obsolete crypto is a policy matter, never a history rewrite.
`-35`/`-36` have no verifier support: decodable, never verifiable.

Key refs: `key:ed25519:<b64u(32B)>`, `key:p256:<b64u(64B X||Y)>` — canonical
spelling enforced. Sign/verify MUST bind the payload `issuer` to the
verifying key's keyref (`attest` refuses otherwise); `kid` is a hint, never a
trust statement.

### 6.3 Algorithm and hash lifecycle

- New algorithms/hashes enter the **closed registry additively**, default
  off in every verifier, with new keyref prefixes. Removal is a major
  version with a migration window.
- Deterministic signatures (RFC 8032 Ed25519, RFC 6979 ECDSA) are required
  for byte-level reproducibility; a randomized-scheme introduction is a
  documented MAJOR change (PE-CRYPTO-010, `LONGEVITY.md` §5).
- Hybrid bridging (classical + PQ attestations, AND-of-issuers) is expressed
  with existing multi-issuer policy semantics (IMP semantics, DEF adoption).

## 7. Proof composition (linkage IMP; transitive resolution V2)

Composition answers: *given proofs A…D that share members, can one verifier
establish the combined claim without duplicated facts?*

**Union (IMP):** a Proof is a flat container; cross-proof provenance is
expressed by a caller *unioning* member sets into a new proof (members are
content-addressed, so reusing them costs nothing cryptographically;
`proof-cli compose` implements this).

**Linkage (IMP, additive):** an optional `referenced_proofs: [prf-ref…]`
array on Proof records which proofs a composition came from. Semantics:

1. Each `prf-ref` is a well-formed `prf:v1:` id (shape-checked at SCHEMA;
   content is never embedded and never fetched).
2. The containing proof's `proof_id` binds the sorted, deduped id set as an
   additional binding-map key (empty set ⇒ byte-identical V1 binding, so all
   existing proofs keep identical ids; golden-11 regenerates byte-identical).
3. Verification validates linkage as topology: sorted/deduped/bounded
   (`max_referenced_proofs`), no self-reference (`CYCLE_DETECTED`).
   References are reported REFERENCED — linkage only, contributing nothing
   to validity. There is deliberately no `EXTERNAL_DEPENDENCY_UNAVAILABLE`
   refusal: unresolvable-by-design references are normal offline state, and
   missing content yields INDETERMINATE through the ordinary evidence rules,
   never a new failure mode.
4. Transitive DAG resolution across bundles (fetch-and-verify chains, depth
   accounting) remains V2: the linkage this section specifies is what that
   resolution will traverse.
5. Policies may require or forbid referenced proofs explicitly (policy v2;
   v1 stays frozen).

## 8. Bundles and references (offline-first, normative behavior)

A **bundle** is the portable unit of exchange: a canonical container of one
or more proofs plus optional evidence blobs and status objects. Every
verification MUST report a **reference-availability matrix**:

- present and verified
- present but tampered (`ID_MISMATCH`/`SIGNATURE_INVALID`)
- absent (dangling)
- externally referenced (digest given, content withheld)

The engine NEVER silently treats missing evidence as valid (v1: digests-only
externals supplied by the caller; `DANGLING_REFERENCE`; G7). A verifier may
ignore unreferenced extra members. `allow_remote` remains `false` by
construction in v1; fetch-based resolution is an adapter-layer concern
(`ECOSYSTEM-ARCHITECTURE.md`).

## 8b. Transparency evidence model (first-class abstract capability, IMP)

Transparency is an architectural capability, not mandatory infrastructure:
proofs verify fully without it, and no log, chain, or server is required.
The abstract model the core implements — registration, receipt, inclusion,
consistency/non-equivocation, ordering — with log cryptography beneath in
adapters:

- **Registration**: a statement digest is submitted to a log. Modeled as
  `transparency_registration` evidence (digest-bound, adapter-supplied).
- **Receipt**: the log's signed inclusion promise. Modeled as
  `transparency_receipt` evidence bound (`attestation_ref`) to a checkpoint
  attestation; the receipt digest is verified, the promise semantics live in
  the adapter (Merkle proofs, consistency arguments).
- **Inclusion**: `transparency_inclusion{log}` holds iff a receipt is bound
  to a currently-valid `transparency.checkpoint` attestation issued by `log`
  (presence + binding + issuer + checkpoint freshness via its validity
  window) — the portable, offline-verifiable part.
- **Consistency / non-equivocation / ordering**: log properties asserted by
  checkpoints (sequence numbers, tree states) and checked by adapters and
  auditors; the core transports checkpoint claims opaquely and binds their
  issuers, never interpreting log internals.
- **Checkpoints** are ordinary attestations (`claim.type =
  "transparency.checkpoint"`, issuer = log identity, SHOULD carry
  `log`/`sequence` fields): signatures, validity windows, revocation, and
  compromise semantics apply unchanged — checkpoint freshness and log-key
  rotation fall out of existing machinery.

## 9. Verification procedure

### 9.1 Stages (fixed order; IMP)

1. **PARSE** — strict CBOR decode (subset §4), limits enforced pre-allocation.
2. **SCHEMA** — closed schemas, `v` checks, unknown fields rejected.
3. **CANONICAL** — re-encode-and-compare.
4. **IDENTIFIERS** — recompute every member id and `proof_id`; compare.
5. **SIGNATURES** — COSE_Sign1 verification per §6 (alg, key shape, envelope
   content matches stored content).
6. **KEYS** — key-reference ↔ alg consistency, issuer binding.
7. **TIME** — timeliness per §10 (issued/expires vs. verified_at ± skew).
8. **REVOCATION/SUPERSESSION** — apply signed status objects with authority
   checks; lifecycle per §11.
9. **EVIDENCE** — evidence digest bindings; attestation evidence_refs resolve.
10. **RELATIONSHIPS** — endpoints resolve; grounding for trust-relevant edges.
11. **GRAPH** — node/edge limits; SUPERSEDES linear-acyclic; depth bound.
    Provenance DAG profile (V1.1, opt-in via `require_acyclic_provenance` /
    `--require-acyclic`): when enabled, the full member graph must also be
    acyclic (`CYCLE_DETECTED`); default off — REFERENCES cycles are linkage
    (citations/see-also), not derivation. Derivation chains SHOULD enable it.
11b. **STATUS** — caller-feed hygiene (V1.1): malformed/unauthorized/
    future-dated/supplied-signature problems. Never flips validity; exposed
    via `status_inputs_valid`.
12. **POLICY (caller hand-off)** — pipeline reports `INDETERMINATE`; the
    caller evaluates policy (§12) on the verified state. The pipeline MUST
    NOT PASS by itself.
13. **FINAL** — emit the report (below).

### 9.2 Report: dimensioned verdicts

v1 (IMP) emits the triple `{cryptographic_validity, evidence_validity,
policy_decision}` + feed health `status_inputs_valid` (V1.1; STATUS-stage
failures never flip validity) + lifecycle records. The additive projection
`dimensions()` (IMP, `proof-verify/src/report.rs`) derives eight dimensions
from the same stage records without changing the triple, each with verdict ∈
`VALID | INVALID | INDETERMINATE | NOT_APPLICABLE`:

| Dimension | Decides | Source stages |
|---|---|---|
| structural | well-formed bytes | PARSE/SCHEMA/CANONICAL |
| cryptographic | signatures, hashes, id binding | IDENTIFIERS/SIGNATURES/KEYS |
| evidence | evidence supports proposition per rules | EVIDENCE/RELATIONSHIPS/GRAPH |
| provenance | lineage/graph integrity (v2) | GRAPH + composition |
| temporal | timeliness at verifier clock | TIME |
| revocation | signed status | REVOCATION |
| policy | requested requirements | POLICY (caller) |
| overall | aggregation defined by policy (v2) | projection |

Aggregation default (v1 semantic, preserved): `overall` = AND over applicable
dimensions; `INDETERMINATE` in any trust dimension ⇒ never `PASS`;
`NOT_APPLICABLE` is reported when a dimension has no input (e.g. provenance
with no edges) and does not itself fail.

### 9.3 Conflict and contradiction as native states (IMP)

The report carries `conflicts[]` alongside validity — contradiction is a
native, first-class state, not an error and not a verdict:

- **Divergent claims** (`divergent_claims`): same `(claim.type, subject)`,
  differing fields among verified statements. Identical re-assertion is
  corroboration and stays silent.
- **Denials** (`denial`): a verified statement carries `denies:
  <attestation-id>`. Resolvable targets anchor on the denied claim;
  unresolvable targets are external denials (asserter recorded, never failed:
  denying another system's claim is legitimate).
- **Contradictions** (`contradiction`): a grounded `CONTRADICTS` edge between
  two verified statements (third-party contradiction assertions).

All three leave validity unchanged. The core represents opposition; it never
decides reality. Adjudication composes in policy v2 (`any` for alternative
authorities, `threshold` for quorums, `not` + `no_conflicting_evidence` for
strictness).

### 9.3 History vs currentness (IMP)

The report separates **historical validity** (was it valid then, as
recorded?) from **current acceptance** (is it acceptable now under this
context/policy?). A SUPERSEDED attestation keeps evidence validity (`VALID`,
history preserved) while `not_superseded` policy fails it for current use.
Correctness requirement: none of these may be collapsed in any projection.

## 10. Time model (IMP unless noted)

- Time values are `uint` Unix seconds. No fractional, no implicit timezone.
- **Event time** (`effective_at`): asserted occurrence time; factual claim,
  not proof of wall-clock truth.
- **Attestation time** (`issued_at` / `expires_at`): assertion issuance and
  validity bounds; `expires_at` may be absent (unbounded).
- **Verification time** (`VerifyCtx.verified_at`): caller-supplied clock.
  `0` = "no trustworthy clock" sentinel ⇒ every timeliness check fails
  (`EXPIRED`).
- **Skew** (`clock_skew_leeway`, default 300 s): symmetric, saturating;
  absorbs honest drift only. `issued_at ≤ now+skew` and
  `now ≤ expires_at+skew`.
- **Freshness** (`revocations_known_at`): missing, or older than
  `verified_at+skew`, ⇒ revocation status `UNKNOWN` ⇒ fail closed.
- A timestamp establishes an assertion about time — not objective truth
  (DEF: clock-uncertainty records; transparency anchoring).

## 11. Lifecycle, revocation, supersession, withdrawal, compromise (IMP)

Per signature-verified statement-attestation, exactly one state:

`ACTIVE` (within validity, no valid status, fresh info) ·
`EXPIRED` (`EXPIRED`) · `REVOKED` (`REVOKED`) · `SUPERSEDED` (historical,
evidence stays valid) · `COMPROMISED` (`COMPROMISED`: issued at/after a valid
signed compromise instant for its issuer; tainted, history NOT preserved) ·
`UNKNOWN` (`REVOCATION_UNKNOWN`, fail closed).

Precedence: `COMPROMISED > REVOKED > SUPERSEDED > EXPIRED > UNKNOWN > ACTIVE`.

Per evidence item, one derived status: `AVAILABLE` · `WITHDRAWN`
(`WITHDRAWN`: valid signed withdrawal; history preserved) · `COMPROMISED` ·
`REVOKED` · `SUPERSEDED` (history preserved) · `EXPIRED` · `UNKNOWN` ·
`UNAVAILABLE` (adapter-reported only). Precedence: `COMPROMISED > WITHDRAWN
> REVOKED > SUPERSEDED > EXPIRED > UNKNOWN > AVAILABLE`. A backing
attestation that is absent (not verified in-proof) is recorded UNKNOWN with
validity preserved — `attestation_ref` is a provenance hint, never a
validity input (fail on disproof, note on absence); strict callers use
`evidence_usable`.

- Status objects are signed attestations (`claim.type =
  revoke|supersede|withdraw|compromise`); unsigned lists are never trusted.
- A status applies only if: claim well-formed AND kind-appropriate authority
  (revoke/supersede: target's original issuer or `revocation_authorities`;
  withdraw: authorities, target attestation's issuer, or bound-attestation
  issuer for evidence; compromise: target identity itself or authorities)
  AND not future-dated (`issued_at ≤ now+skew`). Else
  `UNAUTHORIZED_STATUS`/`EXPIRED`/`SCHEMA_VIOLATION` — never applied.
- Status objects never satisfy `issuer_trusted` and never contribute validity
  intervals (PE-TRUST-004).
- A status targeting ids outside the proof is still signature-verified and
  echoed, with no lifecycle impact here.

## 12. Policy interface (IMP v1 contract)

The policy layer is the **only** thing that turns verification facts into a
decision. Same evidence under different policies may yield different
decisions.

**V1 language (frozen):** JSON `{"policy_version":1,"policy_id",
"requirements":[...]}` — implicit AND over a closed set of ten requirement
types: `signature_valid`, `issuer_trusted{issuer}`,
`issuer_excluded{issuer}`, `relationship_exists{relationship}`,
`not_expired`, `not_revoked`, `not_superseded`, `evidence_present{kind}`,
`transparency_present`, `proof_fresh{max_age_seconds}`.

Rules:

- Policy is validated before evaluation (`POLICY_INVALID` on any syntax/
  field/version error); never evaluated partially, never executed as code.
- Decisions: `PASS` (valid proof + all requirements pass), `FAIL` (valid
  proof + a requirement fails), `INDETERMINATE` (proof/crypto/evidence not
  established — requirements neither satisfied nor refuted).
- Evaluation is a pure deterministic function of
  (`VerifiedState`, `Policy`, `EvalInputs`); defaults fail closed.
- Trust list: valid signature alone never confers trust. `issuer_trusted`
  requires list membership AND a signature-verified attestation in proof.
- `proof_fresh` bounds self-declared age against the verifier clock:
  `created_at` IS covered by `proof_id` (V1 CORE freeze deviation, pre-V1.0
  wire fix), so a holder re-stamp breaks the binding (`ID_MISMATCH`).
  It is still not a trusted timestamp — pair with signed attestation
  windows and transparency anchoring for strong freshness.
- Direct `evaluate_policy` callers keep trust inputs within
  `Limits::max_trusted_issuers` (the one-shot `verify_and_evaluate`
  enforces this and fails closed with `LIMIT_EXCEEDED`).
- Extension: new semantics (freshness windows, external state) arrive only
  via a new `policy_version` with a capability row — never a schema hack.

## 12b. Policy v2 language (IMP)

`policy_version: 2` carries `expression` (never `requirements`; v1 rejects
v2 leaf names, freezing v1 byte-for-byte). Connectives `all`/`any`/`not`/
`threshold{k, of}` over leaves; every child evaluates (complete
explanations). INDETERMINATE stays reserved for unevaluated policy (broken
preconditions), exactly like v1 — leaves are boolean once the guard passes.
Vacuous shapes (`all[]`, `k=0`, `k>n`, mixed connectives) are
`POLICY_INVALID`; total nodes ≤ `max_policy_requirements`. New leaves:
`delegated_authority{root, issuer, scope?}`, `identity_bound{a, b}`,
`transparency_inclusion{log}`, `no_conflicting_evidence`,
`vocabulary_accepted{ns, max_version}`, `evidence_usable{kind}`,
`requires_reference{id}`, `forbids_reference{id}` (direct linkage hooks;
transitive closure is the bundle layer).
Canonical CBOR mirrors the tree; content hashes read `policy:v2:…`.

## 13. Error taxonomy (IMP, stable wire strings)

Codes are protocol: renaming/renumbering is a breaking change. Complete table
in `ERROR-MODEL.md` (24 codes). Conventions: every failure is recorded with
(stage, object, code, message); early exits report evidence invalid, never
vacuous; `Invalid` verdicts always carry ≥1 code; unknown is never converted
to valid.

## 14. Verification context (single object, normative)

`VerificationContext` (`proof-verify/src/context.rs`) is the single normative
shape; `VerifyCtx` (pipeline) and `EvalInputs` (policy) are thin projections
via `From` impls (AUDIT F6 closed). `verify_and_evaluate` pairs both layers
from one context so clock/trust can never diverge.

```
VerificationContext {
  verified_at: u64            // 0 = no trustworthy clock
  clock_skew_leeway: u64     // 300 default
  allowed_algs: {...}        // closed registry switches
  trusted_issuers: [keyref]  // policy trust list, per-evaluation-time
  revocation_authorities: [keyref]
  status_objects: [SignedStatus]   // or via StatusSource.with_status_source
  revocations_known_at: Option<u64>
  limits: Limits
  allow_remote: bool          // v1 MUST be false (zero network I/O)
  report_all_failures: bool   // true = collect past CANONICAL (PARSE/SCHEMA always fail fast)
  accepted_vocabularies: [{ns, max_version}]
  extra_grounded: [label]     // future trust-relevant edge kinds (default [])
  // v2: min_version, jurisdictions, security profile, trust anchors
}
```

The context is echoed (never trusted) in reports/explanations so a consumer
can audit which inputs produced the verdict.

## 15. Portable artifact container (standard, IMP)

The v1 CLI exchanges artifacts as versioned envelopes (`ArtifactEnvelope`,
`proof-format/src/envelope.rs`): `{"container_version":1,"kind","id","cbor":
hex}` + attestation extras (`sign1`, context), with `export`/`import`/
`convert`/`compose` in `proof-cli/src/port.rs`. The shape below is the
standard (AUDIT §8.3, CAP-047):

```
ArtifactEnvelope {
  "container_version": 1,
  "kind": "event|attestation|evidence|relationship|proof|status",
  "id": "<canonical id>",
  "cbor": "<hex of canonical CBOR>",
  // optional, kind-specific, always re-verifiable:
  "sign1": "<b64u COSE_Sign1>"   // attestations/status
  "provenance": [{"created":..., "by":..., "via":...}]  // informational only
}
```

Rules: every field is advisory except `kind`/`cbor`; any consumer MUST
re-derive `id` and, where present, verify `sign1` from `cbor`. JSON is for
human/transport interchange only — never signed, never canonical. A binary
container format (sealed envelope) is a v2 item.

## 16. Versioning and compatibility (IMP)

| Layer | Version signal | On mismatch |
|---|---|---|
| Objects | `v` | `UNSUPPORTED_VERSION` |
| Ids | `:vN:` infix | PARSE reject |
| Policy | `policy_version` | `UNSUPPORTED_VERSION` |
| HashRef | `v` | `SCHEMA_VIOLATION` |
| Algs | registry numbers | unknown/deprecated fail |
| Vocabularies | declared `{ns, version}` vs accepted set | notes only (acceptance is policy) |

Rules: unknown versions fail closed; requirement strings and error-code wire
strings are stable; `proof_id` construction is stable; the canonical CBOR
subset only ever shrinks; fixture vectors are append-only. Compatibility
promise: same bytes + same inputs ⇒ same report, byte-for-byte, across
V1.x implementations.

### 16b. Vocabulary evolution (IMP mechanism)

New vocabulary arrives without changing old semantics, through three
mechanics that compose:

1. **Open labels, closed fields** (unchanged): unknown label strings
   transport verbatim; unknown map fields reject. New meaning never
   redefines old bytes.
2. **Namespaces**: label text before the first `:` is its namespace
   (`acme:invoice`), else `legacy`. Namespaces are provenance: collisions
   across namespaces are impossible by construction, and verifiers never
   fold or merge them.
3. **Declarations**: proofs optionally declare `vocabularies: [{ns,
   version}]`, bound by `proof_id` when present (absent in V1 bytes →
   byte-identical). Contexts optionally restrict via `accepted_vocabularies`;
   the pipeline notes undeclared use, unknown namespaces, and over-max
   versions — informational only. Policy v2 `vocabulary_accepted` adjudicates.

A future vocabulary needs no core change while it fits labels + optional
fields; a future *structural* shape needs a new object/policy `v` with a
migration window. That is the whole evolution mechanism, and it is why the
core can stay small while the ecosystem grows unboundedly.

## 17. Interoperability requirements (IMP)

- **I2-I3:** a second implementation MUST agree on canonical bytes, ids,
  signature validity and verdict triples for all golden vectors — proven
  continuously by `interop/differential.py` (both directions).
- Golden vectors are normative: `fixtures/golden-01..31`, each embedding its
  expected verdict triple + codes; generators self-check before writing.
- A conformant implementation MUST implement the complete §4 subset, §5 id
  construction, §6 COSE profile, §9 stages, §12 policy semantics, §13 codes.
- Independent implementers MUST NOT silently relax any fail-closed rule,
  canonicality check, or limit.

## 18. Security invariants (normative; details in SECURITY-MODEL.md)

1. Fail-closed defaults for every unknown (version, alg, field, state).
2. No global state: all trust inputs caller-supplied, engine stateless.
3. Zero network I/O inside verification (v1).
4. Canonical round-trip identity enforced on decode.
5. IDs recomputed from bytes; tamper ⇒ `ID_MISMATCH`.
6. Signatures over canonical bytes only, domain-separated ("PE1").
7. Revocation is always signed; status signer authority enforced.
8. Bounded resources before allocation-heavy work; no parser panics (AUDIT F5
   remediation required); no unbounded recursion.
9. Explanation is a pure projection of the report — cannot contradict it.
10. Historical artifacts remain interpretable; obsolete crypto is a *policy*
    matter, never a history rewrite.

## 19. Normative references

RFC 8949 §4.1/§4.2.1 · RFC 9052 §3/§4.2/§4.4/§9 · RFC 8152 (obsolete, negated) ·
RFC 8032 · RFC 6979 · RFC 4648 §5 · FIPS 180-4 · IANA COSE registry.
Repo files: `docs/format.cddl` (wire), `docs/policy-grammar.ebnf` (policy),
`FORMAT.md`, `SPEC.md`, `CRYPTO.md`, `POLICY.md`, `LIFECYCLE.md`, `TRUST.md`,
`ERROR-MODEL.md`, `VERSIONING.md`, `INTEROPERABILITY.md`, `LONGEVITY.md`,
`docs/requirements-matrix.md`.

## 20. Conformance statement

A v1-conformant implementation MUST: (a) reject everything the subset
forbids; (b) derive ids exactly as §5; (c) verify COSE exactly as §6;
(d) run the stages in order with no silent reordering; (e) never emit PASS
from the pipeline alone; (f) fail closed on every §18 invariant; (g) agree
with the Rust implementation on all golden vectors and on any verdict where
contexts are equal. Anything this document marks DEF is not part of v1
conformance and must fail closed until released under its capability row.