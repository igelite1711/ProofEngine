# ARCHITECTURE-FREEZE.md — Proof Engine Semantic Freeze (Candidate → FROZEN)

> **Status:** FROZEN (promoted from `FREEZE-CANDIDATE.md` after the §53 gate
> review below). This document is normative: where it differs from any other
> document on frozen semantics, this document wins; where it differs from
> `docs/format.cddl` on wire bytes, the CDDL wins.
>
> **Pin:** commit `51ce178`, tag `freeze-candidate-1`,
> `fixtures/golden-01..31` (31 vectors), `interop/differential.py` 37 checks
> both directions.

---

## 1. Governing abstraction (immutable)

A Proof is a portable, cryptographically bound package of assertions and
their supporting evidence and provenance, evaluated by a verifier under an
explicit verification context. The engine is a
claim/evidence/provenance/verification engine — not a truth engine, trust
authority, or decision maker.

```
CLAIMS + EVIDENCE + ATTESTATIONS + PROVENANCE + CRYPTOGRAPHIC BINDINGS
     + OPTIONAL TRANSPARENCY EVIDENCE
                  │
                  ▼
  PROOF + VERIFICATION CONTEXT → VERIFICATION RESULT + POLICY → DECISION
```

## 2. IMMUTABLE: the frozen set

| # | Frozen element | Norm |
|---|---|---|
| F1 | Canonical CBOR subset | RFC 8949 preferred + deterministic encoding; shortest ints; bytewise-lexicographic maps; dup keys rejected; floats/tags/bignums/indefinite/simple forbidden; `nint` restricted to `i64`; re-encode-and-compare everywhere (`FORMAT.md` §1) |
| F2 | Identifiers | `<prefix>:v1:<b64uNoPad(sha256(canonical))>`; full 32-byte digests only; pad-bit spellings rejected; `proof_id` binds proposition + exact sorted member id sets (+`referenced_proofs`/`vocabularies` keys only when non-empty; `created_at` never covered) |
| F3 | COSE_Sign1 profile | Untagged; protected exactly `{1:alg, 4:kid}`; empty unprotected; `external_aad=h'504531'`; closed registry (`-19` required, `-9` opt-in default-off; `-8/-7/-35/-36` deprecated); `kid==issuer` binding |
| F4 | Verification order | 11 check stages (`PARSE→…→GRAPH`) + caller POLICY hand-off + FINAL = 13 fixed positions; failures recorded never repaired; unknown never becomes valid |
| F5 | Verdict shape | Triple `{cryptographic_validity, evidence_validity, policy_decision}` + lifecycle/evidence-status/conflict records + additive 8-dimension projection; pipeline never emits `PASS` alone |
| F6 | Error codes | 24 stable wire strings (`ERROR-MODEL.md`); append-only; renaming is breaking |
| F7 | Lifecycle | 6 attestation states (`COMPROMISED>REVOKED>SUPERSEDED>EXPIRED>UNKNOWN>ACTIVE`) + 8 evidence states; signed status objects only; `SUPERSEDED` preserves history; `COMPROMISED` taints |
| F8 | Policy V1 | Implicit AND over the closed 10; `POLICY_INVALID` before eval; `PASS/FAIL/INDETERMINATE`; valid signature ≠ trusted ≠ satisfied |
| F9 | Open vocabularies | Unknown labels transported verbatim; acceptance is policy; unknown fields rejected |
| F10 | Offline, stateless core | Zero network I/O in `verify_proof()`; all trust inputs caller-supplied and echoed; `same bytes + same inputs ⇒ same report` |
| F11 | Interop contract | 31 golden vectors normative; second implementation must agree on bytes/ids/signatures/bindings both directions |

## 3. EXTENSIBLE: what may evolve without reopening

| Class | Mechanism (no core rewrite) |
|---|---|
| Cryptographic suite | New COSE number + `key:<name>:` prefix + closed-registry row, default-off, hybrid dual-attestation via AND (`CRYPTOGRAPHY.md` §2) |
| Hash migration | `HashRef.alg` enum + `:v2:` ids with dual-verify window (`LONGEVITY.md` §3) |
| Policy language | New `policy_version` with capability row; v1 byte-stable forever |
| Trust-relevant edges | `extra_grounded` context set beyond V1 `requires_grounding()` |
| Transparency/storage/transport | Adapters behind `StatusSource`/`ArtifactStore`/`Bundle`/envelope; log crypto lives in adapters |
| Identity methods | Additive keyref prefix + op behind `is_supported_keyref` |
| Privacy (selective disclosure, ZK) | Digest commitments + member subsets + `referenced_proofs`; mechanisms in adapters |
| Domain semantics | Profiles/vocabularies/policies above the core; zero mechanism branches |

## 4. §53 gate answers (summary; evidence in `FREEZE-CANDIDATE.md` §3)

Semantic: universally applicable (12-domain differential); claims first-class (`Claim`+`Proposition`); evidence≠claim; attestations explicit; provenance first-class (edges+grounding+linkage+bundles); relationships explicit+open; identity contextual (never provider); delegation generic (root-pinned ACTIVE chains); lifecycle explicit (6+8); conflict representable (3 native states, validity unchanged); uncertainty explicit (`UNKNOWN`/`INDETERMINATE`/`NOT_APPLICABLE`).
Cryptographic: deterministic canonicalization; agility via closed registry; replaceable/deprecatable algorithms; historical algorithms identifiable (`allow_deprecated`, historical-only labels); 31 golden vectors.
Verification: layered (11+POLICY+FINAL); context explicit (`VerificationContext`); historical≠current; policy≠verification; explainable (machine+human projections).
Interoperability: VC/PROV/C2PA/SCITT mappings as adapters; stdlib-only second implementation, 37 checks both directions; no PE service required.
Scalability: event/transaction/batch-able/composed models; `Limits` at every boundary; graph attacks addressed (linear SUPERSEDES, depth/node/edge caps, cycle detection).
Evolution: explicit versioning per layer; extension behavior defined (`EXTENSION-MODEL.md`); schemas evolve via `v`; vocabulary via open labels+namespaces+declarations; crypto via registry; policy via versions.
Neutrality: 12 industries, same core, zero branches; no mandatory infrastructure.
Durability: 2126 test passes (`COMPATIBILITY.md` §4 + `LONGEVITY.md`); independence test passes (offline, stdlib verifier, spec-built second implementation).

## 5. Reopen procedure (the freeze rule, §54)

After this point, no feature may modify §2 merely because it is convenient.
Classify first: CORE / GENERIC EXTENSION / ADAPTER / DOMAIN PROFILE /
APPLICATION / INFRASTRUCTURE. If a requirement appears to need a frozen
change, write `docs/ARCHITECTURE-CHANGE-PROPOSAL-<topic>.md` from
`docs/ARCHITECTURE-CHANGE-PROPOSAL-TEMPLATE.md` and prove: existing
primitives cannot represent it; extension tried and failed; security,
compatibility, migration, verifier, and durability impacts acceptable. Only
a genuine foundational deficiency reopens the freeze, by explicit
maintainer decision with a new pin recorded here.

## 6. Post-freeze change log (extensions only; §2 untouched)

| Commit | Classification | Layer | Verdict impact |
|---|---|---|---|
| `af2242b` (P4) | GENERIC EXTENSION | `proof_verify::resolve_proof_chain` + `proof-cli resolve` behind the `ArtifactStore` seam (bundle layer; P4 of `MIGRATION-PLAN.md`) | None by construction: root report reproduced verbatim; anything unresolved is `complete == false`, never a verdict change |

## 7. Final freeze decision record (2026-09-11, independent re-audit)

Independent re-audit of the pinned tree and everything committed above it,
per the master program's §56 cycle (investigate → verify → attack → freeze):

**Verdict: FROZEN** — the semantic foundation at commit `51ce178`
(tag `freeze-candidate-1`) is immutable per §2. Everything above the pin is
extension work governed by §3/§5/§6.

Evidence re-verified in this session (live tree = pin + extensions):

| Gate | Result |
|---|---|
| Workspace build + tests | 267 passed, 0 failed (32 binaries; includes resolve + V2-leaf suites) |
| Domain differential (12 industries) | 6/6 pass — identical verdict shape across journeys |
| Golden vectors | 31/31 CDDL-validated (`tools/validate_cddl.py`) |
| Independent verifier (stdlib-only Python) | `interop/differential.py`: 37 pass, 0 fail, both directions (I2/I3a/I3b/negatives) |
| Traceability | 88 PE-ids in matrix+code, all test-linked |
| Neutrality | 47 mechanism files, zero domain vocab in mechanism sources |
| No-panic (PE-SEC-004) | clean in all production paths |
| fmt / clippy (`-D warnings`) | clean |
| Web-demo honesty gate | embedded data == fresh CLI output (`check_web_demo.py`) |

Adversarial re-attack (this session): canonicalization (shortest-form, dup
keys, forbidden constructs, re-encode-and-compare), id full-digest and
pad-bit rejection, algorithm confusion + deprecated ids fail-closed, PQ
header parse-neutrality, supersession history preservation vs revocation
currency, compromise taint semantics, revocation authority and freshness
fail-closed, graph grounding/dangling/cycle/depth/edge limits, DoS bounds at
every parser/verifier boundary (`Limits`), inner-content-vs-envelope
agreement, status-object end-to-end re-verification — all confirmed in code
and covered by tests/fuzz seeds.

Residual open items (process, not semantic — none reopen §2):

1. In-flight uncommitted work at the time of this record (V2
   `requires_reference`/`forbids_reference` leaves + resolve hardening +
   doc sync) is a continuation of the `freeze-candidate-1-1` extension line.
   It was verified green in the live tree (frozen v1 stays byte-stable:
   `v1_rejects_v2_leaf_names_and_stays_frozen`). It must land as commits
   inside the §3 (policy `policy_version` capability row) and §6
   classification before release.
2. Guide pages for 8 of the 12 demonstrated industries remain deferred to
   P12 (`docs/INDEX.md`); not a semantic gap.
