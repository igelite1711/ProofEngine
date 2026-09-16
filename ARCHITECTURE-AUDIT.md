# Proof Engine — Architecture Audit

> **Status:** Complete (2026-09-10). As-built audit of the V1 repository at
> commit `1738644`. This is the Phase-0 deliverable of the "ultimate
> architecture" program. It records what is genuinely foundational, what is
> accidental, what is domain-specific, what should be generalized, removed,
> redesigned, moved outside the core, become an extension, become a standard,
> or remain application-specific — with evidence pointers for every claim.
>
> **Method rule:** every statement below is traced to code, tests, docs, or
> CI log evidence. Nothing is asserted from reputation or hope.

---

## 0. Executive verdict

Proof Engine V1 is an **exceptionally sound foundation**. The cryptographic
core (canonical CBOR, content-derived identifiers, COSE_Sign1, staged
verification, fail-closed culture) is among the most disciplined designs seen
in this problem space. The audit found:

- **No surviving blockers** in the trust-critical paths (canonicalization,
  identifier binding, signature verification, lifecycle, policy evaluation).
- **Two documentation lie-by-implementation defects** (F1 `report_all_failures`
  dead config; F2 stale `ARCHITECTURE.md` unknown-type claim) and **a genuine
  no-panic invariant violation surface** (F5), all low-risk but real.
- **A coherent universal model**: five persisted primitives + two value
  objects, open vocabularies, explicit verifier context, and a hard
  separation of cryptographic validity ≠ evidence validity ≠ policy decision.
- **Neutrality by construction**, proven by a five-industry differential
  suite that runs the identical core — not by prose.
- **Independent verification** (stdlib-only Python verifier/creator), golden
  vectors, four fuzz targets, deterministic demo — an interop posture most
  projects never reach.

The gaps are not "what is broken" but "what the V1 boundary deliberately
left out" (composition, partial-verification dimensions, adapters, SDKs,
ingestion, batch) — all consistent with the master architecture program, and
all additive without touching the core data model.

Severity-ranked action register: Section 10. Full traces: Section 11.

---

## 1. Audit method & scope

### 1.1 What was examined

| Area | Evidence |
|---|---|
| All 7 workspace crates | `crates/proof-{core,format,crypto,graph,verify,policy,cli}/src` fully read |
| All crate tests | `crates/*/tests/*.rs` (golden, lifecycle, proof, policy, soak, chain, cli_e2e) |
| Domain proof-suite | `domains/proof-domains/tests/*.rs` (excluded consumer crate) |
| Independent verifier | `interop/{minicbor,pengine,differential}.py` (stdlib-only) |
| Fuzz targets | `fuzz/fuzz_targets/{cbor_decoder,graph_ingest,policy_parser,proof_verify}.rs` |
| CI / supply chain | `.github/workflows/{ci,interop,fuzz}.yml`, `deny.toml`, `Cargo.lock`, `rust-toolchain.toml` |
| Docs (5,036 lines) | root `*.md`, `docs/*.md`, domain docs, CDDL + EBNF grammars |
| Build & test | `cargo build --locked` EXIT=0; `cargo test --locked` full suite EXIT=0 at audit time |
| Git state | single commit `1738644`, clean tree |

### 1.2 Commands executed

```
cargo build --locked                 # EXIT=0
cargo test --locked                  # EXIT=0 (full suite green)
grep -rn 'unwrap()|expect(|panic!'   # panic-surface scan across crates/*/src
find                                 # full source/doc/line inventory
```

### 1.3 Existing self-audit posture

The repository already self-audits continuously: `make trace` pins 75 PE-xxx
requirement rows to implementation + positive/negative tests; `make neutrality`
gates domain vocabulary out of mechanism sources; `make demo` byte-pins
determinism; `interop/differential.py` cross-checks Rust against Python both
directions. This audit builds on those gates instead of re-running every
sub-check.

## 2. As-built inventory

### 2.1 Workspace map (all path deps — no unreviewed source)

```
crates/
  proof-core/    463 L  domain model, 22 error codes, Limits, HashRef   [0 external deps]
  proof-format/  1,752 L deterministic CBOR subset + closed schemas      [core, thiserror]
  proof-crypto/  1,565 L hashes, ids, COSE_Sign1 (-19 req / -9 opt)      [sha2, base64, hex,
                                                                          ed25519-dalek, p256]
  proof-graph/     374 L typed directed-graph validation (verified inputs)
  proof-verify/  1,033 L ProofBuilder + 11-stage pipeline + VerifyReport [depends on graph]
  proof-policy/    942 L closed requirement set, deterministic evaluator [depends on verify]
  proof-cli/     3,568 L dispatcher, artifact I/O, demo, inspect, graph, doctor, journey
excluded (standalone):
  domains/proof-domains/  1,148 L  5-industry consumer suite (PE-NEUT-003)
  fuzz/                     177 L  4 cargo-fuzz targets (nightly only)
interop/  Python stdlib-only independent verifier + creator (I2/I3)
tools/    traceability, neutrality, CDDL, web-demo, bench, publish
demo/     deterministic demo + offline browser UI (generated)
fixtures/ golden-01..23 (normative for interop)
```

### 2.2 Data model (five persisted primitives)

| # | Primitive | ID | Signed? | Role |
|---|---|---|---|---|
| 1 | Event | `evt:v1:` | no | happening-record: type, subject, effective_at, payload digest, metadata |
| 2 | Attestation | `att:v1:` | yes (COSE_Sign1) | issuer-bound claim + validity window + optional evidence_ref |
| 3 | Evidence | `evd:v1:` | no (id-bound) | digest-bound reference + optional attestation_ref |
| 4 | Relationship | `rel:v1:` | no (id-bound) | typed edge from→to + evidence_ref + attestation_ref |
| 5 | Proof | `prf:v1:` | no (binds members) | proposition + sorted member id sets |

Non-persisted roles: `Proposition` (value object), `StoredAttestation`
(content + sign1), `Policy` (evaluation input), status objects (revoke /
supersede are signed **attestation subtypes**, never unsigned lists).

### 2.3 Verification pipeline (stages, fixed order)

PARSE → SCHEMA → CANONICAL → IDENTIFIERS → SIGNATURES → KEYS → TIME →
REVOCATION/SUPERSESSION → EVIDENCE → RELATIONSHIPS → GRAPH → POLICY
(caller hand-off) → FINAL triple `{cryptographic_validity,
evidence_validity, policy_decision}` + per-attestation lifecycle +
explanation basis. Fail-closed: unknown at any stage → never PASS.

### 2.4 Trust inputs (all caller-supplied, none stored)

`VerifyCtx { verified_at, clock_skew_leeway, trusted_issuers, allow_remote=false,
allowed_algs, limits, status_objects, revocation_authorities, revocations_known_at,
report_all_failures }`. Zero-clock sentinel fails every time check. Missing/stale
revocation information ⇒ `UNKNOWN` ⇒ fail closed.

## 3. What is genuinely foundational (preserve, never weaken)

**G1 — Canonical CBOR as the single signed representation.** RFC 8949
preferred serialization + core-deterministic encoding: shortest-form ints,
bytewise-lexicographic maps, duplicate keys rejected, floats/tags/bignums/
indefinite/simple forbidden, depth 16 / 1 MiB proof / 64 KiB fields, re-encode
-and-compare on decode (`cbor.rs`; `PE-FMT-001..007`). This is the entire
interop surface and must not fork in any direction.

**G2 — Content-addressed, versioned identifiers.** `<prefix>:v1:<b64u-nopad
(sha256(canonical))>`; `proof_id` binds the proposition plus the exact sorted
member id sets; ids recomputed on every verify (`id.rs`, `PE-CRYPTO-007/009`).
Includes the pad-bit canonical-spelling defense — stronger than most systems.

**G3 — Closed COSE_Sign1 profile with domain separation.** Protected header
exactly `{1:alg, 4:kid}`, empty unprotected, `external_aad` = `h'504531'`
("PE1"), untagged outer array, Ed25519 (-19) required + ESP256 (-9) opt-in,
deprecated polymorphic ids `-8/-7/-35/-36` rejected, `kid`-to-issuer binding
(`cose.rs`, `PE-CRYPTO-001..004`). The parser is algorithm-number-neutral and
PQ-migration-tested (`cose.rs::pq_and_classical_same_structure`).

**G4 — The staged verification pipeline.** Eleven check stages with fixed
order, per-stage `CheckRecord`, failures recorded never repaired, stable
error codes, and the separated triple — the master prompt's "never collapse
the levels of truth" implemented as running code (`pipeline.rs`,
`PE-VERIFY-011`).

**G5 — Explicit verification context.** Nothing trust-relevant lives inside
the engine: clock, trust list, revocation data, allowed algorithms, limits
are caller inputs echoed in the explanation basis (`VerifyCtx`). This is the
"verifier supplies context, proof contains facts" principle verbatim.

**G6 — Lifecycle as a state machine (validity × currentness × freshness).**
`ACTIVE | EXPIRED | REVOKED | SUPERSEDED | UNKNOWN` with precedence
`REVOKED > SUPERSEDED > EXPIRED > UNKNOWN > ACTIVE`; SUPERSEDED preserves
historical validity; status objects are signed attestations with per-target
authority (`LIFECYCLE.md`, `pipeline.rs` stages 7–8). This satisfies
"historical vs current validity" and "revocation must be signed".

**G7 — Privacy by digest.** Payloads are digest-only refs; no content ever
enters proofs; no fetch in the verifier. External evidence is supplied by the
caller and authenticated by digest comparison (`PE-EVID-003`).

**G8 — Open vocabularies + policy-governed acceptance.** EventType,
EvidenceKind, RelType are open string wrappers; namespaced domain labels ride
through the closed schemas; policy — not core — judges vocabulary
(`model.rs`, `PE-FMT-008`, `PE-NEUT-001/002`).

**G9 — Independent verifier and normative vectors.** Stdlib-only Python
implementation (parse/canonical/id/signature/proof-binding), I2 + I3 both
directions, 23 golden vectors with embedded expected verdict triples
(`interop/`, `fixtures/`, `PE-INTEROP-001..003`). A second implementation
already agrees byte-for-byte — the strongest correctness evidence in the repo.

**G10 — Self-checking builders.** Every `create_*`/`attest`/`make_*`/
`ProofBuilder::build` round-trips through canonical CBOR + closed schema +
id assignment and refuses to sign bytes the issuer field disowns
(`build.rs`, `builder.rs`). Build-time self-checks make codec drift a build
failure, not a verification surprise.

**G11 — Fail-closed defaults everywhere.** `verified_at=0` ⇒ expired; empty
trust list ⇒ un-trusted; missing/stale revocation info ⇒ `UNKNOWN`; unknown
version/alg/field ⇒ loud code, never silent PASS.

**G12 — Traceability and honesty gates.** 75 PE-xxx rows machine-checked;
neutrality grep gate; demo byte-determinism sha256 gate; fuzz build gate per
PR — operational discipline that makes later phases cheap.

## 4. What is accidental (findings register)

| # | Finding | Severity | Evidence | Disposition |
|---|---|---|---|---|
| F1 | `VerifyCtx.report_all_failures` is documented ("report all failures instead of stopping at the first") but **never read** by the pipeline | Medium (doc lie; dead config) | `pipeline.rs:58,73` only; zero other references | Implement fail-collect mode or remove field; docs must match code |
| F2 | `ARCHITECTURE.md` §3.1 still says unknown event types "reject (fail closed), not warn" — contradicts the shipped open-vocabulary design (unknown types accepted, policy judges) | Low (doc drift) | `ARCHITECTURE.md:71` vs `model.rs` doc header, `SPEC.md` §2.4, `docs/phase7-report.md` "Stale spec pins corrected" note | Rewrite §3.1 sentence to match open-vocabulary semantics |
| F3 | Root `tests/` is an **empty directory** while `ARCHITECTURE.md` §2 says it holds e2e/negative/golden vectors | Low (layout drift) | `ARCHITECTURE.md:38`; `ls tests/` empty; vectors live in `crates/*/tests` | Update ARCHITECTURE layout block or move golden harnesses (prefer: update doc) |
| F4 | Seven scratch artifact JSONs are **committed at repository root**: `att.json, ev1.json, evd.json, inv1.json, policy.json, proof.json, rel.json` | Low (hygiene) | `git ls-files` lists them; content is fixed-seed demo material duplicated by `demo/out/` and `fixtures/` | Move under `examples/` or `fixtures/live/` and reference from a doc; delete from root |
| F5 | **No-panic invariant violations in production paths**: `P256Key::pubkey_xy` uses `.expect("x"/"y")`; `proof-graph` Kahn loop uses `.expect("node")`; CLI `main.rs` uses `fs::create_dir_all(&d).unwrap()`, `.read().unwrap()`; `cli/src/lib.rs:83,114` use `it.next().unwrap()` (peek-guarded) | Medium (invariant drift vs `proof-core` PE-SEC-004 claim "no unwrap/expect/panic in production paths") | grep scan colocated above | Replace with `?`/`map_err`/`match`; add a CI grep gate like the neutrality gate; panics on I/O are real robustness defects |
| F6 | `VerifyCtx` (pipeline) and `EvalInputs` (policy) duplicate clock/skew/trust fields with **different shapes** — divergence foot-gun | Low (design) | `pipeline.rs:30-59` vs `eval.rs:39-57` | Introduce one `VerificationContext` value object; keep both structs as thin projections |
| F7 | `interop/README.md` says "no P-256 ECDSA verification (independent secp256r1; golden-21..23 cross-check)" while `docs/LONGEVITY.md` §5 says the independent Python ECDSA verifier cross-checks golden-21/22/23 — ambiguous | Low (doc inconsistency) | `interop/README.md` vs `LONGEVITY.md:83` | Align wording; state explicitly what Python does and does not run |
| F8 | CBOR `nint` range restricted to `i64` while full CBOR allows `-2^64..-1` — a deliberate protocol restriction best kept, but `FORMAT.md` still needs the explicit amendment promised in `docs/phase1-report.md` residual #1 | Low (doc debt) | `docs/phase1-report.md:33`; `FORMAT.md` | Add the nint-range restriction sentence to FORMAT.md (promised, not yet done) |
| F9 | `tools/refactor_enums_to_strings.sh` — one-shot historical migration script committed in `tools/` | Low (hygiene) | file exists | Move to `tools/archive/` or remove; keep two-way migration only in history |
| F10 | `docs/certification-report.md` claims CLI I/O "exit matrix 0/1/2 tested" and "no continue-on-error" in CI — but `ci.yml` has `continue-on-error: true` on the advisory job, and F5 shows CLI panics bypass the exit-code contract | Low-Med (doc overclaim) | `certification-report.md`; `ci.yml` advisory job; `main.rs` unwraps | Re-word certification row ("gates for advisories: continue-on-error by design"); fix CLI panics first |

## 5. What is domain-specific (and correctly contained)

- **Well-known vocabulary constants** (`payment.created`, `settles`,
  `transaction_record`, `ai.action.executed`, …) live only as *labels* in
  `proof-core/src/model.rs` with an explicit "convenience, not exhaustive"
  contract, and `tools/check_neutrality.py` (PE-NEUT-001/004) prevents them
  becoming logic. They are the audit's one deliberate neutrality smell —
  they exist to make the demo and domain docs legible. Keep, but treat the
  constant list as a registry that must stay empty of *logic*, and prefer
  namespaced labels (`acme.payments.settled`) over the bare V1 labels.
- **Policies and domain journeys** (`examples/policies/*.json`,
  `docs/domains/*.md`, `domains/proof-domains/tests/*`) are caller
  material by construction — the correct layer.
- **CLI and demo verb vocabulary** (`settle`, `invoice`) — application
  and demo only.

**Judgment:** the boundary is sound. The only core-adjacent risk is
`RelType::requires_grounding()` hard-coding `OWNS|CREATED|SETTLES|EXECUTED`
as trust-relevant edges (`model.rs:170`). That is a protocol semantic (which
edge kinds are written without backings) rather than a domain semantic — but
it is the one place the core carries an opinion about relationship meaning.
Recommendation: keep the *mechanism* (mandatory grounding for a configurable
set) and move the *membership* into the versioned protocol config, so future
vocabularies can declare their own trust-relevant edge kinds without a core
change (additive, policy/context-driven).

## 6. What should be generalized

1. **Inline evidence option.** Evidence and event payloads are digest-only
   today (privacy + size). For genuinely self-contained proofs the model
   needs an opt-in `content` alternative with hard size caps — additive `v2`
   field, never weakening digests (digest stays; content becomes *also*
   carried). Design must keep "never silently treat missing external evidence
   as valid" (capability G7 unchanged).
2. **Reference syntax standard.** Subjects/objects/issuers are open strings.
   Standardize a namespaced reference syntax (e.g. `ref:<ns>:<kind>:<id>`) as
   a spec addendum so distinct domains don't invent conflicting conventions.
   Purely additive documentation + optional validation helper.
3. **Single verification context.** Unify `VerifyCtx` + `EvalInputs` into
   one `VerificationContext` value object (F6) so the pipeline and policy
   can never drift apart; both existing structs become thin constructors.
4. **Dimensioned report.** The master model (six truth levels + overall)
   is richer than the current binary `cryptographic/evidence` validity pair.
   Project a `Verdict` enum (`VALID | INVALID | INDETERMINATE |
   NOT_APPLICABLE`) per dimension (structural, cryptographic, evidence,
   provenance, temporal, revocation, policy) on top of existing stage
   records — **additive projection**, no change to the triple contract.
5. **One-shot convenience API.** `verify_and_evaluate(bytes, ctx, policy)`
   that returns the typed report + outcome together, so the pipeline/policy
   pairing error (running policy on the wrong report) is a type-level
   impossibility for library users.

## 7. What should be redesigned (small, specific)

- **The parse-failure projection.** Today a PARSE failure is reported as
  `cryptographic_validity: Invalid` (crypto stages include PARSE/SCHEMA/
  CANONICAL) with `evidence_validity: Invalid` forced by the early-exit
  rule. Defensible, but it conflates *structural* with *cryptographic*
  failure in the public verdict. Redesign the report to compute
  `structural_validity` (PARSE/SCHEMA/CANONICAL) as its own dimension and
  define the triple as a *projection* so bytes that never parse are
  structurally INVALID rather than "cryptographically invalid".
- **`status_objects`/revocation flow.** Caller-supplied status objects are
  re-verified end-to-end but there is no *registry contract* for "service
  that answers status". Redesign the surface so a `StatusSource` trait can
  be implemented by files, transparency adapters, or callbacks later —
  without changing the fully-offline default.

## 8. What should move outside the core / become an extension / a standard

### 8.1 Move outside the core (already largely outside — finish the job)

- CLI key handling (`--seed`, file keystore) — explicitly demo-grade; move
  to a `proof-cli`-adjacent *credentials* module or documented external
  contract (SECURITY.md already declares this; quarantine it so it cannot
  leak into library defaults).
- `tools/refactor_enums_to_strings.sh`, root scratch JSONs (F4/F9).

### 8.2 Become an extension (versioned capability rows, never core hacks)

- **Transparency adapters** (generic: append-only logs, inclusion proofs,
  consistency proofs, receipts, TSAs, external registries) — consume
  transparency *evidence*; no anchoring required.
- **Storage adapters** (filesystem, object, SQL, CA-store, document) behind
  one `ArtifactStore` interface; core stays persistence-free.
- **External standards adapters**: C2PA, W3C Verifiable Credentials, SCITT,
  X.509/PKI, signed HTTP records, device attestation, enterprise events —
  defined as *mapping layers*, verified both directions by differential
  tests against the core model.
- **Policy v2** (OR/NOT/threshold/quorum/temporal/relationship/provenance
  constraints) as a new `policy_version` with a capability row — the V1
  AND-only contract stays frozen.
- **Post-quantum and hash-migration suites** on the existing registry
  mechanics (`docs/LONGEVITY.md` — already designed, not implemented).

### 8.3 Become a standard (frozen, interop-normative)

- Canonical CBOR subset + id construction + COSE_Sign1 profile (FORMAT.md —
  already normative; freeze as Protocol Registry v1).
- The **artifact container** behind the CLI/JSON wrappers: today each
  artifact file is `{"kind","id","cbor":hex,[…]}` — an *ad-hoc* format that
  interop does not implement. Standardize it (envelope spec) so Python/TS/Go
  can exchange the same files, not just the canonical bytes.
- Stable error-code table, verification-context JSON shape, and golden
  vector record shape (already normative in `fixtures/` — promote to a spec
  appendix).

## 9. Gap analysis vs. the master architecture program (62-point prompt)

Status legend: **IMP** implemented+tested · **PRT** partial, gap noted · **GAP** absent · **BY-E** by-design exclusion (extension layer).

| Master-program demand | Status | Evidence / gap note |
|---|---|---|
| §3 Reassess architecture | IMP | this document |
| §4 Universal model (Entity/Event/Claim/Evidence/Attestation/Relationship) | IMP/PRT | five primitives + open strings; **Entity is by-reference only** — acceptable, needs a spec statement |
| §5 Proof as composition model | GAP | member sets flat; CAP-045 nested-proof = V2; additive `referenced_proofs` design proposed |
| §6 Separate four levels of truth | IMP | crypto/evidence/policy triple + lifecycle; **provenance dimension & NOT_APPLICABLE missing** (additive projection proposed) |
| §7 Verification context | IMP | `VerifyCtx`; unify with `EvalInputs` (F6) |
| §8 Historical vs current validity | IMP | LIFECYCLE.md + golden-19 |
| §9 Cryptographic agility | IMP | closed registry, PQ parser tests, LONGEVITY contract |
| §10 Canonicalization first-class | IMP | PE-FMT-001..009 + cross-impl |
| §11 Content addressing | IMP | ids + digest refs |
| §12 Bundles and references | PRT | digests-only; no inline content; no reference-availability matrix report |
| §13 Offline-first | IMP | zero network in verifier; caller supplies externals |
| §14 Transparency as extension | PRT | `transparency_receipt` kind + `transparency_present` requirement exist; adapters GAP |
| §15 Interoperability first | IMP | I2/I3 + vectors; artifact-container standardized GAP |
| §16 Generic policy engine | PRT | closed AND-set; OR/NOT/threshold = policy v2 |
| §17 Provenance graph | PRT | validate_graph; traversal/ancestry APIs GAP |
| §18 Proof explanation | IMP | explain_* pure projections |
| §19 Partial verification | PRT | INDETERMINATE exists; NOT_APPLICABLE + explicit dimension set GAP |
| §20 Revocation & supersession | IMP | lifecycle + signed status |
| §21 Time | IMP | u64 + skew + explicit clock; clock uncertainty GAP (documented) |
| §22 Identity | IMP | keyrefs + external refs by convention; no PE-owned identity |
| §23 Privacy | IMP | digest-only; selective disclosure/ZK = V2 |
| §24 Security model | PRT | THREAT-MODEL.md exists; this program adds SECURITY-MODEL.md |
| §25 Resource safety | IMP | Limits enforced + 8 MiB CLI cap |
| §26 Supply chain | PRT | deny+bans+lock; SBOM/signed releases/provenance GAP |
| §27 Event-driven ingestion | GAP | V2 (adapter architecture) |
| §28 High-volume / batching | GAP | V2 (batch/aggregate proofs) |
| §29 API | GAP | V2 (reference API) |
| §30 SDKs | PRT | Rust first-class; TS/Python/Go GAP (interop Python is a verifier, not an SDK) |
| §31 CLI | IMP | 16 subcommands, 0/1/2 contract, JSON, stdin/out, completion |
| §32 Reference UI | PRT | offline browser demo exists; full claim→decision visualization PRT |
| §33 Domain neutrality test | IMP | 5 domains, one core |
| §34 Origin-like capability | IMP | media/ai domains cover licensing/attribution/derivation |
| §35 Economics outside core | IMP | by construction |
| §36 Contextual trust | IMP | no global trust score |
| §37-38 Storage/networking neutrality | IMP | zero deps; adapters V2 |
| §39-40 Versioning & backward compat | IMP | VERSIONING.md, fail-closed versions |
| §41 Formal spec | PRT | SPEC.md+FORMAT.md exist; this program consolidates PROOF-ENGINE-SPEC.md |
| §42 Independent verifier | IMP | interop/ Python |
| §43 Golden vectors | IMP | 23 vectors |
| §44 Adversarial testing | IMP | mutation-soak 2000+ mutants, negative matrix |
| §45 Fuzz everything that parses | IMP | 4 targets, CI smoke; local run blocked under PRoot (documented) |
| §46 Error model | IMP | 22 stable codes |
| §47-48 Observability / privacy-preserving logs | GAP/IMP | no telemetry by design; redacted Debug on keys; structured logs GAP |
| §49 Performance | PRT | bench.sh verify-only; creation/memory benches GAP |
| §50-51 Architectural boundaries | IMP | layering strict; Section 51 list honored |
| §52 Remove-half test | IMP (concept) | V1 is already minimal; re-run at each phase |
| §53 100-year test | IMP | LONGEVITY contract |
| §54 No-internet test | IMP | demo passes offline-only |
| §55 No-PE-trust test | IMP | I2/I3 + explicit context |
| §56 Ten-domains test | PRT | 5 domains; target 10 before declaring success |
| §57 Phased implementation | PRT | phases 0-7 done as V1; this program re-slices |

## 10. Severity-ranked action register

**P0 — must fix before the next release (correctness of claims/docs):**

1. **F1** — implement fail-collect mode for `report_all_failures` or remove the
   field and its doc comment. Docs must match code (VERIFICATION.md rule).
2. **F5** — eliminate `unwrap`/`expect`/`panic!` from production paths
   (keys.rs, graph.rs, cli lib.rs/main.rs, demo.rs) and add a CI grep gate so
   the PE-SEC-004 claim becomes enforced, not aspirational. CLI must never
   panic on I/O — route through the 0/1/2 contract.
3. **F2, F8** — reconcile `ARCHITECTURE.md` §3.1 and add the nint-range
   amendment to `FORMAT.md` (both already promised).

**P1 — coherence hardening (no format impact):**

4. **F6** — single `VerificationContext` object; `VerifyCtx`/`EvalInputs`
   become projections.
5. **F3, F4, F9, F10** — layout hygiene (tests/, root JSONs, tools/archive,
   certification wording). Add F4 files to `.gitignore` after relocating.

**P2 — architecture program (released under new capability rows):**

6. Dimensioned verdict report (structural/crypto/evidence/provenance/temporal/
   revocation/policy + NOT_APPLICABLE) as an additive projection.
7. Artifact-container standard (envelope spec) + Python/TS interop on it.
8. Inline-content evidence option (v2, capped) for self-contained proofs.
9. Proof-composition model (`referenced_proofs`, member-union semantics).
10. Configurable trust-relevant edge set (moving `requires_grounding`
    membership out of `model.rs`).
11. `StatusSource` trait for revocation/transparency adapters.
12. Ten-domain validation; policy v2; SDKs; ingestion; API (MIGRATION-PLAN).

## 11. Audit trail

| Evidence | Location |
|---|---|
| Full-source line inventory (16,546 Rust L) | `find . -name '*.rs' \| xargs wc -l` (audit run) |
| Doc line inventory (5,036 L) | `find . -name '*.md' \| xargs wc -l` (audit run) |
| Build green | `cargo build --locked` EXIT=0 (audit run, log `/tmp/pe-build.log`) |
| Tests green | `cargo test --locked` EXIT=0 (audit run, log `/tmp/pe-test.log`) |
| Panic-surface grep | `grep -rn 'unwrap()\|expect(\|panic!' crates/*/src` (audit run) |
| Root scratch files tracked | `git ls-files` lists `att.json ev1.json evd.json inv1.json policy.json proof.json rel.json` |
| `report_all_failures` unused | `grep -rn report_all_failures crates/` → only `pipeline.rs:58,73` |
| Empty root `tests/` | `ls tests/` (empty) vs `ARCHITECTURE.md:38` |

---

*Conformance note: this document changes no code. Findings and dispositions
feed `MIGRATION-PLAN.md`; the consolidated normative spec lives in
`PROOF-ENGINE-SPEC.md`; the threat model in `SECURITY-MODEL.md`; the target
architecture in `ECOSYSTEM-ARCHITECTURE.md`.*