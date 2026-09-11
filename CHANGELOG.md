# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] (V1 in development; protocol semantics evolve on `main`)

### Added (convergence elevation: identity, delegation, transparency, lifecycle, conflict, versioning)

- **Policy v2** (`policy_version: 2`): boolean `all`/`any`/`not`/`threshold{k,of}`
  expressions over leaves; INDETERMINATE reserved for unevaluated policy;
  vacuous shapes rejected; node budget enforced; v1 frozen byte-for-byte
  (v1 rejects v2 leaf names; v2 rejects the `requirements` key). Six
  adjudication leaves: `delegated_authority{root,issuer,scope?}`,
  `identity_bound{a,b}`, `transparency_inclusion{log}`,
  `no_conflicting_evidence`, `vocabulary_accepted{ns,max_version}`,
  `evidence_usable{kind}`. Canonical CBOR mirrors the tree;
  `policy:v2:…` hashes; golden-28; EBNF v2.
- **Delegation chains**: `delegate` claim convention (subject = grantee,
  optional opaque scope) resolved over ACTIVE links from trust-listed roots,
  cycle-safe and scope-exact when required. Delegation without a trusted
  root is nothing.
- **Identity/equivalence**: `identity.bind` claims + grounded EQUIVALENT
  edges (identity-ref endpoints allowed; shaped ids must resolve); honored
  only from trust-listed asserters, never transitive-by-core, never global.
- **Transparency abstract model** (SPEC §8b): registration → receipt →
  inclusion → consistency/ordering; `transparency_registration`/
  `transparency_checkpoint` kinds; checkpoints as ordinary log-issuer
  attestations (freshness/rotation fall out of existing machinery).
- **Lifecycle elevation**: `withdraw` (cease reliance, history preserved)
  and `compromise` (taint at/after instant, history NOT preserved) status
  kinds with kind-appropriate authority; `COMPROMISED` lifecycle state
  (dominates precedence); per-evidence derived status
  (`AVAILABLE→UNAVAILABLE` spectrum); `WITHDRAWN`/`COMPROMISED` codes
  (append-only: 22→24); golden-29/30.
- **Native opposition**: `denies` claim fields (external denials noted,
  never failed) + grounded CONTRADICTS edges feed typed conflict records
  (`divergent_claims`/`denial`/`contradiction`); validity unchanged, policy
  adjudicates.
- **Vocabulary evolution**: optional bound `vocabularies:[{ns,version}]`
  declarations (absent → byte-identical V1); `accepted_vocabularies`
  context; informational notes only (acceptance is policy); golden-27.
  New namespaces need no core change; new structure needs a new `v`.
- **Storage seam + bundles**: `ArtifactStore` (memory/filesystem) and
  `Bundle` blobs authenticating against evidence digests.
- **No-panic CI gate**, fuzz policy-parser 10-type coverage, CLI
  `withdraw`/`compromise`/`export`/`import`/`convert`/`compose` commands,
  independent secp256r1 verifier (37-check differential over 31 vectors).

### Added (convergence: P1–P4 foundations, additive only)

- **Unified `VerificationContext`** (`proof-verify::context`): single normative
  object; `VerifyCtx`/`EvalInputs` are thin projections. One-shot
  `verify_and_evaluate()` pairs pipeline+policy on one context.
- **Dimensioned verdicts** (`VerifyReport::dimensions`): 8 dimensions ×
  `VALID/INVALID/INDETERMINATE/NOT_APPLICABLE`; v1 triple preserved.
- **Fail-collect diagnostics**: `report_all_failures:true` continues past
  `CANONICAL` to report every stage (evidence forced Invalid either way).
- **Standard envelope** (`proof-format::envelope` +
  `proof-crypto::verify_envelope`; `export`/`import`/`convert` commands).
- **Composition** (`compose` command): union of member sets, dedup by id,
  provenance preserved, new `proof_id` binds the union.
- **`StatusSource` registry contract** (`VecStatusSource` offline default).
- **Configurable grounding** (`validate_graph_with_grounding`).
- **No-panic hardening**: P-256/System/graph/CLI production paths return
  `Result` instead of `expect`/`unwrap`.
- **Ten-domain neutrality**: logistics, legal, supply-chain, health, gov join
  payment, credential, media, AI, sensor (same core, same verdict shape).
- **Architecture records**: `EXTENSION-MODEL`, `CRYPTOGRAPHY`,
  `VERIFICATION-MODEL`, `POLICY-MODEL`, `COMPATIBILITY` (sub-references of
  the unified spec; §50 review complete).
- **Composition linkage** (`referenced_proofs`, SPEC §7): sorted/deduped/
  bounded source ids bound by `proof_id` when present, byte-identical V1
  binding when empty (generator reproduces golden-11/12 byte-identically);
  self-links refused (`CYCLE_DETECTED`); `compose` records sources;
  golden-24/25/26.
- **Transitive resolution** (`proof_verify::resolve`, bundle layer):
  BFS over `referenced_proofs` against an `ArtifactStore` with same-context
  re-verification, depth accounting, diamond dedupe, and an explicit matrix
  (`UNAVAILABLE`/`ID_MISMATCH`/`DEPTH_EXCEEDED`/`OVER_BUDGET`/`STORE`);
  root verdict reproduced verbatim, incompleteness fail-closed. `resolve`
  CLI command (exit 0 iff complete). Core stays linkage-only (frozen).
- **Bench dimensions** (`tools/bench.sh`): large/wide/deep proofs, signing,
  parse-only, and batch throughputs with peak-RSS notes (subprocess
  end-to-end, honestly labeled); `BIN` override for custom target dirs.
- **In-process bench** (`crates/proof-bench`, P5): 11 isolated scenarios
  (create/sign/canon/hash/verify-small-large-deep/graph/policy/serde/
  evidence) with latency + peak-RSS and a JSON baseline regression gate;
  no new dependencies.
- **Batch verification** (`proof_verify::verify_batch` + `batch-verify`
  CLI): many proofs under one shared context with per-member independent
  semantics (no sampling, no short-circuit, over-cap `LIMIT_EXCEEDED`);
  `tools/bench.sh` gains a batch dimension (invocation overhead amortized,
  verification work identical per member).
- **Traversal APIs**: `ResolutionReport::ancestors()` (transitive closure
  with shallowest depths, unavailable refs named as unresolved) and
  `descendants_of()` over an explicit candidate set with union-store
  equivocation detection.
- **Reference hooks** (policy v2, eight adjudication leaves):
  `requires_reference{id}` / `forbids_reference{id}` over direct linkage
  (`prf:v1:` shape-checked at parse, v1 rejects); transitive closure stays
  bundle-layer. EBNF + CBOR + describe extended; v1 byte-identical.
- **Divergence representation** (SPEC §17): `report.conflicts[]` records
  same-type/subject groups with differing fields; validity unchanged, policy
  adjudicates; corroboration stays silent. Surfaced in CLI JSON.
- **Historical crypto mode**: `AllowedAlgs::with_deprecated` verifies `-8`
  via Ed25519 and `-7` via P-256 (labeled historical-only; `-35`/`-36`
  never verifiable). Was-valid-then vs acceptable-now, no history rewrite.
- **Independent P-256**: stdlib-only secp256r1 ECDSA in `interop/pengine.py`;
  differential now 37 checks across all 31 vectors incl. refs and vocabulary
  bindings, P-256 both directions, Python-composed proofs verified
  by Rust, and closed-schema parity (unknown member fields rejected by
  both implementations).
- **Storage seam + bundles**: `ArtifactStore` trait with memory/filesystem
  backends (conflict = corruption, never silent update); `Bundle` blobs
  authenticate against evidence digests through the pipeline's own rule.
- **No-panic CI gate**: `make no-panic` (`tools/check_no_panic.py`,
  PE-SEC-004) enforced in CI; exhaustiveness arms return fail-closed errors.
- **Supply-chain release artifacts** (PE-OPS-006): CycloneDX SBOM projected
  from `Cargo.lock` (`tools/gen_sbom.py`; stdlib, offline, deterministic),
  SLSA-style build provenance (`tools/gen_provenance.py`), `sha256sums.txt`
  via `make release-meta OUT=dist/`; SSH-signature signing procedure in
  `RELEASE.md`; SBOM determinism enforced in CI.
- **SCITT adapter** (`crates/proof-adapter-scitt`, P7): signed statements /
  receipts → attestations + `transparency_registration` / `transparency_receipt`
  evidence with sha256-of-canonical-statement binding both directions
  (stdlib differential recomputes it); Ed25519 verified, x5chain/DID stable-code
  rejections; checkpoint constructor feeds policy `transparency_inclusion`;
  pinned fixtures; X.509 chains and Merkle proofs explicitly out of scope.

### Fixed (protocol-doc forks, no wire break)

- **CDDL aligned to code**: `type` (not `event_type`), `claim:{type,…}` (not
  `claim_type`+`claim` split), `[* tstr]` (empty member sets allowed).
- **`FORMAT.md`**: `i64` nint range, schema caps, 50-char id bound, error-code
  vector rule.
- **`ARCHITECTURE.md`**: open-vocabulary sentence, empty `tests/` note.
- **LONGEVITY/certification wording**: P-256 interop scope, advisory
  continue-on-error.
- **`proof_fresh` honesty**: documented as advisory (holder-rewritable
  `created_at`), qualifier in the pass message, restamp behavior pinned by
  test; `EvalInputs` bounds documented, one-shot path enforces
  `LIMIT_EXCEEDED`.
- **Fuzz drift**: policy-parser target covers all eighteen requirement types.

### Added

- **Human-first commands**: `inspect` (read-only, never a trust decision),
  `graph` (`text`/`dot`/`mermaid`), `doctor`, `version`, and `completion`
  (`bash`/`zsh`/`fish`/`powershell`, generated from the command table).
- **Unix streaming**: `--proof -` reads a proof from stdin
  (`verify`/`evaluate`/`explain`/`inspect`/`graph`); `--out -` writes an
  artifact or report to stdout. stdout stays machine-readable; humans read
  stderr.
- **Human verify summary**: `verify` (and `evaluate --json`) print a
  ✓/✗-per-stage summary with `RESULT` on stderr. Color is TTY-only,
  honors `NO_COLOR`, and never touches JSON output.
- **Hierarchical help**: `help <command>` and `<command> --help`.
- **Interactive tour**: `demo --interactive` walks build → verify → policy
  contrast → tamper/restore → revoke → supersede → a second domain, every
  step computed live by the core (refuses cleanly without a TTY).
- **Browser demo**: `make web-demo` builds a self-contained
  `demo/web/index.html` (double-click, offline, no server/login) whose
  proofs, reports, and policy outcomes are generated by the real CLI;
  `make web-check` fails if embedded data ever differs from fresh output.
- **`inspect --json`**: machine-readable decoded-proof projection for
  tooling (the web demo renders member data from it).
- **Positional proof path**: `verify proof.json` means
  `verify --proof proof.json`. Short flags: `-o -q -j -p -c -k -s -t`.

### Fixed

- **`k=v` field order no longer matters**: `--claim`/`--meta`/`--context`
  pairs are canonicalized to CBOR map order, so `b=1,a=2` and `a=2,b=1`
  produce identical bytes instead of `SCHEMA_VIOLATION`.
- **`--quiet` is now total**: artifact/proof loader progress notes respect
  `--quiet`; previously `loaded …` lines leaked to stderr.
- **Terminal-safe output**: escape sequences and control characters from
  untrusted proof content are stripped; Graphviz/Mermaid labels are quoted.

### Maintenance

- **Stale spec pins corrected**: `ARCHITECTURE.md` retitled V0.1 → V1
  draft, model sections now describe open string vocabularies (matching
  `model.rs`), the closed policy set lists all ten requirement types
  (matching `policy.rs`/`POLICY.md`), and the pipeline sketch matches the
  11-check-stage + caller-POLICY + FINAL shape (`SPEC.md` §6.1).
- **SPEC §6 clarified**: the "11-stage" heading now reads as 11 check
  stages plus caller POLICY evaluation and FINAL emission, matching the
  13-row table and `pipeline.rs` (`finalize()` reports INDETERMINATE;
  `proof-policy` evaluates separately).
- **Stale counts unpinned**: `README.md`/`Makefile` no longer pin fixed
  test counts (`cargo test --locked` is the gate). `VERIFICATION.md` no
  longer pins an old count.
- **Lifecycle boundary clarified**: `LIFECYCLE.md` gap note now points at
  `proof_fresh` + caller clocks instead of claiming "no requirement
  type"; `capability-map.md` CAP-073 golden range corrected 01..19 →
  01..23.

## [1.0.1] - 2026-09-09

Patch release of the tooling and docs; protocol semantics and wire format
unchanged from 1.0.0.

### Changed (proof-cli UX)

- **`relate` fails fast on bare labels**: `--from` / `--to` / `--evidence-ref`
  / `--attestation-ref` must be artifact ids (`evt:…`, `att:…`, `evd:…`),
  not bare labels like `invoice:i9`. A shape-check catches the mistake at
  creation time (exit 2 + hint) instead of surfacing `DANGLING_REFERENCE`
  later at verification.
- **`build` accepts an empty evidence list**: `--evidence ""` now means the
  proof genuinely has no evidence; the missing-flag error names this escape
  hatch.
- **No more `REPLACE_WITH` surprises**: `evaluate`/`explain` fail fast with a
  hint when the policy still contains `REPLACE_WITH_YOUR_ISSUER_KEY`,
  preventing the classic doubled-prefix `key:ed25519:key:ed25519:…`.
- **`verify`/`evaluate` explain UNKNOWN lifecycle**: when no
  `--revocations-known-at` is supplied and lifecycle is UNKNOWN (fail
  closed), a stderr hint suggests the re-run invocation. stdout stays
  machine-readable.
- **`decision indeterminate` clarified**: prose output now spells out that
  INDETERMINATE means "no decision made", and prints the exit-code legend.

### Fixed

- Example policies (`examples/policies/*.json`) no longer carry a
  `description` field, which the fail-closed policy parser rejects
  (`POLICY_INVALID: unknown field description`); all four examples now
  parse and evaluate.

### Docs

- README quick-start and "Creating a Proof" rewritten as copy-paste-correct
  walks (invoice event created, artifact ids wired into `relate`/`build`,
  `--revocations-known-at` present, policy substitution touches only the
  issuer suffix).
- `proof-cli help` documents the id requirement for `relate`, empty
  `--evidence`, and the `--revocations-known-at` rule.
- `examples/policies/README.md` shows correct vs. wrong issuer substitution.
- Crate metadata completed for crates.io (homepage, documentation, license,
  categories) — enabling `cargo install proof-cli` from the registry.

## [1.0.0] - 2026-09-08

V1 protocol release. The requirement set, wire format, ID construction,
verification pipeline, lifecycle states, policy language, and error codes are
defined in `SPEC.md` and companions.

### Added (shipped with V1.0)

- **Policy requirement `proof_fresh`**: fails when a proof's `created_at` is
  older than `max_age_seconds` relative to the verifier clock. Provides
  replay protection against stale proofs. `VerifiedState` now carries
  `proof_created_at` from the pipeline.
- **Canonical policy encoding**: `policy_to_canonical_cbor()` and
  `canonical_policy_hash()` enable signing, comparison, and deterministic
  caching of policies. Policies now have a canonical CBOR form.
- **Detached content verification**: `verify_content_digest()` and
  `compute_digest()` in `proof-crypto` provide the canonical way to verify
  that external content matches a HashRef digest.
- **VerifyCtx input limits**: `max_status_objects`, `max_trusted_issuers`,
  and `max_revocation_authorities` in `Limits` prevent DoS via unbounded
  input vectors.
- **Configurable domain separation**: `sign_ed25519_with_aad()`,
  `sign_esp256_with_aad()`, and `verify_sign1_with_aad()` allow custom
  `external_aad` for cross-domain isolation. Default remains "PE1".
- **CDDL schema**: `docs/format.cddl` provides a formal machine-readable
  schema for the wire format. `tools/validate_cddl.py` validates golden
  vectors against it.
- **Policy grammar**: `docs/policy-grammar.ebnf` provides a formal grammar
  for the policy language.
- **Error aggregation mode**: `VerifyCtx.report_all_failures` flag enables
  reporting all failures instead of stopping at the first (useful for
  debugging).

### Changed

- `Limits` struct extended with three new fields (backward-compatible:
  existing code using `Limits::default()` continues to work).
- `VerifyCtx` extended with `report_all_failures` field (default false).
- `VerifiedState` extended with `proof_created_at` field.
- Policy requirement set expanded from 8 to 10 types (existing policies
  continue to work).
- All seven crates published to crates.io as 1.0.0 with complete metadata
  (description, license, repository, homepage, documentation).

## [0.1.0] - 2026-09-07

First release of the library, CLI, and format specification.

### Added

- **Canonical CBOR codec** (`proof-format`) with strict limits: duplicate map
  keys rejected, non-canonical integers rejected, depth/size bounded, bad
  UTF-8 rejected.
- **Domain model and error codes** (`proof-core`): five persisted primitives
  (Event, Attestation, Evidence, Relationship, Proof), closed enums, `Limits`,
  stable machine-readable error codes.
- **Crypto** (`proof-crypto`): SHA-256 ids over canonical bytes, COSE_Sign1
  Ed25519 (required) and ES256 (optional); deprecated polymorphic algorithms
  (-8/-7/-35/-36) are rejected. Builders validate before signing and never
  sign bytes the issuer field disowns.
- **Graph validation** (`proof-graph`): endpoint resolution, mandatory
  grounding for trust-relevant edge types, cycle rejection, bounded supersedes
  chains.
- **Verification pipeline** (`proof-verify`): 11 deterministic stages (PARSE →
  SCHEMA → CANONICAL → IDENTIFIERS → SIGNATURES → KEYS → TIME → REVOCATION →
  EVIDENCE → RELATIONSHIPS → GRAPH), lifecycle state machine (ACTIVE /
  EXPIRED / REVOKED / SUPERSEDED / UNKNOWN), explicit clock + skew,
  caller-supplied signed revocation/supersession status objects with a
  `revocations_known_at` staleness bound.
- **Policy engine** (`proof-policy`): declarative closed requirement set with
  implicit AND, PASS / FAIL / INDETERMINATE decisions, trust-list semantics
  (a valid signature never satisfies `issuer_trusted` by itself), and
  stage-by-stage human-readable explanations.
- **CLI** (`proof-cli`): artifact creation, proof building, verification,
  policy evaluation and explanation; artifact files are JSON wrappers around
  canonical CBOR and are re-verified on every load; exit codes 0/1/2 for
  PASS / verdict / error.
- **Golden vectors**: 18 self-checking fixture generators and deterministic
  golden files (01–18) covering happy paths and every documented failure mode,
  plus golden-19 (superseded proof under a currency-sensitive policy).
- **Demo**: `make demo` runs a deterministic end-to-end scenario (PASS →
  tamper → FAIL → revoke → FAIL) and reproduces byte-identical artifacts on
  every run.

### Security

- Fail-closed posture throughout: unknown versions, unknown algorithms,
  oversized or malformed input, stale revocation information and missing
  clocks all refuse rather than guess. See `SECURITY.md` and
  `THREAT-MODEL.md`.

### Notes

- The fixed test key (`--seed test`) is for demos and tests only; production
  key custody is out of scope for V0.1.
- Fuzzing (`IMPLEMENTATION_PLAN.md` acceptance item A8): cargo-fuzz targets
  under `fuzz/` with seeds and nightly wiring (`.github/workflows/fuzz.yml`);
  600s smoke green (see VERIFICATION.md for the latest green run id), 4/4 targets no findings.
