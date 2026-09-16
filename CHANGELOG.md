# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] (V1 in development; protocol semantics evolve on `main`)

### Added (post-`v1.0.0` hardening)

- **13th domain journey: election certification** (`domains/proof-domains/tests/election.rs`).
  Ballot batch cast → counted → tally certified: three-event chain, two
  grounded `PRODUCED` edges, election-authority attestation, `pollbook_record`
  evidence, `evidence_present` policy leaf. All cross-domain suites
  (verdict shape, revoke, supersede, tamper, foreign policy) now cover 13
  industries with zero core changes.

### Added (first signed cut — `v1.0.0`, see `dist/RELEASE-NOTES.txt`)

- **`docs/allowed_signers` release principal** (`release@proof-engine`,
  ed25519). SSH-signed `dist/` (`proof-cli`, `sbom.cdx.json`,
  `provenance.json`, `sha256sums.txt`, `RELEASE-NOTES.txt`; verify with
  `ssh-keygen -Y verify -f docs/allowed_signers`). Private key held
  ephemerally outside the repo, never committed.

### Changed (pre-launch core audit — BREAKING, fail-closed empty feed)

- **Empty status feed fails closed by default.** Freshness asserted with
  zero status objects and no explicit opt-out ⇒ lifecycle UNKNOWN ⇒
  evidence INVALID (`REVOCATION_UNKNOWN`), exit 1 — at the core
  (`VerifyCtx`/`VerificationContext` defaults), CLI (`verify`/`evaluate`/
  `batch-verify`/`resolve`), and HTTP API alike. Previously this verified
  ACTIVE/VALID ("caller-asserted absence"). Genesis/demo/feedless flows
  assert absence explicitly with `--no-require-status` /
  `no_require_status: true` (recorded with an `explicitly allowed` note);
  `--require-status` is a compat no-op affirming the default.
  Grandfathered fixtures/harnesses pin the old context explicitly; new
  vectors default closed. See
  `docs/ARCHITECTURE-CHANGE-PROPOSAL-empty-feed-fail-closed.md` (APPROVED
  pre-launch, §11).
- **Strict-mode RESULT line.** `--strict-current`/`--production` currency
  rejection now renders `RESULT INVALID (historically valid — not currently
  acceptable) (exit 1)` instead of the self-contradicting
  `VALID … => INVALID` line. Exit codes unchanged.
- **`supersede` flag aliases.** `--target`/`--successor` accepted for
  `--old`/`--new` (revoke uses `--target`). Byte-identical output.
- **Delegation failure message.** `delegated_authority` now names the
  scope requirement and lifecycle/trust-list checks on failure.
- **Custom-edge linkage rule pinned.** `custom_edge_cycle_fails_as_derivation_by_default`
  documents in code that every edge type except REFERENCES/EQUIVALENT is
  derivation (INTEROPERABILITY scope-boundary note added for the
  crypto-vs-verdict split).
- **Currency signal coherence.** `currently_acceptable` is now false on
  UNKNOWN lifecycle (empty feed under the fail-closed default), agreeing
  with the exit code; REVOKED/EXPIRED/COMPROMISED/WITHDRAWN keep the
  orthogonal validity/currency split (pinned by
  `revoked_lifecycle_is_not_currency_gap`, new
  `unknown_lifecycle_fails_currency` test). CLI + HTTP API mirrors in sync.
- **Shape-named policy templates.** `init-policy` default is `standard`
  (`standard_v1`); `strict`/`fresh`/`basic`/`minimal` replace the industry
  nouns, which survive as aliases emitting shape-named ids. The error
  itself now teaches the safe path: empty-feed UNKNOWN prints the exact
  `--no-require-status` vs `--status` retry commands.
- **`proof-cli commit` for confidential claims.** Computes
  `hex(hash("salt|value"))` (sha256/sha384, `--value-file` preferred)
  for the documented salted-commitment pattern; `--value`/`--value-file`
  mutual exclusion enforced.
- **Commitment pattern pinned.** `v2_commitment_pattern_hides_value_but_binds_policy`
  proves salted-hash commitments verify and bind `claim_field` policy with
  existing primitives (equality-only; ZK predicates stay adapters).

### Added (architecture push — semantic model, extension proof, verdict goldens)

- **v2 `evidence_bound` policy leaf.** `{"type":"evidence_bound","kind":K}`
  passes iff some AVAILABLE evidence of kind K is cryptographically bound —
  named by a verified ACTIVE attestation's `evidence_ref` whose claim
  `evidence_digest` equals the digest. Lets policy *require* the opt-in
  binding (ten v2 leaves total; v1 rejects the name; EBNF + CBOR + describe
  + fuzz tripwires extended).
- **Fail-closed composition.** `compose` validates the UNION graph
  (grounding incl. `--extra-grounded`, dangling refs, SUPERSEDES linearity,
  derivation acyclicity) before building — cross-proof cycles/branches fail
  at compose time, not later at verify. TIME/REVOCATION currency stays
  verify-time by design; single-proof `build` stays structural-only.
  Shared `extra_grounded` CLI parser between verify and compose.
- **Golden vectors 32–34** (append-only): 32 derivation cycle
  (`CYCLE_DETECTED`), 33 digest mismatch (`ID_MISMATCH`), 34 future-status
  history (valid/valid, no codes). New `gen_conformance_vectors` example;
  Rust harness + `make conformance` (now 25 checks) cover them automatically.
- **`custom_vocabulary` domain test.** A synthetic `acme` industry (custom
  event/evidence/rel vocabularies + caller-declared `extra_grounded` trust
  kind + custom policy) verifies end-to-end with zero core changes —
  constructive proof of the neutrality claim beyond the twelve industries.
- **Durability paper trail.** Freeze manifest covers all working-tree frozen
  files (audit scripted); `check_freeze.py` now also gates untracked new
  files under frozen paths (negative-tested); `RELEASE.md` requires
  `make interop` + `make conformance` + manifest/ACP coverage before any cut.

### Added (adoption push — integration, verdict portability, replay guardrail)

- **`verify`/`evaluate` `--seen-store` replay guardrail (CLI-side; core stays
  stateless).** `--seen-store <file> --seen-context <ctx>` checks the proof
  id before accepting (replay → exit 1, success paths only); `--seen-record`
  appends on success. Same `{"seen": ["<ctx>::<proof_id>"]}` file shape as
  `tools/seen_set.py` (single-writer scope); missing/corrupt store with the
  flags present is exit 2 (fail closed). Runbook §4b documents CLI vs script.
- **`tools/conformance.py` full-verdict runner (`make conformance`, CI-gated).**
  Replays every golden proof/policy vector (bytes + embedded context) and
  compares recorded triples, failure codes, and policy decisions — 22 checks
  green. Third parties mirror the stdlib-only script for verdict agreement;
  recipe in `INTEROPERABILITY.md`.
- **`docs/INTEGRATION.md` wiring guide.** One-shot Rust pattern
  (`verify_and_evaluate` + `VerificationContext`, compile-checked), shell/API
  production invocations, feeds/rotation/replay/blobs/keys/PII checklist,
  conformance pointers. README For Developers now shows the one-shot;
  `docs/INDEX.md` lists the guide.

### Added (review-fixes batch — 9 findings closed; see docs/ARCHITECTURE-CHANGE-PROPOSAL-review-fixes-9.md)

- **`--production` strict operator profile.** `verify`, `evaluate`/`explain`,
  `batch-verify`, and `resolve` accept `--production`: implies
  `--require-acyclic` (full-DAG) + `--require-status` (empty feed fails
  closed) + `--strict-current` currency overlay. `--no-require-status`
  explicitly opts back out of the feed gate only. `verify`/`batch-verify`
  JSON gains `currently_acceptable` (+ per-member in batch, root+members in
  resolve); human `VALID` becomes `VALID (historical …)` when currency fails
  but pipeline passes. Bare defaults unchanged (frozen verdicts preserved).
- **Opt-in `evidence_digest` semantic binding.** Reserved claim field
  `evidence_digest: <64|96 hex>` with `evidence_ref` cryptographically ties
  the attested value to the dataset digest (mismatch `ID_MISMATCH`, missing
  `DANGLING_REFERENCE`, malformed `SCHEMA_VIOLATION`; absent field = no
  check). CLI `attest` help documents the binding.
- **`relate` fail-fast grounding.** Trust-relevant types
  (`requires_grounding()`) without refs are creation errors (exit 2);
  `--allow-ungrounded` preserves intentional negative-test vectors (verify
  still fails closed).
- **`evaluate` single-truth output.** Prose prints decision prose only
  (no report JSON); `--json` merged `{policy_outcome,report}`;
  `--strict-current`/`--production` overlays currency on policy (exit 1 on
  VALID-but-not-current even when policy passes, with stdout+stderr note so
  `--quiet` callers still see why).
- **Reference API parity (perimeter, 0.1.x).** `POST /v1/verify|evaluate|
  explain` accepts the full `VerifyCtx` surface (`esp256`, `historical`,
  `report_all`, `accepted_vocab`, `extra_grounded`, `require_acyclic`,
  `require_status`/`no_require_status`, `production`, `strict_current`);
  wire strings match the CLI (lowercase validities/policy, UPPER
  lifecycle/status) plus `currently_acceptable` (verify) and
  `currently_acceptable`/`currency_fail` (evaluate/explain) with full
  `conflicts` records (was bare count); batch/resolve JSON gains per-member
  currency. Non-text `evidence_digest` fails closed. `attest` fail-fasts
  malformed/missing-ref/non-text `evidence_digest` at creation (exit 2).

### Added (usability push — first-PASS friction)

- **`init-policy --template minimal`.** Domain-agnostic starter
  (`signature_valid` + `issuer_trusted` + `not_expired` + `not_revoked`, no
  relationship/evidence vocabulary) so sensor/legal/science proofs get a
  passing policy without payment-kind editing. Settlement-family templates
  (`settlement`/`strict-document`/`basic-payment`) fail fast (exit 2) when
  domain vocabulary would silently default — pass `--proof` to infer kinds
  or explicit `--relationship`/`--evidence-kind` flags.
- **No more `--evidence ""` hatch.** `build --evidence`/`--relationships`
  may be omitted for zero members (explicit `""` keeps working);
  events/attestations stay required so forgotten inputs still fail fast.
- **`add-evidence --digest-file`.** Hashes file bytes (SHA-256) like
  `create-event --payload-file` — no manual hashlib plumbing.
- **`proof-cli id` plumbing command.** `id --artifact f.json` prints the
  content id, `--field issuer` the issuer keyref — replaces every
  `python3 -c "import json;…"` one-liner; README + `quick_proof.sh` are now
  zero-python flows.
- **`explain --json`.** One merged machine document
  (`{policy_outcome, report, explanation}`) like `evaluate --json`; prose
  stays the default for both (never mixed).
- **Fixed literal `{out}`/`{issuer}` next-hints.** `init-policy` (and two
  `artifact` hints) printed uninterpolated placeholders; they now name the
  real files. README manual flow + `tools/quick_proof.sh` rewritten around
  `--payload-file`/`--digest-file`/`init-policy --proof`/`proof-cli id`,
  ending with an annotated `--production` strict check; README gains a
  5-minute orienting block and `--production` in common flags; interactive
  tour closes with history-vs-currency.

### Fixed (same batch — fail-closed conformance, pre-V1.0 CORE)

- **Derivation cycles always fail.** New `check_derivation_acyclic` (all
  types except REFERENCES/EQUIVALENT) runs unconditionally in GRAPH
  (`CYCLE_DETECTED` → evidence invalid). REFERENCES citations stay
  linkage-valid; `--require-acyclic`/`--production` additionally rejects
  REFERENCES cycles for full-DAG assurance.
- **Status knowledge cutoff strict.** Status effects apply iff
  `issued_at <= verified_at` (no `+skew` grace). Skew still covers
  attestation windows (TIME). Future statuses are STATUS hygiene
  (`status_inputs_valid:false`), never applied — historical queries answer
  "was valid then?" correctly.

### Added (independent external review hardening batch 2 — 12 findings closed)

- **V2 `claim_field` policy leaf (GENERIC EXTENSION).** Typed claim-value
  predicates over lifecycle-ACTIVE verified claims:
  `{"type":"claim_field","claim_type":"…","subject":"…","field":"amount",
  "op":"gte","value":100}`. Ops `eq/ne/gt/gte/lt/lte`; uint allows all six,
  text/bool `eq/ne` only (byte equality, no normalization); `field:"type"`
  rejected (use `claim_type`); missing field, type mismatch, or no in-scope
  ACTIVE claim → FAIL (never vacuous pass). V1 byte-stable (v1 parser rejects
  the name; `v1_rejects_v2_leaf_names_and_stays_frozen` extended). EBNF, CBOR,
  `describe`, evaluator, and `ClaimSummary.fields` projection ship together.
- **`--require-status` fail-closed feed mode (default off).** `verify`,
  `evaluate`, `batch-verify`, and `resolve` accept `--require-status`: empty
  status feed with asserted freshness fails closed (`REVOCATION_UNKNOWN`)
  instead of reporting ACTIVE on caller-asserted absence. Without the flag,
  empty-feed proofs carry an explicit `empty status feed` pipeline note plus a
  CLI stderr warning (gated on ACTIVE so UNKNOWN/STALE keep their own hint).
  `VerifyCtx::require_status_feed` / `VerificationContext` projection for API
  users; lifecycle tests pin both modes.
- **`init-policy --proof` inference.** Relationship/evidence kinds are inferred
  from the proof's first members, so non-payment domains need no manual
  template editing (explicit `--relationship`/`--evidence-kind` win; payment
  defaults last).

### Fixed (same batch — fail-closed conformance, pre-V1.0 CORE)

- **CDDL `created_at` correction (`docs/format.cddl` only).** `proof-binding`
  now covers `created_at` (plus `referenced_proofs`/`vocabularies` when
  non-empty), matching the implementation, FORMAT.md, freeze F2, and both
  interop verifiers. Zero wire bytes change; spec contradiction eliminated.
- **Typed references enforced (F4/F5).** `attestation.evidence_ref` must be
  `evd:v1:`, `evidence.attestation_ref` / relationship refs typed per slot —
  enforced at schema (`SCHEMA_VIOLATION`), builders, and CLI creation flags
  (fail fast with slot-specific messages). Python + TypeScript verifiers check
  the same prefixes; differential gains a wrong-typed-ref NEG both languages
  (39 checks). Dangling correct-prefix hints keep `Unknown ok:true`
  semantics, gated by `evidence_usable` / `--strict-current` as before.
- **Envelope self-consistency (F7).** Attestation/status envelopes now
  crypto-verify the signature against the content issuer even without trust
  inputs; forged signatures fail `SIGNATURE_INVALID` at import/export instead
  of reading as success. Import success means well-formed + self-consistent,
  never trusted (help text states this).
- **Lifecycle target shapes (F10).** Revoke/supersede old+new require
  `att:v1:`; withdraw requires a shaped artifact id; compromise requires a
  keyref, shaped id, or `did:`. Garbage fails at STATUS, never silent lineage.
- **Denylist vs lifecycle separation (F8).** `RevocationSet` documented as the
  unsigned caller denylist; `--revoked` help and POLICY.md distinguish it from
  the signed `--status` feed; separation pinned by test (signed-revoked +
  empty denylist → INDETERMINATE, not `not_revoked` FAIL).
- **Hygiene (F12).** `is_supported_keyref` rejects empty bodies;
  `MemoryStore::with_limits` tracks `Limits` (default unchanged at 1MiB);
  `CborValue::Nint(≥0)` `debug_assert`s (release normalizes, no panic);
  `--seed <hex>` warns toward `--seed-file`; CLI stack seeds scrubbed.
  Custom-AAD APIs contracted as ADVANCED adapter-only with a cross-AAD
  non-verification test (pipeline always PE1; behavior unchanged).
- **CLI `--strict-current` single-RESULT-line rendering** (adopted in-tree):
  VALID-but-not-current proofs render one coherent verdict instead of two
  conflicting RESULT lines; `evaluate` prose reports the actual exit meaning.
  Plus `currency_tests` (4) for `is_currently_acceptable`.

### Changed (WIRE: `created_at` bound into `proof_id` — CORE freeze deviation, pre-V1.0)

- **`proof_id` now covers `created_at`.** The V1 binding map gains one key
  (`"created_at"` over the proof's own creation timestamp), closing the
  freshness gap the external review flagged: `proof_fresh` reads
  `created_at`, which a proof holder could previously re-stamp without
  breaking the binding (advisory replay hygiene only). With the timestamp
  authenticated by the id, a re-stamped envelope recomputes to a different
  `proof_id` and fails closed with `ID_MISMATCH` at IDENTIFIERS. This is a
  breaking wire change (every existing proof id changes), recorded as a
  **CORE-class deviation from the V1 freeze** in `docs/freeze-manifest.json`
  with the rationale in `ARCHITECTURE-FREEZE.md` §5: V1 is unpublished, so
  the window to fix the binding honestly is now, before golden vectors
  become normative. Golden vectors 11/12, 13–18, 24–27, 29–31 regenerated;
  Python (`interop/pengine.py`) and TypeScript (`interop/ts/pengine.ts`)
  differentials updated in lockstep and cross-verified 37/37 + 33/33.
  `proof_fresh` semantics unchanged; the now-redundant
  `proof_fresh`-without-`not_expired` CLI warning was removed, and the
  soak suite's `created_at`-flip exception is gone (every byte fails closed).
  `docs/ARCHITECTURE-CHANGE-PROPOSAL-created_at-binding.md` documents the
  decision (§11 PENDING).

### Added (independent external review hardening — envelope consistency + freshness honesty)

- **Envelope consistency (fail closed).** A proof wrapper whose `id` disagrees
  with the canonical bytes it carries is now rejected at load with
  `envelope id mismatch` (exit 2 for the CLI, 400 for `proof-api`) — never
  silently verified under a different identity. Raw transports that omit `id`
  still load by bytes alone; the pipeline report's `proof_id` remains
  authoritative. Applies to `proof-cli` (`load_proof`, all commands) and
  `proof-api` (`/v1/verify`, `/v1/evaluate`, `/v1/explain`).
- **Freshness honesty for `proof_fresh`.** `evaluate` now warns on stderr
  when a policy uses `proof_fresh` WITHOUT `not_expired`, because
  `created_at` is self-declared age (bound by `proof_id` since the wire fix
  above, so silent re-stamps fail `ID_MISMATCH`) rather than a trusted
  timestamp. Strong freshness must come from signed attestation windows
  (`not_expired`) or transparency anchoring. `examples/policies/README.md`
  documents the rule; verdicts are unchanged (the frozen pipeline and policy
  semantics stay byte-stable).
- **Repo-relative demo output.** `proof-cli demo` (no `--out`) now writes
  `<repo>/demo/out` instead of `./demo/out` relative to the caller's CWD, so
  `make demo` and `interop/differential.py --repo <repo>` agree from any
  directory (falls back to CWD-relative when run outside a checkout).

### Changed (WIRE-ADDITIVE: status-input hygiene no longer poisons validity — CORE freeze deviation, pre-V1.0)

- **Ineffective status effects are feed health, not proof failure.**
  Malformed status claims, non-status supplied objects, bad supplied
  signatures, `UNAUTHORIZED_STATUS`, and future-dated effects now record in a
  new `STATUS` stage (excluded from `evidence_validity`) instead of
  `REVOCATION`. A proof whose lifecycle is ACTIVE stays
  `crypto valid, evidence valid` with `status_inputs_valid: false` and the
  feed error in `failure_codes` — callers distinguish "proof revoked" from
  "feed broken" without conflating them. Lifecycle outcomes (REVOKED /
  COMPROMISED / UNKNOWN) stay in `REVOCATION` and still flip validity.
  Policy now evaluates (PASS/FAIL) on ACTIVE proofs with bad feeds instead of
  short-circuiting to INDETERMINATE; feed operators SHOULD alert on
  `status_inputs_valid == false`. Recorded as a CORE-class deviation in
  `ARCHITECTURE-FREEZE.md` §6: V1 unpublished, window to fix honestly is now.

### Known tradeoff (superseded by the fix above)

- **Unauthorized status objects (HISTORICAL rule, superseded).** Pre-V1.1
  builds reported `UNAUTHORIZED_STATUS` as (`crypto valid, evidence invalid`,
  lifecycle preserved) and never applied. Since the STATUS-stage fix above,
  the same case reports (`crypto valid, evidence valid`,
  `status_inputs_valid: false`, lifecycle ACTIVE) and never applies.
  Integrators SHOULD still filter untrusted feeds (or use a `StatusSource`
  adapter), but a mis-signed object no longer forces `INDETERMINATE` policy
  evaluation.

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
- **Ingestion adapter** (`ingest` CLI, P9): JSONL external event records
  (file or stdin) normalized into canonical event artifacts + manifest
  through the same builder as `create-event`; fail-closed with line numbers
  by default, `--skip-bad` lists skips in the manifest, `--dry-run`
  validates only; unknown fields rejected, never swallowed.
- **Reference API** (`crates/proof-api`, P9): thin loopback-only HTTP
  interface (no new dependencies — std sockets, `GET /v1/health|version|metrics`,
  `POST /v1/verify|evaluate|explain|ingest`); every response re-derived from
  request bytes + explicit context, never stored/cached/guessed; strict
  request-line validation, 8 MiB body cap, structured errors, shape-only
  access log + counters; async/auth/rate-limit/TLS explicitly out
  of scope per ECOSYSTEM §7.
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
- **Third independent implementation (TypeScript)**: `interop/ts/` re-verifies
  the cryptographic interop core from the spec + golden corpus — strict CBOR
  subset, Ed25519/P-256 COSE_Sign1 (`@noble/curves`), proof binding stages 1-6
  incl. composition refs and vocabularies. Its differential runner re-checks
  every in-scope golden vector generically, rejects 9 crafted mutants
  (closed-schema parity across all member slots), and verifies the Rust demo
  proof (I3b). Documented single-dependency exception to the Python
  stdlib-only rule; lives outside the stdlib CI grep.
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
