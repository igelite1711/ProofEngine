# SECURITY-MODEL.md — Proof Engine Threat & Security Model

> **Status:** Consolidated (2026-09-10). Supersedes/extends `THREAT-MODEL.md`
> (which remains accurate for the implemented V1 surface). Covers the master
> program's full threat list: forged evidence, stolen keys, replay,
> substitution, equivocation, canonicalization attacks, downgrade attacks,
> algorithm confusion, malicious external references, malicious graph
> construction, timestamp manipulation, revoked credentials, compromised
> issuer, compromised verifier, denial of service, parser attacks, resource
> exhaustion, dependency compromise. Every row: **threat → attack →
> mitigation → residual risk → test**.
>
> Guarantees and non-guarantees per `SECURITY.md`. Assume a skeptical,
> well-resourced attacker; the engine's job is to make *false acceptance
> expensive* and *every refusal loud and explainable*.

---

## 1. Assets and trust boundaries

| Boundary | In | Out |
|---|---|---|
| Crypto | canonical bytes ⇄ COSE_Sign1 | everything else is untrusted input |
| Verification | portable Proof + explicit context → report | engine holds no state between calls |
| Storage | indexes over immutable artifacts | stores never redefine a proof_id |
| Network | none in v1 (zero fetch in `verify_proof`) | future adapters are separate layers |
| AI/integrators | operate **above** the engine | can never override a `FAIL` |

**Assets:** canonical bytes, private keys (outside the engine by design),
trust lists, revocation sets, policies, report/explanation integrity,
verifier availability (bounded resources).

**Properties (in priority order per the program):** integrity → authenticity
→ freshness/currentness → binding → decision integrity → availability of
verification → privacy → confidentiality (caller-supplied transport).

## 2. Attacker model

- **A1 Malicious issuer** — signs false claims with its own valid key.
- **A2 Key thief** — holds a compromised legitimate key.
- **A3 Proof forger/mutator** — tampers bytes, swaps algs/keys/hashes,
  replays proofs, substitutes members.
- **A4 Malicious input supplier** — giant/malformed proofs, evil policies,
  bad UTF-8, deep nesting, pathological graphs.
- **A5 External-evidence liar** — different content than digest, equivocation,
  withholding.
- **A6 Clock/context manipulator** — wrong `verified_at`, overly-broad trust
  list, permissive policy, missing revocation info.
- **A7 Revocation suppressor** — withholds revocations; replays
  pre-revocation proofs.
- **A8 Supply-chain attacker** — dependency/toolchain compromise of the repo
  itself.

Out of scope (documented): compromised host/OS, broken primitives (SHA-2,
Ed25519, P-256 as standards), honest-but-malicious verifier operator who
controls their own inputs by definition.

## 3. Threat register (threat → attack → mitigation → residual → test)

### T1 — Forged evidence / tampered payload
- **Attack**: flip bytes/content while keeping the signature valid; swap an
  evidence blob under the same id.
- **Mitigation**: ids recomputed from canonical bytes on every verification
  (`ID_MISMATCH`); signatures over canonical bytes (`SIGNATURE_INVALID`);
  evidence digest binding enforced; re-encode-and-compare on decode.
- **Residual**: none while primitives hold; collision/preimage degradation is
  migration-managed (LONGEVITY §3).
- **Tests**: golden-05/08/12, mutation-soak 2000+ mutants, `cose::tampered_payload_fails`,
  CLI tamper leg of `make demo`.

### T2 — Stolen keys
- **Attack**: forger signs attestations with a stolen legitimate key.
- **Mitigation**: signatures bind the key to issued claims; revocation/
  supersession lifecycle lets an honest issuer *kill* the key's past output
  for current use; `not_revoked`/`on list` policy gates; the engine
  explicitly separates validity of the claim from trust in the key — the
  caller's trust list per evaluation time is the decisive input (TRUST.md).
- **Residual**: between theft and revocation propagation, a stolen key can
  produce *authentic* attestations. Mitigate by: freshness windows,
  revocation dissemination, per-key validity intervals (V2 capability),
  transparency anchoring (V2). None is promised silently.
- **Tests**: `build::status_object_tamper_detected`, `policy::valid_signature_by_untrusted_issuer_fails`.

### T3 — Replay
- **Attack**: re-present a valid proof as a new event/transaction
  (e.g. double-settle). The engine is stateless by design and will verify
  the same bytes as valid again.
- **Mitigation**: this is a **caller contract** (PROTOCOL.md Gate H), not an
  engine bug: id-bound member sets, validity windows, `proof_fresh`, and
  caller-maintained seen-sets of `event_id`/`proof_id` per binding context.
  The engine could not honestly claim otherwise without becoming stateful.
- **Residual**: caller ignores binding bookkeeping ⇒ misuse; no engine PASS
  is implicated. V2: transparency-anchored nonce registries, threshold-based
  freshness.
- **Tests**: policy `proof_fresh` golden + `lifecycle` skew window; PROTOCOL
  caller-contract docs.

### T4 — Substitution (member/issuer/evidence swap)
- **Attack**: swap a signed attestation into a different proof, swap
  evidence under an attestation, swap relationship endpoints.
- **Mitigation**: `proof_id` binds the exact sorted member id sets; member
  ids bind their own canonical bytes; attestation issuer is bound to the
  verifying key; relationship id covers `evidence_ref` **and**
  `attestation_ref` (the early-draft hole was fixed, `id.rs:43-49`).
- **Residual**: none within limits; partial-graph substitution across proofs
  needs composition semantics (v2).
- **Tests**: golden-12, `build.rs` cross-binding tests, `schema` id checks,
  differential I3b.

### T5 — Equivocation
- **Attack**: issuer presents the same fact with different content to
  different verifiers ("left-right" attack); evidence liar serves different
  bytes to different claimers.
- **Mitigation**: digests bind *content*; equivocation across contexts is a
  transparency problem, not an integrity problem. The engine refuses to
  silently treat mismatched digest content as valid (`verify_content_digest`).
- **Residual**: without a transparency log binding proof ids to
  observability, a malicious issuer can equivocate across verifiers — V2:
  transparency adapters (inclusion/consistency proofs), registry interfaces.
- **Tests**: digest mismatch → `ID_MISMATCH` (`hash.rs` tests, golden).

### T6 — Canonicalization attacks
- **Attack**: duplicate map keys, non-minimal ints, float/JSON drift, tag
  smuggling, alternate base64 spellings → two byte-strings with one meaning
  or one signature meaning two things.
- **Mitigation**: closed CBOR subset (floats/tags/bignum/indefinite/simple
  forbidden); shortest-form ints; bytewise-lexicographic maps; duplicate keys
  rejected; re-encode-and-compare on decode; canonical-b64 id spelling
  enforced (pad-bit variants rejected); text/bytes never conflated; no text
  normalization anywhere.
- **Residual**: implementation divergence between implementations — fuzz +
  golden vectors + independent verifier are the mitigation (they already
  caught a transposed Edwards y/x parity in the Python side once).
- **Tests**: `cbor.rs` negative suite, proptests, `fuzz::cbor_decoder`,
  golden-02/20, differential.

### T7 — Downgrade attacks
- **Attack**: strip a proof to an older version re-interpreted under new
  rules, or force a weaker algorithm — including smuggling a deprecated id
  past a verifier and calling it "historical".
- **Mitigation**: every object carries `v`; unknown versions →
  `UNSUPPORTED_VERSION`, never reinterpreted. Deprecated algs
  (`-8/-7/-35/-36`) rejected even when shape-valid, UNLESS the verifier
  explicitly opts into historical forensics (`allow_deprecated`: `-8` via
  Ed25519, `-7` via P-256-with-P-256-enabled; `-35`/`-36` never). Historical
  acceptances are labeled historical-only in SIGNATURES records and never
  imply current acceptance. Verifier `min_version`/`allowed_algs`
  configurability. Versioned parsers per format version.
- **Residual**: an environment pinned to accept v1 while the ecosystem moved
  to v2 is a caller config choice (deployment risk, not an engine flaw); a
  verifier that enables `allow_deprecated` and then treats historical
  acceptance as current trust has misread the report (operator error).
- **Tests**: `cose::deprecated_alg_8_rejected`,
  `deprecated_rejected_by_default_but_verifiable_historically`,
  `historical_es256_needs_p256_enabled`,
  `deprecated_without_verifier_support_stays_rejected`, `UNSUPPORTED_VERSION`
  golden-04, schema version tests.

### T8 — Algorithm confusion / cross-protocol reuse
- **Attack**: swap `alg` to a different family; reuse a key across protocols/
  domains; smuggle extra header labels.
- **Mitigation**: closed alg set; `kid` shape-length bound per alg; key
  `alg == header alg` re-check; domain separation `external_aad = h'504531'`
  (custom AAD only out-of-band); unexpected header labels including 6/Partial
  IV rejected; parser is algorithm-number-neutral (defends downgrade, not
  trust).
- **Residual**: misconfigured `AllowedAlgs` (caller); cross-domain key reuse
  without agreed AAD (V2 registry).
- **Tests**: `cose::header_label_6_rejected`, `non_empty_unprotected_rejected`,
  `unknown_alg_rejected`, `pq_*` structural tests.

### T9 — Malicious external references / SSRF
- **Attack**: reference URLs pointing at attacker bytes; digests lying;
  verifier tricked into fetching.
- **Mitigation**: digests are mandatory and bind content; the v1 engine
  performs **zero** fetch (`allow_remote=true` is a caller error), so SSRF is
  structurally impossible in the library; external resolution is the
  caller's job with digest comparison.
- **Residual**: a caller that fetches attacker bytes matching a digest has
  already bound them; equivocation across contexts needs transparency (V2).
- **Tests**: `allow_remote` rejection, evidence digest mismatch, PROTOCOL
  caller contracts.

### T10 — Malicious graph construction
- **Attack**: cycles, edge explosion, fake ungrounded trust edges, dangling
  endpoints, SUPERSEDES branching to confuse currentness, forged composition
  linkage (self-links, swapped sources).
- **Mitigation**: node/edge/depth limits enforced; dangling endpoint/ref →
  `DANGLING_REFERENCE`; trust-relevant edges (`OWNS|CREATED|SETTLES|
  EXECUTED` plus caller-configured additions via
  `validate_graph_with_grounding`) require grounding
  (`RELATIONSHIP_UNGROUNDED`); SUPERSEDES linear-acyclic (`CYCLE_DETECTED`,
  branch → `SCHEMA_VIOLATION`); iterative Kahn's (no hostile recursion);
  composition refs shape/sorted/bound-checked with self-links refused
  (`CYCLE_DETECTED`) — and linkage contributes nothing to validity, so a
  forged link cannot upgrade trust.
- **Residual**: non-SUPERSEDES cycles are allowed by design (references may
  be mutual) — graph *semantics* remain a policy matter.
- **Tests**: `proof-graph` suite, `fuzz::graph_ingest`, golden-09/10/24/25/26,
  composition tests.

### T11 — Timestamp manipulation
- **Attack**: backdate `issued_at`, push `expires_at` to infinity, backdate a
  revocation — or re-stamp the unauthenticated `created_at` to defeat
  `proof_fresh`.
- **Mitigation**: embedded time is an assertion, never trust; all timeliness
  evaluated against caller-supplied `verified_at` ± bounded skew; `0` clock
  fails everything; future-dated status objects never apply; skew is
  symmetric and documented. `proof_fresh` is explicitly advisory (holder can
  re-stamp `created_at` without breaking the binding — pinned by test);
  strong freshness comes from signed attestation windows and transparency.
- **Residual**: a lying verifier clock produces garbage-in/garbage-out
  (caller responsibility, declared in SECURITY.md); V2 transparency receipts
  anchor time without trusting embedded stamps.
- **Tests**: lifecycle suite (golden-15, skew window), `time_validity`,
  `created_at_restamp_moves_freshness_without_breaking_binding`.

### T12 — Revoked credentials / revocation suppression
- **Attack**: present a revoked/expired credential as current; withhold
  revocation information.
- **Mitigation**: signed status objects only (unsigned lists never trusted);
  authority bound (`original issuer` or `revocation_authorities`);
  `revocations_known_at` freshness window; missing/stale info →
  `REVOCATION_UNKNOWN` → evidence invalid, fail closed; precedence
  `REVOKED > SUPERSEDED > EXPIRED`.
- **Residual**: suppression before information reaches the verifier (no
  online status in v1). V2: transparency-anchored status, freshness
  requirements in policy, online StatusSource adapters; revocation windows
  are surfaced, never hidden.
- **Tests**: golden-16/18, lifecycle REVOCATION suite, `UNAUTHORIZED_STATUS`.

### T13 — Compromised issuer
- **Attack**: attacker controls an issuer key and signs false-but-valid
  attestations (A1).
- **Mitigation**: the engine never equates a valid signature with trust:
  `issuer_trusted` requires the caller's trust list; the pipeline's triple
  keeps `cryptographic_validity` separate from any policy outcome; deny-list
  (`issuer_excluded`) exists for sanctions screening; revocation lets the
  ecosystem kill currentness; signed `compromise` markings taint at/after
  their instant (`COMPROMISED`, history not preserved — stronger than
  revocation) via self-report or revocation authorities.
- **Residual**: a trusted-but-honest-comprising issuer is a *trust-model*
  failure, not an engine failure; mitigations: multiple independent issuers
  (AND-of-issuers), external authority reviews, domain policy.
- **Tests**: `policy::valid_signature_by_untrusted_issuer_fails`,
  `status_attestations_never_satisfy_issuer_trusted`, demo policy-contrast leg,
  golden-30, compromise unit tests.

### T13b — Delegation and equivalence abuse
- **Attack**: rogue `delegate` grant minting authority for an attacker key;
  malicious `identity.bind`/EQUIVALENT merging victim and attacker identities;
  delegation cycles causing non-termination; scope confusion (narrow grant
  used broadly).
- **Mitigation**: delegation without a trust-listed root is nothing
  (`delegated_authority` requires listed root + verified attestation +
  active-link chain); chains traverse ACTIVE links only (expired/revoked/
  compromised links break the chain fail-closed); cycle-safe BFS bounded by
  delegation count; scope strings match exactly when the requirement names
  one (opaque otherwise, documented); equivalence honored only from
  trust-listed asserters, never transitive-by-core, never global; EQUIVALENT
  edges require grounding like other trust-relevant types; shaped ids must
  still resolve (DANGLING).
- **Residual**: a trusted root that delegates recklessly is a trust-model
  failure; scope semantics belong to domains (core checks string equality
  only); cross-namespace identifier collisions are prevented by namespaces,
  not by the core.
- **Tests**: `policy_v2` delegation/identity suites (chains, cycles,
  untrusted asserters, scope mismatch), graph EQUIVALENT tests.

### T13c — Vocabulary confusion
- **Attack**: same label string meaning different things across domains
  (`invoice` in payments vs logistics); undeclared namespace smuggling new
  semantics past reviewers; version downgrade (old meaning reasserted).
- **Mitigation**: namespaces make collisions structurally impossible
  (`acme:invoice` ≠ `legacy invoice`); declarations bound by `proof_id`
  (dropping them changes the id); contexts restrict via
  `accepted_vocabularies` with informational notes; policy v2
  `vocabulary_accepted` adjudicates; verifiers never fold/normalize.
- **Residual**: two parties using the same namespace with different private
  meanings is a coordination failure (registries are ecosystem work, V2).
- **Tests**: golden-27, vocabulary unit tests, `vocabulary_accepted` tests.

### T14 — Compromised verifier
- **Attack**: attacker modifies verifier logic/trust inputs to force PASS.
- **Mitigation**: determinism (`same bytes + inputs ⇒ same report`),
  canonical self-checks, report/explanation derived purely from state, stable
  codes, no engine state to corrupt, and the independent Python verifier as a
  reference oracle. Trust inputs are explicit and echoed.
- **Residual**: a compromised host/process can change anything (declared out
  of scope); mitigations are ecosystem-level: reproducible builds, signed
  releases, SBOM (V2), independent re-verification.
- **Tests**: demo determinism gate, fuzz determinism assertions, differential
  I2/I3.

### T15 — Denial of service (verifier as a primitive)
- **Attack**: giant proofs, huge member counts, deep nesting, many evidence
  items, exploit vectors (future: remote APIs, ingestion).
- **Mitigation**: hard `Limits` (1 MiB proof, 64 KiB field, 64 evidence, 128
  nodes, 256 edges, depth 16, 32 policy requirements/expression nodes, 64
  status objects, 32 trust list, 16 authorities, 16 referenced proofs, 16
  vocabularies) configurable downward and enforced before
  allocation-heavy work; CLI input capped at 8 MiB at buffering; iterative
  decoders (no stack overflow); no network listener in v1.
- **Residual**: allocator pressure on pathological but in-limit inputs;
  arbitrary CPU is bounded but not free — deployers tune limits downward.
- **Tests**: `LIMIT_EXCEEDED` golden, `cli_e2e::oversized_input_files_fail_closed`,
  `fuzz::proof_verify`.

### T16 — Parser attacks / malformed input
- **Attack**: truncated streams, trailing bytes, bad UTF-8, odd-length maps,
  reserved additional-infos, invalid base64, wrong tag shapes.
- **Mitigation**: strict decoder (every forbidden construct rejected);
  re-encode-and-compare; UTF-8 validated; `MALFORMED`, `DUPLICATE_MAP_KEY`,
  `INVALID_BASE64URL`, `FORBIDDEN_CBOR_CONSTRUCT`, `UNEXPECTED_HEADER_PARAM`;
  parse failures become fail-closed *reports*, never panics (AUDIT F5
  remediation: remove remaining `unwrap/expect/panic` from prod paths and add
  a CI grep gate).
- **Residual**: none within limits once F5 is closed; fuzz is the ongoing
  backstop.
- **Tests**: `cbor.rs` negative matrix, proptests, `fuzz::cbor_decoder`,
  golden malformed vectors.

### T17 — Resource exhaustion (sub-threat of T15/T16)
Same as T15, plus: `max_trusted_issuers`, `max_status_objects`,
`max_revocation_authorities` bound the verification-context vectors, and the
policy requirement count is bounded. Residual: none within bounds.

### T18 — Dependency compromise
- **Attack**: a compromised transitive dependency (ed25519-dalek, p256, sha2,
  serde…) exfiltrates or weakens crypto; yanked/advisory package in the tree.
- **Mitigation**: locked builds (`--locked`, Cargo.lock), `cargo-deny`
  (advisories deny, yanked deny, license allow-list, crates.io-only
  sources), RustSec advisory scan in CI, minimal dependency set (7 path
  crates + small public stack), no git/registry sources, no wildcard
  constraints. Unsafe-code policy: **zero** `unsafe` in all crates (deny.fmt
  + review discipline).
- **Residual**: upstream compromise of a well-vetted crate is possible in
  principle; mitigations: upstream replace/review cadence, SBOM +
  signed/source-built releases + provenance attestations (V2),
  `cargo vet`-style audit (V2).
- **Tests**: `.github/workflows/ci.yml` deny job, `deny.toml`, `cargo tree`
  scan (Phase 7 gate in `docs/phase7-report.md`).

---

## 4. Resource safety (enforced, not advisory)

`max_proof_size 1 MiB · max_field_size 64 KiB · max_depth 16 ·
max_array_items 256 · max_map_entries 64 · max_evidence_items 64 ·
max_nodes 128 · max_edges 256 · max_sig_size 256 B · max_policy_requirements
32 · max_status_objects 64 · max_trusted_issuers 32 ·
max_revocation_authorities 16`. Exceeded ⇒ `LIMIT_EXCEEDED` with an object
path. Decoders are iterative (depth counter, no recursion on hostile input);
CLI file inputs capped at 8 MiB before buffering (`MAX_INPUT_FILE_BYTES`).

## 5. Supply-chain security posture (honest)

Already in place: `cargo build/test --locked`, Cargo.lock committed, deny
gates (advisories/bans/licenses/sources/yanked), zero `unsafe`, minimal deps,
PR build gate for fuzz + nightly 600s smoke per target, traceability +
neutrality gates, deterministic demo byte-pin.

Gaps (open, not claimed): no SBOM artifact, no signed release artifacts, no
SLSA-style provenance attestations, no `cargo vet`-style audit chain, advisory
job runs `continue-on-error` (deny is the real gate). These are V2
operational rows (`MIGRATION-PLAN.md` §Phase-10/11).

## 6. Privacy & confidentiality

- **Default posture (v1):** proofs carry digests, not content; metadata is
  flat text/uint/bool chosen by the producer; logs must never contain
  secrets/evidence (key `Debug` impls are redacted).
- **Logical claims** (subjects, kinds, relationship types) are visible in the
  proof by design — proofs are for sharing.
- **V2 (additive, not silent):** selective disclosure, redaction *with*
  integrity preservation, commitments, encrypted evidence, ZK-based proofs of
  evidence-knowledge. The engine's ZK story must always remain: mechanism,
  never mandated.

## 7. Verification-as-data & decision integrity

- Every verdict triple + lifecycle + explanation is **plain data** — it can
  be re-derived from the same (bytes, context) pair by anyone, any time.
- Explanation text is a pure projection of report state; it can never
  contradict the machine verdict (tested on every vector). Integrators may
  not override `FAIL`; the API hands decisions to policy, which the caller
  owns.
- This is what makes the "no Proof Engine trust" property real: a skeptical
  third party re-runs the same algorithm and gets the same answer.

## 8. Operational security (services, V2)

Logging: structured, no proof payloads, no secrets, no PII by default, safe
ids/digests only. Metrics/traces are non-functional for the core (core has no
telemetry dependency). Incidents: report via SECURITY.md private channel;
90-day coordinated disclosure default; fixes land with capability-map and
changelog notes. Audit logging of trust inputs is already partial
(REVOCATION note echoes status counts + `revocations_known_at`).

## 9. Residual top-3 risks (watch order)

1. **Canonical-CBOR divergence** between implementations (highest interop
   risk) — mitigated by fuzz + vectors + differential; keep fused.
2. **Revocation freshness without online status** (suppression window) —
   surfaced as `REVOCATION_UNKNOWN`; never hidden; V2 transparency.
3. **Caller misconfiguration** (trust list/clock/policy) turning a correct
   engine into a wrong decision — mitigated by loud, auditable explanation
   headers and fail-closed defaults; cannot be fixed in-engine.

## 10. Conformance checklist (for every release)

- [ ] All golden vectors pass on clean checkout.
- [ ] `fuzz` smoke green ≥600 s/target; no new parser surfaces unfuzzed.
- [ ] Mutation-soak green; every tampered byte fails closed.
- [ ] No `unsafe`, no `unwrap/expect/panic` in production paths (grep gate).
- [ ] No deprecation/version/alg downgrade path accepted.
- [ ] Fresh vulnerability scan (deny + advisory) green for the tree.
- [ ] Docs claim only what tests prove (VERIFICATION.md rule).