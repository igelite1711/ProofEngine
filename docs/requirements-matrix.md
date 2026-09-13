# Proof Engine — Requirements Traceability Matrix (V1)

Every row is machine-checked by `tools/check_traceability.py` (run via
`make trace` and CI): each ID MUST appear as a `// PE-XXX-NNN` comment at
its implementation site, and each row MUST name at least one positive and
one negative test that exist. Orphans fail the build.

Conventions: `PE-<gate>-<nnn>`. Gates: FMT format · CRYPTO cryptography ·
EVID evidence · GRAPH graph · VERIFY pipeline · POLICY policy · LIFE
lifecycle/time · TRUST trust · SEC security bounds · CLI interface ·
INTEROP interoperability · OPS operational controls.

## FMT — canonical serialization (FORMAT.md §1)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-FMT-001 | Map keys in lexicographic byte order | FORMAT §1 | `proof-format/src/cbor.rs` encode/decode | `cbor::map_keys_sorted_lexicographically` | `cbor::is_canonical_detects_reordered_map` |
| PE-FMT-002 | Shortest-form integers only | FORMAT §1 | `proof-format/src/cbor.rs` read_arg | `cbor::round_trip_primitives` | `cbor::non_shortest_int_rejected` |
| PE-FMT-003 | Duplicate map keys rejected | FORMAT §1 | `proof-format/src/cbor.rs` decode map | — (decoder invariant) | `cbor::duplicate_map_key_rejected`, golden-02 |
| PE-FMT-004 | Forbidden constructs rejected (float/tag/indefinite/bignum/simple) | FORMAT §1 | `proof-format/src/cbor.rs` decode | — | `cbor::forbidden_constructs_rejected` |
| PE-FMT-005 | Trailing bytes rejected; invalid UTF-8 rejected | FORMAT §1 | `proof-format/src/cbor.rs` decode_strict | — | `cbor::trailing_bytes_and_empty_rejected`, `cbor::invalid_utf8_rejected` |
| PE-FMT-006 | Depth/size/entry limits enforced pre-allocation | FORMAT §1, THREAT-MODEL §5 | `proof-format/src/cbor.rs`, `proof-core/src/limits.rs` | `graph::depth_limit_enforced` | `cli_e2e::oversized_input_files_fail_closed` |
| PE-FMT-007 | Decode→re-encode identity (no canonicalization ambiguity) | FORMAT §1 | `proof-format/src/cbor.rs` decode+encode | `cbor::prop_encode_decode_round_trip` | `cbor::prop_raw_bytes_reject_or_round_trip`, `fuzz::cbor_decoder` |
| PE-FMT-008 | Closed schemas: unknown fields/versions rejected; open vocabularies transported verbatim (V1.0 NEUTRAL) | FORMAT §4, NEUTRALITY §2 | `proof-format/src/schema.rs` check_closed/check_version | `schema::event_round_trip`, `schema::unknown_event_type_accepted` | `schema::unknown_field_rejected` |
| PE-FMT-009 | Text normalization: none — ids/signatures bind exact UTF-8 bytes as given (golden-20) | FORMAT §3.1 | `proof-format/src/cbor.rs` decode_strict | `cbor::text_bytes_as_given_no_normalization` | `cbor::nfc_nfd_are_distinct_ids`, `cbor::golden_20_text_byte_identity` |

## CRYPTO — signatures, hashes, identifiers (FORMAT.md §2–§3, CRYPTO.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-CRYPTO-001 | Closed alg set: -19 required, -9 opt-in, -8/-7/-35/-36 deprecated | FORMAT §5 | `proof-crypto/src/alg.rs`, `cose.rs` verify | `cose::sign_verify_round_trip_ed25519` | `cose::deprecated_alg_8_rejected` |
| PE-CRYPTO-002 | Protected header exactly {1:alg, 4:kid}; unprotected empty | FORMAT §5 | `proof-crypto/src/cose.rs` build/parse | `cose::sign_verify_round_trip_ed25519` | `cose::header_label_6_rejected` |
| PE-CRYPTO-003 | Domain separation external_aad = h'504531' ("PE1") | FORMAT §5 | `proof-crypto/src/cose.rs` EXTERNAL_AAD | `cose::external_aad_is_pe1` | `cose::tampered_payload_fails` |
| PE-CRYPTO-004 | Sig_structure ["Signature1", protected, aad, payload] per RFC 9052 §4.4 | FORMAT §5 | `proof-crypto/src/cose.rs` sig_structure | `golden::golden_04_valid_sign1` | `golden::golden_05_tampered_sign1` |
| PE-CRYPTO-005 | Key binding: issuer == signing key; alg matches key shape | FORMAT §5 | `proof-crypto/src/cose.rs` verify_sign1, `build.rs` attest | `build::attestation_sign_verify_ok` | `build::attestation_wrong_key_fails` |
| PE-CRYPTO-006 | Deterministic ids sha256(canonical), typed prefix, b64u-no-pad | FORMAT §3 | `proof-crypto/src/id.rs` | `id::ids_stable_and_bound`, `golden::golden_01_event_canonical` | `id::id_mismatch_on_tamper`, `golden::golden_12_mutated_proof` |
| PE-CRYPTO-010 | Signature determinism: Ed25519 (RFC 8032) + ECDSA P-256 (RFC 6979) byte-identical for fixed key+message; randomized schemes require a MAJOR re-scope | LONGEVITY §5 | `proof-crypto/src/cose.rs` | `cose::signing_is_deterministic_ed25519_and_esp256` | `cose::esp256_tampered_payload_fails`, `cose::esp256_wrong_key_fails` |
| PE-CRYPTO-011 | ESP256 (P-256) golden vectors 21/22/23 + independent pure-Python verification | LONGEVITY §4, INTEROPERABILITY | `fixtures/golden-21.json`, `interop/pengine.py` | `golden::golden_21_esp256_valid_sign1` | `golden::golden_22_esp256_tampered_rejected`, `golden::golden_23_esp256_wrong_key_rejected` |
| PE-CRYPTO-009 | Ids carry one full SHA-256 digest; truncated/oversized digest refs rejected; no normalization (FORMAT §3, §3.1) | FORMAT §3 | `proof-crypto/src/id.rs` verify_id, `proof-cli/src/main.rs` hex validation | `id::id_digest_must_be_full_sha256`, `cli_e2e::artifact_workflow_verify_then_revoke` | `main::truncated_digest_refs_rejected_as_usage_error`, `cbor::golden_20_text_byte_identity` |
| PE-CRYPTO-007 | proof_id binds proposition + `created_at` + sorted member id sets (created_at covered — V1 CORE freeze deviation, pre-V1.0 wire fix) | FORMAT §3 | `proof-crypto/src/id.rs` proof_id | `policy::created_at_restamp_breaks_binding_and_fails_id_mismatch` | `golden_proof::golden_12_mutated_proof`, `soak::bit_flips_fail_closed` |
| PE-CRYPTO-008 | Hash agility via HashRef alg enum; digest lengths enforced | FORMAT §2 | `proof-core/src/hash.rs`, `proof-crypto/src/hash.rs` | `build::evidence_create_verify_ok_and_tamper_fails` | `hash::digest_lengths_enforced` (added C3) |

## EVID — evidence (FORMAT.md §4.3)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-EVID-001 | Evidence builders enforce schema before id assignment | FORMAT §4.3 | `proof-crypto/src/build.rs` make_evidence | `build::evidence_create_verify_ok_and_tamper_fails` | `schema::unknown_field_rejected` |
| PE-EVID-002 | Attestation evidence_ref must resolve in-proof (digest-only externals) | FORMAT §4.6 | `proof-verify/src/pipeline.rs` EVIDENCE stage | `graph::valid_chain_passes` | `proof::dangling_evidence_ref_fails_evidence` (added C3) |
| PE-EVID-003 | External content never fetched (no network in V0.1) | THREAT-MODEL §3.9 | `proof-verify/src/pipeline.rs` allow_remote guard | `proof::remote_fetch_request_is_caller_error` | — (absence: no net deps, A12) |
| PE-EVID-004 | Evidence digests bind content; tamper detected via id recompute | SECURITY.md | `proof-crypto/src/id.rs` evidence_id | `golden::golden_06_builder_chain` | `golden::golden_08_evidence_tamper` |

## GRAPH — proof graph (FORMAT.md §4.4)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-GRAPH-001 | Typed edges; OWN/CREATED/SETTLES/EXECUTED require grounding | FORMAT §4.4 | `proof-graph/src/lib.rs` validate_graph | `graph::valid_chain_passes` | `graph::ungrounded_settles_rejected` |
| PE-GRAPH-002 | Dangling endpoints/references rejected | FORMAT §4.6 | `proof-graph/src/lib.rs` | `graph::valid_chain_passes` | `graph::dangling_endpoint_rejected` |
| PE-GRAPH-003 | SUPERSEDES acyclic + linear + depth-bounded; other cycles allowed by default; opt-in provenance DAG profile (`require_acyclic_provenance`) rejects any cycle | FORMAT §4.4 | `proof-graph/src/lib.rs` Kahn check + `check_acyclic_provenance` | `graph::non_supersedes_cycles_allowed`, `graph::provenance_dag_allows_chains_rejects_cycles` | `graph::supersedes_cycle_rejected`, golden-10 |
| PE-GRAPH-004 | Node/edge/depth/size limits enforced (bounded traversal) | THREAT-MODEL §5 | `proof-graph/src/lib.rs`, `proof-verify/src/builder.rs` | `graph::depth_limit_enforced` | `graph::edge_limit_enforced`, oversized tests |

## VERIFY — pipeline (ARCHITECTURE.md §4)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-VERIFY-001 | Stage 1 PARSE: strict decode within limits | ARCH §4 | `proof-verify/src/pipeline.rs` verify_proof | `golden_proof::golden_11_valid_proof` | `proof::garbage_bytes_fail_parse_closed` |
| PE-VERIFY-002 | Stage 2 SCHEMA: envelope/member closed validation | ARCH §4 | `proof-verify/src/pipeline.rs` | `golden_proof::golden_11_valid_proof` | `proof::wrong_version_fails_schema` |
| PE-VERIFY-003 | Stage 3 CANONICAL: re-encode byte-identity | ARCH §4 | `proof-verify/src/pipeline.rs` | `golden_proof::golden_11_valid_proof` | `golden::golden_03_non_canonical` |
| PE-VERIFY-004 | Stage 4 IDENTIFIERS: proof_id recompute + compare | ARCH §4 | `proof-verify/src/pipeline.rs` | `golden_proof::golden_11_valid_proof` | `proof::mutated_proof_id_fails_identifiers` |
| PE-VERIFY-005 | Stage 5 SIGNATURES: COSE verify + envelope/payload agreement | ARCH §4 | `proof-verify/src/pipeline.rs` | `golden_proof::golden_11_valid_proof` | `proof::mutated_signature_fails_signatures_stage` |
| PE-VERIFY-006 | Stage 6 KEYS: kid shape, alg agreement, issuer binding | ARCH §4 | `proof-verify/src/pipeline.rs` | `proof::valid_proof_verifies_portable` | `build::attest_refuses_foreign_issuer` |
| PE-VERIFY-007 | Stage 7 TIME: explicit clock + symmetric skew | ARCH §4 | `proof-verify/src/pipeline.rs` time_validity | `lifecycle::active_proof_reports_active_lifecycle` | `lifecycle::expired_attestation_fails_with_expired` |
| PE-VERIFY-008 | Stage 8 REVOCATION (lifecycle) + STATUS (feed hygiene, V1.1): signed status only + authority + timeliness; hygiene never flips validity (`status_inputs_valid`) | ARCH §4 | `proof-verify/src/pipeline.rs` | `lifecycle::revoked_attestation_fails_with_revoked` | `lifecycle::unauthorized_revocation_fails` |
| PE-VERIFY-009 | Stages 9–11 EVIDENCE/RELATIONSHIPS/GRAPH | ARCH §4 | `proof-verify/src/pipeline.rs`, `proof-graph` | `proof::valid_proof_verifies_portable` | `proof::ungrounded_proof_separates_crypto_from_evidence` |
| PE-VERIFY-010 | Failures recorded never repaired; stages never skipped | ARCH §4 | `proof-verify/src/pipeline.rs` finalize/stage_valid | `proof::valid_proof_verifies_portable` | `soak::bit_flips_fail_closed` |
| PE-VERIFY-011 | Early exit reports evidence Invalid (no vacuous Valid) | ARCH §4 | `proof-verify/src/pipeline.rs` finalize | `golden_proof::golden_11_valid_proof` | `proof::garbage_bytes_fail_parse_closed` |
| PE-VERIFY-012 | Deterministic verdict + codes for fixed inputs | VERIFICATION.md | `proof-verify/src/pipeline.rs` | `soak::codes_are_stable_across_runs` | `fuzz::proof_verify` |

## POLICY — decisions (POLICY.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-POLICY-001 | signature_valid reflects pipeline crypto only | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::broken_proof_yields_indeterminate_not_fail` |
| PE-POLICY-002 | issuer_trusted needs list AND verified presence | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::valid_signature_by_untrusted_issuer_fails` |
| PE-POLICY-003 | relationship_exists over validated graph types | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::same_evidence_passes_merchant_fails_strict` |
| PE-POLICY-004 | not_expired over all attestations vs verifier clock | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::expired_attestation_fails_closed_at_pipeline` |
| PE-POLICY-005 | not_revoked over caller revocation set | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::revoked_attestation_fails_not_revoked` |
| PE-POLICY-006 | not_superseded over pipeline lifecycle | POLICY.md | `proof-policy/src/eval.rs`, `state.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::superseded_attestation_fails_not_superseded` |
| PE-POLICY-007 | evidence_present / transparency_present over proof contents | POLICY.md | `proof-policy/src/eval.rs` | `policy::same_evidence_passes_merchant_fails_strict` | `policy::same_evidence_passes_merchant_fails_strict` |
| PE-POLICY-008 | Closed set, AND semantics, empty rejected, deterministic | POLICY.md | `proof-policy/src/policy.rs`, `eval.rs` | `policy::valid_policy_parses` | unknown/empty/extra tests |
| PE-POLICY-009 | Broken proofs → INDETERMINATE (never downgraded/upgraded) | POLICY.md | `proof-policy/src/eval.rs` | `policy::broken_proof_yields_indeterminate_not_fail` | `policy::inconsistent_policy_clock_cannot_turn_fail_into_pass` |
| PE-POLICY-010 | Explanations are pure projections (never contradict verdict) | POLICY.md | `proof-policy/src/explain.rs` | `policy::explanations_never_contradict_verdicts` | — (property of construction) |

## LIFE — lifecycle and time (LIFECYCLE.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-LIFE-001 | ACTIVE/EXPIRED/REVOKED/SUPERSEDED/UNKNOWN states | LIFECYCLE.md | `proof-verify/src/pipeline.rs`, `proof-core/src/model.rs` | `lifecycle::superseded_old_preserves_history` | `golden_proof::golden_lifecycle_vectors_verify_as_recorded` |
| PE-LIFE-002 | verified_at=0 sentinel → EXPIRED (no trustworthy clock) | LIFECYCLE.md | `proof-verify/src/pipeline.rs` time_validity | `lifecycle::zero_clock_fails_closed` | — |
| PE-LIFE-003 | Skew symmetric on both bounds, saturating arithmetic | LIFECYCLE.md | `proof-verify/src/pipeline.rs`, `eval.rs` | `lifecycle::expiry_within_skew_window_is_still_active` | `lifecycle::future_dated_status_object_ignored` |
| PE-LIFE-004 | Revocation freshness: missing/stale → UNKNOWN → fail closed | LIFECYCLE.md | `proof-verify/src/pipeline.rs` | `lifecycle::stale_revocation_info_fails_closed` | `golden_proof::golden_lifecycle_vectors_verify_as_recorded` |
| PE-LIFE-005 | SUPERSEDED preserves history; REVOKED > SUPERSEDED > EXPIRED precedence | LIFECYCLE.md | `proof-verify/src/pipeline.rs` | `lifecycle::superseded_old_preserves_history` | `lifecycle::revoked_attestation_fails_with_revoked` |
| PE-LIFE-006 | Status authority: original issuer or revocation_authorities; future-dated refused | LIFECYCLE.md | `proof-verify/src/pipeline.rs` | `lifecycle::revocation_authority_may_revoke` | `lifecycle::unauthorized_revocation_fails` |

## TRUST — trust model (TRUST.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-TRUST-001 | Valid signature alone never yields trust | TRUST.md | `proof-policy/src/eval.rs` IssuerTrusted | `policy::same_evidence_passes_merchant_fails_strict` | `policy::valid_signature_by_untrusted_issuer_fails` |
| PE-TRUST-002 | Attacker kid never establishes trust (self-bound keys) | TRUST.md | `proof-crypto/src/cose.rs`, `build.rs` | `build::attest_refuses_foreign_issuer` | `cose::wrong_key_fails` |
| PE-TRUST-003 | Defaults fail closed (zero clock, empty trust, no status) | TRUST.md | `proof-verify/src/pipeline.rs`, `eval.rs` defaults | `lifecycle::zero_clock_fails_closed` | — |
| PE-TRUST-004 | Status attestations never satisfy issuer trust | TRUST.md | `proof-policy/src/state.rs` | `policy::status_attestations_never_satisfy_issuer_trusted` | — |
| PE-TRUST-005 | Key rotation: trust list is caller input constrained by evaluation time; no authority from key age/possession | TRUST.md Key lifetime | `proof-policy/src/eval.rs` EvalInputs | `policy::valid_signature_by_untrusted_issuer_fails` | — |

## SEC — security bounds (THREAT-MODEL.md, SECURITY.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-SEC-001 | Bounded decode/build/verify (no unbounded alloc/recursion) | THREAT-MODEL §5 | limits + iterative graph | `graph::edge_limit_enforced` | `graph::supersedes_cycle_rejected` |
| PE-SEC-002 | CLI input files capped pre-buffering (8 MiB) | THREAT-MODEL §4 | `proof-cli/src/lib.rs` read_input_file | `cli_e2e::oversized_input_files_fail_closed` | — (size sweep in test) |
| PE-SEC-003 | No network fetch during verification | THREAT-MODEL §3.9 | `proof-verify/src/pipeline.rs` allow_remote | `proof::remote_fetch_request_is_caller_error` | `.github/workflows/ci.yml` |
| PE-SEC-004 | No panic on hostile input (library paths) | THREAT-MODEL §3.7 | all crates (no unwrap in prod paths) | `soak::bit_flips_fail_closed` | `fuzz::proof_verify` |
| PE-SEC-005 | Base64url ids use canonical alphabet, no-pad | FORMAT §3 | `proof-crypto/src/id.rs`, `keys.rs` | `id::ids_stable_and_bound` | `id::id_rejects_non_canonical_b64` |

## CLI — interface contract (FORMAT.md §7 CLI, USAGE)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-CLI-001 | Exit codes 0 PASS / 1 verdict / 2 usage-engine error | README, POLICY.md | `proof-cli/src/main.rs` run | `main::help_exits_0` | `main::usage_errors_exit_2_not_1` |
| PE-CLI-002 | Artifacts re-verified on every load (transport, never authority) | README | `proof-cli/src/artifact.rs`, `check.rs` | `cli_e2e::artifact_workflow_verify_then_revoke` | `cli_e2e::tampered_artifact_file_rejected_at_build` (added C3) |
| PE-CLI-003 | Explicit clock mandatory; wall clock never read | README | `proof-cli/src/make.rs` common | `cli_e2e::artifact_workflow_verify_then_revoke` | `main::usage_errors_exit_2_not_1` |
| PE-CLI-004 | Machine-readable reports to stdout/file; progress to stderr | README | `proof-cli/src/check.rs` emit_report | `cli_e2e::demo_is_deterministic_and_green` | — |
| PE-CLI-005 | Demo deterministic byte-identical (fixed key + timestamps) | README | `proof-cli/src/demo.rs` | `cli_e2e::demo_is_deterministic_and_green` | `.github/workflows/ci.yml` |
| PE-CLI-006 | explain prints prose only (never JSON over prose) | ARCH §7 | `proof-cli/src/make.rs` evaluate | `policy::explanations_never_contradict_verdicts` | — |
| PE-CLI-007 | evaluate --json: machine-readable policy_outcome+report, exit contract unchanged, explain prose-only | POLICY.md Machine-readable output | `proof-cli/src/check.rs` outcome_json, `make.rs` evaluate | `policy::policy_outcome_json_matches_evaluator` | `cli_e2e::evaluate_json_flag_keeps_exit_contract` |

## INTEROP — independent verification (INTEROPERABILITY.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-INTEROP-001 | Golden vectors pin bytes/ids/verdicts (20 incl. policy + text-identity) | INTEROPERABILITY.md | `fixtures/golden-*.json` + generators | `golden::golden_01_event_canonical` | `golden::golden_05_tampered_sign1` |
| PE-INTEROP-002 | I2: stdlib-only implementation verifies Rust artifacts | INTEROPERABILITY.md | `interop/pengine.py` verify | `interop/differential.py` | `.github/workflows/interop.yml` |
| PE-INTEROP-003 | I3: independent implementation creates artifacts both sides verify | INTEROPERABILITY.md | `interop/pengine.py` create + sign | `interop/differential.py` | `.github/workflows/interop.yml` |

## OPS — operational controls (VERIFICATION.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-OPS-001 | Locked reproducible build | VERIFICATION.md | `Cargo.lock`, `--locked` | `.github/workflows/ci.yml` | — (lock enforced by flag) |
| PE-OPS-002 | Supply chain: advisories, bans, licenses, sources | VERIFICATION.md | `deny.toml`, CI deny job | `deny.toml` | — (deny fails closed on violation) |
| PE-OPS-003 | Fuzz targets build per PR; smoke nightly with log | VERIFICATION.md | `.github/workflows/fuzz.yml` | `.github/workflows/fuzz.yml` | — (first-run invariant catch 7d9db44) |
| PE-OPS-004 | Demo determinism enforced in CI (sha256 rerun) | VERIFICATION.md | `.github/workflows/ci.yml` demo job | `cli_e2e::demo_is_deterministic_and_green` | — |
| PE-OPS-005 | No forbidden dependency families in tree | IMPLEMENTATION_PLAN A12 | `Cargo.lock` review + deny bans | `deny.toml` | — |
| PE-OPS-006 | Release SBOM + provenance: deterministic CycloneDX from lockfile, build record, hashes | RELEASE.md | `tools/gen_sbom.py`, `tools/gen_provenance.py`, `Makefile` release-meta | `.github/workflows/ci.yml` | — (determinism diff fails the gate itself) |
| PE-FREEZE-001 | Semantic foundation untouched since the pin except approved change records | ARCHITECTURE-FREEZE.md §5 | `tools/check_freeze.py`, `docs/freeze-manifest.json`, `Makefile` freeze-guard | `.github/workflows/ci.yml` | — (any unapproved frozen-path diff fails the gate itself) |

## LONG — longevity & post-quantum readiness (docs/LONGEVITY.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-LONG-001 | Identifier digest migration window: new digest via id `:vN:` bump, dual-verify, then cutover; unknown versions fail closed | LONGEVITY §3 | `proof-crypto/src/id.rs` | `docs/LONGEVITY.md` | `crates/proof-crypto/src/id.rs` |
| PE-LONG-002 | Signature algorithm migration on closed registry, default-off, additive keyref prefixes, hybrid dual-sign bridge | LONGEVITY §4 | `proof-crypto/src/alg.rs`, `cose.rs` | `docs/LONGEVITY.md` | `crates/proof-crypto/src/alg.rs` |

## NEUT — core neutrality (docs/NEUTRALITY.md)

| ID | Requirement | Spec | Implementation | Positive test | Negative test |
|----|-------------|------|----------------|---------------|---------------|
| PE-NEUT-001 | No domain vocabulary as logic in mechanism crate sources | NEUTRALITY §2 | `tools/check_neutrality.py` grep gate | `make neutrality` | `.github/workflows/ci.yml` |
| PE-NEUT-002 | Valid signature / trusted issuer / PASS never conflated | NEUTRALITY §4 | `proof-policy/src/eval.rs`, `proof-verify/src/pipeline.rs` | `policy::valid_signature_by_untrusted_issuer_fails` | `policy::status_attestations_never_satisfy_issuer_trusted` |
| PE-NEUT-003 | Same core traversed by ≥3 unrelated domains (differential test) | NEUTRALITY §6 | `domains/proof-domains/tests/differential.rs` | `domains/proof-domains/tests/differential.rs` | `differential::unknown_domain_vocabulary_policy_fail_closed` |
| PE-NEUT-004 | Domain vocabulary lives only in tests/fixtures/docs/demos | NEUTRALITY §2 | `tools/check_neutrality.py` exemptions | `core::tests::extensibility_demonstration` | `make neutrality` |
| PE-NEUT-005 | Neutral capability spec + domain-mapping guide exist | NEUTRALITY §5 | `tools/check_neutrality.py` doc, `docs/capability-map.md` | `docs/capability-map.md`, `docs/domains/README.md` | — |
