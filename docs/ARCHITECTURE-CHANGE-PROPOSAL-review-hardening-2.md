# Architecture Change Proposal: External-Review Hardening Batch 2

**Classification: CORE (conformance, pre-V1.0) + GENERIC EXTENSION (V2 `claim_field` leaf) — §11 PENDING**

| | |
|---|---|
| Proposal | Close 12 substantiated review findings (F1–F12 follow-up): spec/code alignment, typed references, envelope self-consistency, lifecycle target shapes, feed honesty, claim-value predicates, hygiene |
| Layer | `proof-format` (schema/store/cbor) + `proof-crypto` (claim/envelope/keys/build/cose) + `proof-verify` (pipeline/context) + `proof-policy` (V2 leaf, v1 frozen) + `docs/format.cddl` + `docs/policy-grammar.ebnf` |
| Trigger | Independent external review, second pass (12 findings, all reproduced against the tree) |
| Status | Implemented; merge requires maintainer decision (ARCHITECTURE-FREEZE.md §6) |

## 1. Problem

| # | Sev | Finding |
|---|---|---|
| F1 | HIGH | `docs/format.cddl` states `created_at` is NOT covered by `proof_id`; code, FORMAT.md, both interop verifiers, and freeze F2 all state it IS covered. An implementer following CDDL alone computes wrong ids. |
| F2 | HIGH | Revocation blindness: `verify --revocations-known-at <t>` with zero `--status` objects reports ACTIVE/VALID. Freshness is caller-asserted, never feed-proved, with no warning and no opt-in fail-closed mode. |
| F3 | HIGH | Policy is presence-only: no requirement can adjudicate `claim.fields` values (amounts, thresholds, ranges). Real acceptance rules must fork adjudication outside the engine. |
| F4 | MED | `attestation.evidence_ref` accepts any text; `att:v1:`/`evt:v1:` values pass resolution and ride as hints. |
| F5 | MED | `evidence.attestation_ref` accepts any text; wrong-typed values degrade to `Unknown ok:true` instead of failing closed. |
| F6 | MED | Python interop verifier enforces field names only; all schema bounds (text lengths, map sizes, claim/metadata limits, hint) unchecked — accepts proofs Rust rejects. |
| F7 | MED | `verify_envelope(.., None, None)` (used by `export`/`import`) shape-checks attestation/status signatures only. Forged attestations import as success. |
| F8 | MED | Two revocation channels share names/semantics: signed `status_objects` (pipeline lifecycle) vs unsigned `RevocationSet` (policy `not_revoked`). Callers pass one believing they passed both. |
| F9 | MED | `init-policy` emits settlement-domain defaults (`SETTLES`/`transaction_record`) for every domain; `requires_grounding` V1-defaults vs `extra_grounded` extension undocumented at the type. |
| F10 | LOW | `supersede.new` never validated (discarded `_new`); authorized signer can point `old → garbage` with misleading lineage. Revoke/withdraw/compromise targets shape-unchecked. |
| F11 | LOW | Public custom-`external_aad` APIs with no domain-separation contract; future misuse cross-accepts foreign-domain signatures. |
| F12 | LOW | `--seed <hex>` in argv with no runtime warning; stack seed never scrubbed; `MemoryStore` hardcodes 1MiB ignoring `Limits`; `is_supported_keyref("key:ed25519:")` passes empty body; `CborValue::Nint(≥0)` silently normalizes to `Uint`. |

## 2. Foundation deficiency (why CORE, not extension/adapters/profiles)

- **F1**: wire-bytes authority contradicts implementation. No adapter can paper over two ids for one proof; the CDDL text itself must match the frozen binding (F2 row already states coverage).
- **F2**: lifecycle freshness semantics live in `REVOCATION`; only the pipeline can distinguish asserted-absence from feed-proved-absence. Extension/policy cannot see the empty feed.
- **F4/F5/F10**: schema-string typing and lifecycle-claim shapes are parse/lifecycle semantics. Adapters see only post-parse structs; the confusion happens before they run.
- **F7**: envelope verification is the import/export trust root. Adapters consume envelopes after this check.
- **F12-core** (keyref/store/cbor): identifier shape and bound agreement are foundation invariants.
- **F3** is the exception and ships as **GENERIC EXTENSION**: a V2-only leaf behind the `policy_version` capability row (precedent: `requires_reference`/`forbids_reference`). V1 parses byte-identically (`v1_rejects_v2_leaf_names_and_stays_frozen` extended).
- **F6/F9-CLI/F11-docs/F8-docs/F12-CLI** touch no frozen behavior (interop/CLI/docs/tests only).

## 3. Change

- **F1** (`docs/format.cddl` only): `proof-binding` gains `created_at` (bound), optional `referenced_proofs`/`vocabularies` (bound when non-empty); `proof.created_at` reworded bound. Zero code bytes change.
- **F2** (`pipeline.rs`, `context.rs`): `VerifyCtx::require_status_feed` (default false) + `VerificationContext` projection; empty feed with asserted freshness forces `UNKNOWN` when set, else emits an explicit ok-note (`empty status feed: ... caller-checked absence, not feed-proved absence`). CLI `--require-status` + stderr warning gated on ACTIVE (UNKNOWN/STALE keep their own hint).
- **F3** (`policy.rs`, `eval.rs`, `state.rs`, `expr.rs` docs, `policy-grammar.ebnf`): V2-only `claim_field {claim_type?, subject?, field, op, value}`; `FieldOp` eq/ne/gt/gte/lt/lte; `FieldValue` text/uint/bool; type-strict (ordering uint-only; text/bool eq/ne; `field:"type"` rejected — use `claim_type`); matches lifecycle-ACTIVE verified claims only; missing field/type mismatch/no-scope-match → FAIL. `ClaimSummary` gains `fields`.
- **F4/F5** (`schema.rs`): `opt_ref_or_nil` enforces `evd:v1:`/`att:v1:` at parse (`SCHEMA_VIOLATION`); `build.rs` + CLI (`attest`/`add-evidence`/`relate`) fail fast with the same rule. Dangling correct-prefix hints keep `Unknown ok:true` semantics (renewal-carried evidence), already gated by `evidence_usable`/`--strict-current` + human-summary notes.
- **F6** (`interop/pengine.py`, `interop/ts/pengine.ts`, `interop/differential.py`, `interop/README.md`): Python bounds parity (text/metadata/claim/hint/typed refs) + wrong-typed-ref NEG both languages (39 checks). TS typed-ref parity (`checkRef`).
- **F7** (`envelope.rs`): attestation/status envelopes crypto-verify self-consistency (signature valid for content issuer) when trust inputs are absent; forged signatures fail `SIGNATURE_INVALID`. CLI `export`/`import` help states import success ≠ trusted.
- **F8** (`eval.rs`, CLI help, `POLICY.md`): `RevocationSet` documented as unsigned caller denylist; `--revoked` help distinguishes denylist from signed feed; separation pinned by test.
- **F9** (`model.rs` docs, CLI `init-policy --proof`): `requires_grounding` documented as frozen V1 defaults + `extra_grounded` extension; `init-policy` infers relationship/evidence kinds from `--proof` (explicit flags win, payment defaults last).
- **F10** (`claim.rs`): revoke target `att:v1:`; supersede old+new `att:v1:`; withdraw shaped artifact id; compromise keyref-or-shaped-or-`did:`. Garbage fails at STATUS (`SCHEMA_VIOLATION`), never silent lineage.
- **F11** (`cose.rs` docs + test): custom-AAD APIs marked ADVANCED adapter-only; pipeline always PE1; cross-AAD non-verification pinned by test.
- **F12** (`keys.rs`, `store.rs`, `cbor.rs`, CLI): `is_supported_keyref` rejects empty bodies; `MemoryStore::with_limits` tracks `Limits` (default stays 1MiB = default limit); `Nint(≥0)` `debug_assert`s (release still normalizes, no panic); `--seed <hex>` warns toward `--seed-file`; CLI stack seed scrubbed via `zeroize`.

## 4. What breaks

| Item | Impact | Action |
|---|---|---|
| Golden vectors (31) | None — no wire bytes change; code already bound `created_at`, builders already emitted correct prefixes | Verified: demo proof id byte-identical (`prf:v1:aKlERqgUZ…`); `validate_cddl.py` green |
| V1 policies | Byte-stable — `claim_field` v2-only, v1 parser rejects the name | `v1_rejects_v2_leaf_names…` extended |
| Proofs with wrong-typed refs / garbage lifecycle targets / empty-body keyrefs / forged envelope sigs | Now rejected (`SCHEMA_VIOLATION` / `SIGNATURE_INVALID`) | Intended fail-closed; previously-accepted malformed inputs were never valid |
| `verify` reports on empty-feed proofs | One additive ok-note; validity unchanged unless `--require-status` | Existing `all-ok`/`any` assertions hold (notes are ok:true); lifecycle test updated to pin the note |
| `MemoryStore` default | Same 1MiB value, now sourced from `Limits::default()` | `with_limits` for tightened deployments |
| `emit_human_summary` signature (CLI-internal) | Adopted in-tree single-RESULT-line `--strict-current` rendering | All callers updated; CLI-only, not frozen |

## 5. Verification

| Gate | Result |
|---|---|
| `cargo build --locked` | green |
| Targeted unit tests (new) | `typed_refs_reject_wrong_prefix`, `memory_store_tracks_limits`, `forged_attestation_envelope_fails_without_trust_inputs`, `custom_aad_never_cross_verifies_with_pe1`, `created_at_restamp…` (pre-existing), `v2_claim_field_uint_predicates`, `v2_claim_field_parse_rejects_bad_shapes`, `require_status_feed_fails_closed_on_empty_feed`, `require_status_feed_passes_with_feed_present`, `denylist_and_signed_lifecycle_are_independent_channels`, CLI `currency_tests` (4) |
| Demo determinism | `prf:v1:aKlERqgUZA…` identical on rebuild |
| Tamper matrix (5 attacks) | all FAIL closed (`ID_MISMATCH`/`DANGLING`/`MALFORMED`/`SCHEMA_VIOLATION`) |
| Lifecycle matrix (expire/revoke/supersede/withdraw/compromise±) | correct, incl. pre/post-compromise split |
| Python verifier on custom + golden-11 proofs | byte-identical `proof_id`; wrong-typed-ref NEG both sides `SCHEMA_VIOLATION` |
| `validate_cddl.py` | 31/31 (re-run at merge; CDDL now matches code) |
| Full `cargo test` + full differential | deferred to CI (local box CPU-throttled: pure-Python ed25519 ≈9s/verify); fast-path gates run locally |
| `freeze-guard` / `trace` / `neutrality` / `no-panic` / `fmt` / `clippy` | re-run at merge (no new PE ids minted; no prod-path unwrap/expect/panic added; `debug_assert!` allowed) |

## 6. Alternatives rejected

| Alternative | Why rejected |
|---|---|
| Open schemas (accept unknown fields) for extensibility | Weakens determinism/interop; versioned schemas + v2 policy rows already carry evolution (EXTENSION-MODEL.md §2) |
| Fail pipeline on dangling `attestation_ref` hints | Breaks renewal-carried evidence (old evidence, new attestation); `evidence_usable` + `--strict-current` already gate currency |
| `require_status_feed` default-true | Breaks fresh-proof UX (empty feed is normal with no revocations); warning + opt-in is the honest balance |
| `claim_field` in V1 | Breaks V1 freeze byte-stability; V2-only preserves it |
| Removing well-known vocab constants from core | API break for zero mechanism gain; constants are data, not branches (neutrality gate exempts `model.rs` tables; mechanism sources take no domain branches) |
| Custom-AAD removal | Adapters legitimately need out-of-band domains; contract + test contains the footgun without removing the tool |

## 11. Maintainer Decision (PENDING)

| | |
|---|---|
| Decision | PENDING — freeze-manifest records added (`uncommitted`: 1× CORE + 1× GENERIC EXTENSION) |
| Rationale | Conformance + honesty fixes on frozen invariants; additive policy capability; pre-V1.0 window |
| Breaking | Intended fail-closed only for previously-malformed inputs; no valid-proof verdict changes except opt-in `--require-status` |
| Compat | None required (pre-V1.0); goldens untouched |
| Pin action | Re-evaluated at merge; targeted tests + CI gates are the record |
