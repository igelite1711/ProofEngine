# ARCHITECTURE-CHANGE-PROPOSAL: conformance hardening (fail-closed restoration)

> Commit `176f036` (branch `complete/core-surrounds-docs-usability`).
> Class: CORE (verdicts change on some inputs — see §3).
> **Decision: PENDING maintainer verdict (this §11).** The freeze guard passes
> mechanically once `docs/freeze-manifest.json` names the files; merge still
> requires the explicit maintainer decision per `ARCHITECTURE-FREEZE.md` §5.

## 1. Requirement

The frozen specification already promises fail-closed defaults for every
unknown (`PROOF-ENGINE-SPEC.md` §18.1), typed reference slots, versioned
identifiers, and staged error attribution (`ERROR-MODEL.md`). The
implementation must honor those promises on all inputs — a verifier that
PASSes without a clock, accepts a mistyped backing reference, or silently
downgrades `v=2` to `v=1` bytes is non-conformant with its own frozen spec.

## 2. Why existing primitives cannot represent it

No new primitive is requested. The deficiency is implementation-side: thirteen
frozen-path files each contained at least one path where code diverged from
the documented frozen behavior (enumerated in §3). No extension, adapter, or
profile can fix a pipeline that itself mis-evaluates; the fix must touch the
frozen paths.

## 3. Affected semantics

No §2 foundation element changes meaning. Each item below restores the
documented meaning for inputs where code diverged. Old → new, identical bytes:

| # | File | Old | New (documented behavior restored) |
|---|---|---|---|
| 1 | `proof-policy/src/eval.rs` (`ProofFresh`) | `verified_at=0` → age saturates to 0 → PASS | FAIL "no trustworthy clock" (matches TIME, `NotExpired`, and the `0`-sentinel contract in `context.rs`) |
| 2 | `proof-policy/src/combine.rs` | revocation-set bound checked against `max_trusted_issuers` (32, wrong message) | bound against `max_status_objects` (64); 33–64-entry sets newly accepted, 65+ still rejected |
| 3 | `proof-format/src/bundle.rs` | empty blob always `Malformed` (even `sha256("")` match) | digest equality only; empty-with-correct-digest verifies |
| 4 | `proof-graph/src/lib.rs` | `max_nodes` checked edge endpoints only; direct-API huge `NodeSet` passed | total member ids also bounded |
| 5 | `proof-graph/src/lib.rs` | `evidence_ref`/`attestation_ref` accepted any member id type | must be `evd:v1:` / `att:v1:` respectively (`SCHEMA_VIOLATION` otherwise) |
| 6 | `proof-graph/src/lib.rs` | duplicate edge ids accepted | `SCHEMA_VIOLATION` |
| 7 | `proof-graph/src/lib.rs` | `looks_like_artifact_id` recognized only `:v1:` | any `prefix:vN:` shape treated as member-shaped (fail closed on future versions) |
| 8 | `proof-format/src/schema.rs` | `attestation/evidence/relationship/proposition_to_cbor` hardcoded `v:1` (silent downgrade of `v:2`) | emits actual `v`; decoder rejects `v≠1` with `UNSUPPORTED_VERSION` |
| 9 | `proof-crypto/src/claim.rs` | empty-string lifecycle targets (`""`) accepted | `SCHEMA_VIOLATION` |
| 10 | `proof-crypto/src/id.rs` | `vocabularies` bound in caller order (unsorted callers diverge) | sorted by `ns` inside `proof_id_full` |
| 11 | `proof-crypto/src/envelope.rs` | `sign1` unchecked when trust inputs absent | shape-checked (`parse_sign1`) always; crypto verify still needs trust inputs |
| 12 | `proof-format/src/cbor.rs` | `Nint(≥0)` silently wrapped via `as u64` in release (`debug_assert` only) | normalized to `Uint` (no panic, no wrap) |
| 13 | `proof-format/src/cbor.rs` | `u64→usize` length casts truncate on 32-bit targets | `arg_to_usize` fails closed with `LIMIT_EXCEEDED` |
| 14 | `proof-crypto/src/cose.rs` | unbounded caller `external_aad` hashed into `Sig_structure` | 1 KiB bound (`LIMIT_EXCEEDED`) |
| 15 | `proof-verify/src/pipeline.rs` | key-shape failures (`ALGORITHM_CONFUSION`, `UNKNOWN/DEPRECATED_ALGORITHM`, `UNEXPECTED_HEADER_PARAM`) recorded under `SIGNATURES` | recorded under `KEYS` per `ERROR-MODEL.md` stage column |
| 16 | `proof-verify/src/report.rs` | `provenance` dimension `NOT_APPLICABLE` on early exit (no lifecycle data) | `INDETERMINATE` when `!lifecycle_checked` (matches evidence dimension) |
| 17 | `proof-core/src/limits.rs` | no validation ctor; zero/upward limits constructible | additive `Limits::checked()` (downward-only); existing defaults unchanged |
| 18 | `proof-format/src/bundle.rs` + `store.rs` | unbounded bundle/store ingest | additive `Bundle::validate(limits)`; `MemoryStore::put` 1 MiB transport guard (trait errors stay `String` by seam contract) |

Verdict impact is confined to inputs the frozen spec already declares must
fail (zero-clock, empty/mistyped lifecycle material, version confusion,
unbounded input). Well-formed V1 proofs verify byte-identically: `fixtures/`
untouched, all 31 golden vectors validate, `interop/differential.py` 37/37.

## 4. Security implications

Threats removed: replay-guard bypass (#1), DoS via unbounded AAD/allocations
(#13, #14, #18), type-confusion acceptance (#5), version-downgrade
equivocation (#8), silent integer wrap (#12). No new threats: every change
narrows acceptance; nothing previously rejected is now accepted except #2
(33–64 revocation entries, bounded by the pipeline's own status-object limit)
and #3 (empty content with matching digest — authentication unchanged).
Fuzz: 4/4 targets build; stable seed mirrors added for all four
(`crates/{proof-format,proof-graph,proof-verify}/tests/fuzz_seeds.rs` plus
the existing policy mirror); `soak.rs` 2000-mutant suite green.

## 5. Compatibility implications

No version boundary: `v`, id, policy, alg, and error-code wire strings
unchanged. Golden vectors append-only (none modified). Second
implementations: Python/TS differentials green without changes (37 checks);
the corrected behaviors (zero-clock FAIL, typed refs, version preservation)
are already what a spec-faithful implementer produces. 2126 readability
improved (fewer silent acceptances to misinterpret).

## 6. Migration requirements

No migration: no proof written under frozen semantics changes meaning.
Callers relying on the old non-conformant acceptances (zero-clock PASS,
mistyped refs, empty targets, `v=2`-as-`v=1`) must fix their inputs; those
inputs were never valid under the frozen spec. CLI: new verifier flags are
purely additive (absent flags reproduce old strict defaults).

## 7. Alternatives considered

Do-nothing (leave divergences): rejected — ships a verifier that contradicts
its own spec on attacker-reachable inputs (zero clock, crafted refs).
Per-call-site policy workarounds: rejected — lifecycle emptiness and id
binding live below policy; callers cannot compensate.

## 8. Extension-based solution attempted

Not applicable: extensions compose above verified facts; they cannot repair
facts the pipeline mis-evaluates. Verified by construction — every item is a
pipeline/schema/codec path, none expressible as vocabulary, policy, adapter,
or profile.

## 9. Independent verification impact

None required: `interop/differential.py` (37/37) and the TS differential pass
unchanged; no recipe updates (the corrected behaviors match the spec text
the second implementers already built against).

## 10. Long-term durability impact

Each fix replaces an open-ended acceptance with the closed rule the spec
already stated, reducing future reopen pressure. `Limits::checked()`,
`Bundle::validate()`, and `arg_to_usize` add the missing bound-check seams so
future limits work needs no core edits.

## 11. Decision

PENDING — maintainer verdict, date, and new freeze pin to be recorded here on
merge. Mechanical gate (`tools/check_freeze.py`) passes via the manifest
record naming commit `176f036`; that record is process bookkeeping, not the
decision itself.
