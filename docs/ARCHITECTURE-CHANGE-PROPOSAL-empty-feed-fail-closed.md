# ARCHITECTURE-CHANGE-PROPOSAL: empty-feed fail-closed default (external review HIGH)

> Status: PROPOSAL (not approved). Freeze-reopen procedure §54.
> Source: independent external review, TEST 6 stale-feed hole.
> This document proposes; it changes nothing until a maintainer verdict ( §11 ).

## 1. Requirement

An operator who verifies a proof with a stale or missing revocation feed
must not receive `RESULT VALID` + `currently_acceptable:true` + exit 0 for
a proof whose attestation was in fact revoked, when the revocation object
was simply never supplied. For whom: any caller using bare `verify` as an
acceptability gate (the command name invites exactly that reading).

## 2. Why existing primitives cannot represent it

They can represent it — `--require-status` / `--production` fail closed on
the empty feed, and JSON `currently_acceptable` plus the empty-feed warning
note describe the gap. The failure is a *default*, not a primitive:
identical bytes verify VALID (bare) vs INVALID (strict). Evidence from the
review: revoke at 1700000400, verify at 1700000500 without `--status` →
exit 0, `currently_acceptable:true`, lifecycle ACTIVE. The secure behavior
exists behind an opt-in flag most first-time callers never pass.

## 3. Affected semantics

Frozen F7 (Lifecycle) + F5 (verdict shape) + F4 (verification order):
today, freshness-asserted + zero status objects ⇒ ACTIVE with an honesty
note (V1.1 F2 fix). Proposed: freshness-asserted + zero status objects ⇒
UNKNOWN (fail closed) unless the caller passes an explicit
`--allow-empty-feed` (or equivalent context flag `allow_empty_feed`),
preserving a deliberate caller-asserted-absence path. Old proofs do not
change bytes; their *bare-verify verdict* changes from VALID to INVALID —
this is the breaking part and why it needs a reopen, not a patch.

## 4. Security implications

Removes: stale-feed / missing-revocation acceptance (the review's only
fail-open). Introduces: denial-of-availability risk for offline verifiers
with genuinely no revocations (mitigated by explicit `--allow-empty-feed`
+ `--require-status`/`--production` guidance). No new confusion, replay,
or parser surface: feed validation, STATUS hygiene, and
`status_inputs_valid` are untouched. Fuzz + negative-matrix plan: add
empty-feed-with-freshness vectors to the negative matrix (expect
REVOCATION_UNKNOWN), golden append-only additions, differential checks
unchanged (stages 1–6 unaffected).

## 5. Compatibility implications

Breaking for bare-verify callers relying on empty-feed VALID (including
`crates/proof-cli/tests/cli_e2e.rs` fresh-proof expectation and
`currently_acceptable:true` on empty feed). Migration boundary: new CLI
minor with `--allow-empty-feed` escape hatch; core pipeline flag
(`allow_empty_feed`, default false under proposal) with dual behavior
during one release window (warn-then-fail). Second implementation:
`interop/` stages 1–6 unaffected; differential needs new empty-feed
 lifecycle vectors.

## 6. Migration requirements

Tooling: `quick_proof.sh` / demo / docs gain `--allow-empty-feed` on the
fresh-proof path (no revocations exist yet) or ship a genesis empty-feed
attestation; `status_feed.py` becomes the recommended feed source.
Conversion: none (no wire change). Old proofs: bare-verify verdict may flip
VALID→INVALID where no feed was supplied — that is the intended fix, and
must be announced as such, never silent.

## 7. Alternatives considered

(a) Keep semantics, strengthen messaging only (chosen interim path in this
change: coherent strict RESULT line + existing warnings/notes). Insufficient
because exit 0 + `currently_acceptable:true` remains machine-readable as
acceptable; prose cannot fix a wire-shaped default. (b) Flip only
`currently_acceptable` (CLI-side `is_currently_acceptable`) to false on
empty feed while keeping pipeline VALID. Insufficient alone: splits CLI
from core report and from `proof-api` mirrors, and still leaves exit 0.
Evidence: review §TEST 6 + §TEST 14.

## 8. Extension-based solution attempted

Attempted as CLI/docs-only (this change set): strict-mode message fix,
`--target`/`--successor` aliases, runbook/README boundary notes. Measured
shortfall: all preserve the fail-open default by design (freeze-safe), so
the stale-feed hole persists for bare-verify users. An adapter cannot fix
a core default.

## 9. Independent verification impact

`interop/pengine.py` (stages 1–6 + proof-id) unaffected. New differential
entries: empty-feed-with-freshness lifecycle vectors (Rust side), Python
side documents out-of-scope (lifecycle engine-side by design). Recipe
update: second implementers must treat "no status inputs + freshness
asserted" as UNKNOWN under the proposal.

## 10. Long-term durability impact

A fail-closed empty-feed default, once frozen, aligns the command name
(`verify`) with its safest reading and removes the one default that
rewards inaction (supplying no feed). The explicit-absence escape hatch
(`--allow-empty-feed`) keeps offline/genesis use legal and auditable.
No further reopen expected: feed semantics, STATUS hygiene, and currency
splits are otherwise stable.

## 11. Decision

APPROVED pre-launch (core-audit architect decision): the engine has not
launched, so the breaking default flip ships now rather than behind a
dual-verify window. `require_status_feed` defaults true in `VerifyCtx`,
`VerificationContext`, CLI, and HTTP API; `--no-require-status` /
`no_require_status` is the explicit-absence escape hatch; grandfathered
fixtures/harnesses/demos assert absence explicitly. Companion CLI-only
fixes (strict RESULT line, supersede aliases) and test/doc updates ship in
the same change. No new freeze pin cut here — the freeze manifest records
this ACP at the next pin.
