# Phase 0 Gate — Spec Baseline (2026-09-06)

## Ambiguities #1–#4 (binding resolutions)
1. Five primitives vs Proposition/Policy/Revocation: 5 persisted only; Proposition=value object, Policy=evaluation input, Revocation/Supersession=signed Attestation subtypes (claim.type revoke/supersede).
2. Event/Claim/Object: Event=only happening-record; Claim=Attestation content struct; Object=by-id reference union. Field name unified to `effective_at`.
3. Grounded edges: trust-relevant types (SETTLES, OWNS, CREATED, EXECUTED) REQUIRE evidence/attestation ref else `RELATIONSHIP_UNGROUNDED`; others logged.
4. Revocation vs offline: signed revocation objects + caller-supplied set; stale/missing → `UNKNOWN` → fail closed (`REVOCATION_UNKNOWN`). Transparency adapter deferred.

## Consistency fixes applied
- FORMAT §1: lexicographic (§4.1+§4.2.1), length-first rejected; §5: RFC 9052 refs, header {1,4} only, external_aad=h'503531', algs -19/-9, -8/-7 → DEPRECATED_ALGORITHM; tags forbidden.
- ARCH §3.1/§3.5/§4-stage-5 aligned to FORMAT single definitions.
- PLAN typo fixed; Phase 0 boxes checked.

## Second-verifier check (gate question)
"Could an independent engineer implement a second verifier from docs?" — YES for V0.1 scope: FORMAT.md + docs/standards-refs.md + fixtures-shape (§8) fully determine canonical bytes → id → Sig_structure → verify with -19. Remaining risk: CBOR library preferred-serialization edge cases → mitigated by re-encode-and-compare + golden vectors in Phase 1.

## Decision
Phase 0 COMPLETE. No code written. Approved to start Phase 1 (foundation) with locked choices: CBOR lexicographic, COSE_Sign1/-19 required/-9 optional, SHA-256/384, b64u-no-pad ids, uint epoch time.

## Withheld (fail-closed until resolved)
- P-256 key serialization exact bytes (confirm 32B X + 32B Y at Phase 1 code time vs IANA curves page).
- COSE `crit` handling for future custom labels (none in V0.1 — any custom label rejected).
