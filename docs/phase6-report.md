# Phase 6 Report — Lifecycle (2026-09-07)

## Delivered
- Pipeline stages 7 (TIME) and 8 (REVOCATION/SUPERSESSION) in `proof-verify`:
  explicit clock + skew (`clock_skew_leeway`, applied to both validity bounds),
  signed revoke/supersede status objects, and the state machine
  `ACTIVE|EXPIRED|REVOKED|SUPERSEDED|UNKNOWN` per attestation, exposed as
  `VerifyReport.lifecycle` records plus the `lifecycle_checked` flag.
- `proof-crypto`: `revoke_attestation` / `supersede_attestation` builders,
  `verify_status_object` (signature-verified end-to-end, kid-bound issuer),
  `to_signed_status` wrapper.
- `VerifyCtx` extensions: `status_objects` (caller-supplied signed status, the
  "verifier-supplied revocation set"), `revocation_authorities` (keys empowered
  over any target), `revocations_known_at` (freshness of revocation info).
- New codes: `EXPIRED`, `REVOKED`, `REVOCATION_UNKNOWN`, `UNAUTHORIZED_STATUS`.
- Fixtures `golden-15..18.json` (expired / revoked / superseded / unknown),
  self-checked by `crates/proof-verify/examples/gen_lifecycle_vectors.rs`, and
  re-verified on clean checkout by `golden_proof.rs::golden_lifecycle_vectors_verify_as_recorded`
  (acceptance A3 pattern).
- Quality: 117/117 tests workspace-wide (12-test lifecycle suite including a
  skew-window regression, 2 new policy-interaction tests, golden harness
  extended), fmt clean, clippy zero warnings, `build --locked` ok.

## Gate (plan §Phase 6): PASS
Expired → evidence invalid with `EXPIRED`; revoked → `REVOKED` (embedded and
caller-supplied status objects both enforced); superseded old → `SUPERSEDED`
with evidence validity preserved (historical note kept, never deleted);
missing or stale revocation information → `UNKNOWN` → fail closed, never PASS.
Unauthorized status signer → `UNAUTHORIZED_STATUS` and the effect never applies.

## Semantics locked
- `TIME`: `issued_at ≤ now+skew` and (`expires_at` none or `now ≤ expires+skew`).
  `verified_at = 0` is the fail-closed "no trustworthy clock" sentinel → every
  attestation EXPIRED. Nil expiry is unbounded (no `not_expired` violation).
- Status effects apply only when the claim is well-formed, the signer has
  authority over the target (the target's original issuer, or a key in
  `revocation_authorities`), and the status object itself is not future-dated
  (`issued_at ≤ now+skew`). Failed-authority / future-dated objects are
  reported as failures but never change any target's state.
- Status precedence per attestation: `REVOKED` > `SUPERSEDED` > `EXPIRED` >
  `UNKNOWN` > `ACTIVE`. `SUPERSEDED` alone keeps evidence valid.
- Freshness: `revocations_known_at` missing or older than `verified_at+skew`
  → lifecycle `UNKNOWN` → evidence invalid. Suppression windows are surfaced,
  never hidden ("no revocation known as of T", not "fresh"); a future
  transparency adapter anchors freshness (plan §4 ambiguity #4).
- Status objects targeting ids outside this proof: only an explicit authority
  may present them, and they have no lifecycle impact here; they are still
  signature-verified and echoed in `report.status_objects`.
- Policy interplay: pipeline-established `EXPIRED`/`REVOKED`/`UNKNOWN` flip
  `evidence_validity` to invalid, so policy can only be INDETERMINATE — never
  PASS. The policy layer keeps `not_expired`/`not_revoked` as defense in depth:
  a caller evaluating with a divergent clock FAILs rather than upgrading.

## Hostile review notes
- Unsigned id lists are never trusted: every revocation/supersession is a
  signed COSE object whose signer is bound to the key (`kid`), verified like
  any attestation before its claim is even read.
- A valid signature alone confers nothing — authority is per-target and
  explicit (original issuer or configured `revocation_authorities`).
- Skew is symmetric and documented: it widens both validity bounds and the
  status-object timeliness bound; vector-15 records this (expiry honored only
  past `expires_at + skew`) — the generator self-check caught the first
  attempt that ignored the window and the fixture clock was corrected.
- The verification basis is echoed in the report: the REVOCATION note records
  how many status objects were seen and as of when revocation info was known,
  so a consumer can audit which trust inputs produced the verdict.

## Files touched
`crates/proof-verify/src/{pipeline,report,lib}.rs`, `crates/proof-core/src/{error,model}.rs`,
`crates/proof-crypto/src/{build,claim}.rs`, `crates/proof-policy/tests/{policy,golden_policy}.rs`,
`crates/proof-verify/tests/{lifecycle,golden_proof}.rs`,
`crates/proof-verify/examples/gen_lifecycle_vectors.rs`, `fixtures/golden-15..18.json`.
