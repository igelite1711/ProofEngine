# Phase 5 Report — Policy (2026-09-06)

## Delivered
- `proof-policy` (new crate): `parse_policy` (closed JSON validation → `POLICY_INVALID`,
  empty requirements refused, version gate), `evaluate_policy` (implicit AND, pure,
  deterministic), `VerifiedState` (built only from a matching report+proof pair),
  `explain_report` / `explain_outcome` / `explain_full` (pure projections).
- New code `POLICY_INVALID` (syntax never partially evaluated).
- `fixtures/golden-13..14.json` (merchant PASS, strict FAIL on identical evidence).
- Quality: 94/94 tests workspace-wide (15 new: 6 parser + 7 eval + 2 golden),
  fmt clean, clippy zero warnings, `build --locked` ok.

## Gate (plan §Phase 5): PASS
Same proof PASSes `merchant_payment_v1` and FAILs `strict_transparency_v1`
(transparency only) — Evidence≠Policy demonstrated by test, not slogan.
Untrusted-issuer-with-valid-sig FAILs; expired/revoked FAIL their requirements;
broken proofs yield INDETERMINATE (never downgraded to FAIL-as-policy, never PASS).

## Semantics locked
- `not_expired`: `issued_at ≤ now+skew` and (`expires_at` none or `now ≤ expires+skew`).
  Nil expiry passes (no bounded validity to violate); mandatory-expiry policies
  need a future requirement type.
- `not_revoked`: id in caller set → FAIL, else PASS ("no revocation known", NOT
  "fresh" — suppression windows are Phase 6 scope; pipeline reports
  `lifecycle_checked: false` until then).
- `EvalInputs::default` uses clock 0 so time requirements fail until a real clock
  is supplied (fail-closed default).
- INDETERMINATE whenever crypto or evidence validity is not established.

## Hostile review notes
- Policy JSON is data, never code: no expression language, no reference resolution
  beyond closed enums, size-capped by `max_policy_requirements`.
- `state_from_report_and_proof` refuses mismatched pairs (caller error, not verdict).
- Verified-issuer set derives from the report's own passing SIGNATURES records, not
  from re-reading the proof — an unverified attestation can never leak into trust.
