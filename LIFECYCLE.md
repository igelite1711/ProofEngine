# Proof Engine — Lifecycle and Time (V1 draft — in development)

> Formalizes states, validity/currentness/freshness, clocks, authority, and
> precedence. Pipeline stages TIME + REVOCATION implement this document.

## Three distinct dimensions

| Dimension | Values | Decided by |
|-----------|--------|------------|
| VALIDITY | valid / invalid | signatures + schema + time bounds + revocation |
| CURRENTNESS | active / superseded | signed supersession objects |
| FRESHNESS | known-as-of-T / unknown / stale | caller-supplied `revocations_known_at` vs verifier clock |

A proof can be VALID but not CURRENT (superseded history), or VALID but not
FRESH (unknown revocation state → evidence invalid, fail closed).

## Lifecycle states (per signature-verified statement attestation)

| Status | Code | Evidence | Meaning |
|--------|------|----------|---------|
| ACTIVE | — | valid | timely, unrevoked, fresh info |
| EXPIRED | `EXPIRED` | invalid | outside `[issued_at, expires_at]` ± skew (or no clock) |
| REVOKED | `REVOKED` | invalid | covered by a valid signed revocation |
| SUPERSEDED | — (historical note) | valid | a valid signed supersession points onward; history preserved |
| COMPROMISED | `COMPROMISED` | invalid | issued at/after a valid signed compromise instant for its issuer; tainted, history NOT preserved (unlike revocation) |
| UNKNOWN | `REVOCATION_UNKNOWN` | invalid | no/stale revocation info |

Precedence per attestation: `COMPROMISED > REVOKED > SUPERSEDED > EXPIRED >
UNKNOWN > ACTIVE`. Status objects targeting ids outside the proof are still
signature-verified and echoed, but have no lifecycle impact here.

## Evidence status (per evidence item, derived)

| Status | Code | Validity | Meaning |
|--------|------|----------|---------|
| AVAILABLE | — | valid | digest-bound, present, no adverse signal |
| WITHDRAWN | `WITHDRAWN` | invalid | covered by a valid signed withdrawal; history preserved |
| COMPROMISED | `COMPROMISED` | invalid | tainted via compromise (direct marking or compromised backing) |
| REVOKED | `REVOKED` | invalid | backing attestation revoked |
| SUPERSEDED | — | valid | backing attestation superseded; history preserved |
| EXPIRED | `EXPIRED` | valid* | backing attestation expired (*ok record carrying the code, attestation convention) |
| UNKNOWN | `REVOCATION_UNKNOWN` | invalid, except backing-absent (see below) | backing state unestablished and relied upon |
| UNAVAILABLE | — | n/a | referenced content not supplied (adapter/bundle layer reports this) |

Backing absent (dangling `attestation_ref`, or renewal carrying old evidence
forward without its attestation) is recorded UNKNOWN with validity preserved:
`attestation_ref` is a provenance hint, never a validity input — fail on
disproof, note on absence. Strict callers adjudicate via
`evidence_usable` (policy v2, AVAILABLE-only).

## Clock rules

- Explicit `verified_at` (+ `skew_leeway`, default 300 s, symmetric on both
  bounds, saturating arithmetic). `verified_at == 0` is the fail-closed
  "no trustworthy clock" sentinel → every attestation EXPIRED.
- `issued_at > now + skew` → not yet valid → `EXPIRED`.
- `expires_at == None` → unbounded (no violation possible). Policies needing
  mandatory expiry have no dedicated requirement type (use `proof_fresh` for proof-age bounds plus caller-supplied clocks; documented boundary).
- Status objects use the same clock: `issued_at > now + skew` (future-dated)
  never applies. A status object's own `expires_at` is not consulted for
  applicability (documented limitation).

## Authority and freshness rules

- Applies only if: well-formed claim AND authority for the kind AND not
  future-dated. Else `UNAUTHORIZED_STATUS` / `EXPIRED` / `SCHEMA_VIOLATION`,
  never applied. Authority per kind: revoke/supersede — signer == target's
  original issuer OR ∈ `revocation_authorities`; withdraw — authorities, or
  target attestation's issuer, or bound-attestation issuer for evidence
  (events/relationships need explicit authority); compromise — target
  identity itself (self-report) or authorities.
- Freshness: `revocations_known_at` missing, or
  `verified_at - revocations_known_at > skew` → non-revoked/superseded/
  unexpired attestations become UNKNOWN (fail closed, never hidden).

## Currency for policy (Gate F supersession rule)

- Supersession never erases historical validity: `historical_validity =
  VALID`, `currentness = SUPERSEDED` (evidence stays valid).
- `VerifiedState.superseded_ids` exposes the pipeline lifecycle to policy.
- `not_superseded` fails when any relied-upon attestation is superseded.
  Without it, PASS means "valid", not "current" (POLICY.md).

Traceability: PE-LIFE-001..006, PE-POLICY-006
(`docs/requirements-matrix.md`).
