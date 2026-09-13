# Operator Runbook — Proof Engine V1.1

> How to run verification honestly in production. Normative rules live in
> `FORMAT.md` / `SPEC.md` / `POLICY.md`; this is the operational checklist.

## 1. Clocks

- Always pass `--clock <u64>` (CLI never reads wall time). `verified_at == 0`
  means "no trustworthy clock" → every attestation EXPIRED (fail closed).
- Keep `--skew` small (default 300s). Skew covers drift, not travel.
- `proof_fresh{max_age}` bounds self-declared `created_at` (bound by
  `proof_id` since the V1.1 wire fix — re-stamps fail `ID_MISMATCH`) against
  your clock. Pair with `not_expired` (signed windows) for strong freshness.

## 2. Revocation freshness (`--revocations-known-at`)

- Omit it → lifecycle UNKNOWN → evidence INVALID (fail closed). This is the
  #1 first-run surprise and it is correct.
- Set it to when your status feed was last synced; must be within `--skew`
  of `--clock`, or freshness itself fails closed.
- Serve status objects via `--status <file>` (repeatable) and authorities via
  `--authority <keyref>` (repeatable). Unsigned id lists are never trusted.

## 3. Status feeds and `status_inputs_valid`

- `evidence_validity` reflects the proof + *applied* lifecycle only.
- `status_inputs_valid: false` + `STATUS`-stage failures means "feed broken"
  (malformed / unauthorized / future-dated / bad-signature object), NOT
  "proof revoked". Alert on it; do not treat it as revocation.
- Filter untrusted feeds before verification (or use a `StatusSource`
  adapter). Anyone can hand you a mis-signed object; since V1.1 it cannot
  flip a good proof to INVALID, but it still litters `failure_codes`.

## 4. Trust lists

- Valid signature ≠ trusted. `issuer_trusted` requires list membership AND a
  verified attestation. Pin `--trusted` roots; use `delegated_authority`
  (v2) for chains, `identity_bound` for aliases. Delegation traverses ACTIVE
  links only.
- P-256 (`--esp256`) is opt-in, default off. Historical algs
  (`--historical`) answer "was-valid-then" for forensics; policy still
  decides current trust.

## 5. Content availability

- Evidence is digest-only: the core never fetches. Operate a content store
  for digests your policies rely on; `evidence_present` checks presence of
  the digest record, `evidence_usable` (v2) checks AVAILABLE status.
- Composition (`compose`) unions members and binds `referenced_proofs`.
  References alone confer nothing — verify members or `resolve` the bundle.

## 6. Provenance profile

- Default: `REFERENCES` cycles are linkage-valid (citations/see-also).
  `SUPERSEDES` must always be linear/acyclic.
- Derivation chains (`derived-from`) SHOULD pass `--require-acyclic`
  (provenance DAG profile) to reject any relationship cycle with
  `CYCLE_DETECTED`.

## 7. Exit codes and triage

- `verify`: 0 = crypto valid AND evidence valid; 1 = verdict; 2 = usage/engine.
- `evaluate`: 0 = policy PASS; 1 = FAIL/INDETERMINATE; 2 = usage/engine.
- Triage order: `PARSE/SCHEMA/CANONICAL` (bytes) → `IDENTIFIERS/SIGNATURES/KEYS`
  (crypto) → `TIME/REVOCATION` (currency) → `EVIDENCE/RELATIONSHIPS/GRAPH`
  (support) → `STATUS` (feed) → `POLICY` (decision).
