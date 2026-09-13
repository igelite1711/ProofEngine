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

## 2. Revocation freshness (`--revocations-known-at`) + feed helper (M4)

- Omit it → lifecycle UNKNOWN → evidence INVALID (fail closed). This is the
  #1 first-run surprise and it is correct.
- Set it to when your status feed was last synced; must be within `--skew`
  of `--clock`, or freshness itself fails closed.
- Serve status objects via `--status <file>` (repeatable) and authorities via
  `--authority <keyref>` (repeatable). Unsigned id lists are never trusted.
- Helper: `python3 tools/status_feed.py --dir ops/status --clock <u> [--format cli]`
  validates envelopes, suggests `--revocations-known-at`, warns on staleness.
  Feed problems emit STATUS failures (`status_inputs_valid:false`) without flipping
  validity — alert, do not treat as revocation.

## 3. Status feeds and `status_inputs_valid`

- `evidence_validity` reflects the proof + *applied* lifecycle only.
- `status_inputs_valid: false` + `STATUS`-stage failures means "feed broken"
  (malformed / unauthorized / future-dated / bad-signature object), NOT
  "proof revoked". Alert on it; do not treat it as revocation.
- Filter untrusted feeds before verification (or use a `StatusSource`
  adapter). Anyone can hand you a mis-signed object; since V1.1 it cannot
  flip a good proof to INVALID, but it still litters `failure_codes`.

## 4. Trust lists + rotation (M4)

- Valid signature ≠ trusted. `issuer_trusted` requires list membership AND a
  verified attestation. Pin `--trusted` roots; use `delegated_authority`
  (v2) for chains, `identity_bound` for aliases. Delegation traverses ACTIVE
  links only.
- Rotation: V1 lists carry bare keyrefs (no per-key validity in core by design).
  Maintain `examples/trust/registry.example.json` with `valid_from/valid_until`
  per key and prune per evaluation time:
  `python3 tools/trust_prune.py --registry ops/trust.json --at <verified_at> --format cli`
  For historical evaluation, prune at the old instant (supply the historical root).
  A retired key left in the list is as powerful as a current one — pruning IS the contract.
- P-256 (`--esp256`) is opt-in, default off. Historical algs
  (`--historical`) answer "was-valid-then" for forensics; policy still
  decides current trust.

## 4b. Replay protection (M4, caller contract)

- The engine is stateless: same bytes re-verify. Replay-sensitive callers MUST
  keep a seen-set of `proof_id` per binding context (nonce/tx/challenge in claim
  fields or metadata). Reference helper:
  `python3 tools/seen_set.py --store ops/seen.json --proof proof.json --context tx:1234 [--record]`
  Express windows via `issued_at/expires_at` + `proof_fresh` + `not_expired`.
  Re-presenting a valid proof is expected to verify; treating it as new without
  bookkeeping is caller misuse (PROTOCOL.md Gate H).

## 5. Content availability

- Evidence is digest-only: the core never fetches. Operate a content store
  for digests your policies rely on; `evidence_present` checks presence of
  the digest record, `evidence_usable` (v2) checks AVAILABLE status.
- Composition (`compose`) unions members and binds `referenced_proofs`.
  References alone confer nothing — verify members or `resolve` the bundle.

## 6. Provenance profile + currency (M2/M3)

- Default: `REFERENCES` cycles are linkage-valid (citations/see-also).
  `SUPERSEDES` must always be linear/acyclic.
- Derivation chains (`derived-from`, `PRODUCED/CREATED/EXECUTED/OWNS/SETTLES`)
  SHOULD pass `--require-acyclic` (provenance DAG profile) to reject any
  relationship cycle with `CYCLE_DETECTED`. Since V1.1 the CLI warns when
  derivation edges are verified without the flag.
- Currency: bare `verify VALID` means historically valid. `SUPERSEDED` preserves
  history (evidence VALID); dangling `attestation_ref` hints preserve validity
  with provenance unverified. Both emit `note:` warnings. For verify==acceptable,
  use `verify --strict-current` (fails on SUPERSEDED/unverified hints) or
  `evaluate` with `not_superseded` / v2 `evidence_usable` / `no_conflicting_evidence`.

## 7. Exit codes and triage (M1 contract)

- `verify`: 0 = crypto valid AND evidence valid AND (if `--strict-current`) currently acceptable; 1 = verdict FAIL/INDETERMINATE/not-current WITH JSON report on stdout; 2 = usage/engine error only (missing file, bad JSON, missing `cbor`, bad hex — no bytes to verify).
- Malformed CBOR/trailing/truncated/unknown-field/envelope-mismatch now emit JSON FAIL (exit 1), not prose-only exit 2. Automation MUST parse stdout JSON on exit 1.
- `evaluate`: 0 = policy PASS; 1 = FAIL/INDETERMINATE; 2 = usage/engine.
- Triage order: `PARSE/SCHEMA/CANONICAL` (bytes) → `IDENTIFIERS/SIGNATURES/KEYS`
  (crypto) → `TIME/REVOCATION` (currency) → `EVIDENCE/RELATIONSHIPS/GRAPH`
  (support) → `STATUS` (feed) → `POLICY` (decision).
