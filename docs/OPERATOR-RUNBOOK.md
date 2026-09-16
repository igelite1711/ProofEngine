# Operator Runbook — Proof Engine V1.1

> How to run verification honestly in production. Normative rules live in
> `FORMAT.md` / `SPEC.md` / `POLICY.md`; this is the operational checklist.
>
> **Start here: `--production`.** `verify/evaluate --production` is the strict
> operator profile: implies `--require-acyclic` (full-DAG) + `--require-status`
> (empty feed fails closed) + `--strict-current` currency (SUPERSEDED history
> or unverified provenance hints fail). Bare `verify` VALID means *historically
> valid* — check `currently_acceptable` in JSON or use `--production` for
> verify==acceptable. `--no-require-status` opts back out of the feed gate only.

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
- **Empty feed fails closed (pre-launch core audit):** freshness WITH zero
  status objects and no explicit opt-out → lifecycle UNKNOWN →
  evidence INVALID (`REVOCATION_UNKNOWN`), exit 1. An empty feed proves
  nothing was shown, not that nothing was revoked. Genesis/demo flows with
  genuinely no revocations pass `--no-require-status` (explicit
  caller-asserted absence, recorded with an `explicitly allowed` note).
  `--require-status` is a no-op affirming the default (kept for
  compatibility); `--production` keeps implying the gate alongside
  `--require-acyclic` + `--strict-current`.
- **Historical cutoff (Fix 4):** a status object issued AFTER the verifier
  clock never applies to that verification, even within `--skew`. Skew covers
  honest clock drift for attestation windows (TIME), not future-knowledge
  time-travel. Verifying at clock T with a revocation issued at T+100 stays
  ACTIVE at T (correct history); verify again at T+200 to see REVOKED.
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

## 4b. Replay protection (guardrail + contract)

- The engine is stateless: same bytes re-verify. Replay-sensitive callers MUST
  bind each business action to a context (nonce/tx/challenge in claim fields
  or metadata) and track seen proof ids per context. Two wired options:
  - CLI guardrail (recommended for shell operators): append
    `--seen-store ops/seen.json --seen-context "tx:$TX_ID" --seen-record`
    to `verify`/`evaluate` (omit `--seen-record` for check-only). Replay →
    exit 1; verdict FAIL paths skip the gate; missing/corrupt store with the
    flags present is exit 2 (a requested guardrail that cannot be enforced
    fails closed, never silently passes). Same file shape as the script below.
  - Script (other surfaces / batch jobs):
    `python3 tools/seen_set.py --store ops/seen.json --proof proof.json --context tx:1234 [--record]`
- Scope: single-writer, caller-owned store (back it up; serialize writers or
  shard by context). Same proof + same context twice IS a replay; same proof
  + new context is not.
- Express windows via `issued_at/expires_at` + `proof_fresh` + `not_expired`.
  Re-presenting a valid proof is expected to verify; treating it as new without
  bookkeeping is caller misuse (PROTOCOL.md Gate H).

## 5. Content availability

- Evidence is digest-only: the core never fetches. Operate a content store
  for digests your policies rely on; `evidence_present` checks presence of
  the digest record, `evidence_usable` (v2) checks AVAILABLE status.
- Composition (`compose`) unions members and binds `referenced_proofs`.
  References alone confer nothing — verify members or `resolve` the bundle.

## 6. Provenance profile + currency (M2/M3, Fix 2/3)

- Derivation cycles ALWAYS fail (Fix 2): `PRODUCED/CREATED/EXECUTED/OWNS/
  SETTLES/ISSUED/CONTAINS/SUPERSEDES/REVOKES/CONTRADICTS` cycling fails with
  `CYCLE_DETECTED` even without flags. `REFERENCES` cycles stay linkage-valid
  (citations/see-also); `EQUIVALENT` identity assertions are excluded from
  cycle checks. `--require-acyclic`/`--production` additionally rejects
  `REFERENCES` cycles for full-DAG assurance.
- `SUPERSEDES` must always be linear/acyclic.
- Opt-in semantic binding (Fix 5): attestation claim field
  `evidence_digest: <64|96 hex>` with `evidence_ref` cryptographically ties
  the attested value to the dataset digest (mismatch/missing/malformed fails
  EVIDENCE closed). Absent field = no check (backward compatible). Use for
  values that must match bytes (e.g. `value=23` + dataset digest); prefer
  `--payload-file` + `evidence_digest` over manual hex plumbing.
- Trust-relevant edges fail fast at creation (Fix 8): `relate` rejects
  ungrounded `OWNS/CREATED/SETTLES/EXECUTED/EQUIVALENT/CONTRADICTS` without
  `--evidence-ref`/`--attestation-ref` (use `--allow-ungrounded` only for
  intentional negative-test vectors).
- Currency: bare `verify VALID` means historically valid (JSON
  `currently_acceptable:false` when SUPERSEDED history or unverified
  provenance hints present; human `HISTORICALLY_VALID (...)` label -- never bare `VALID`). Dangling
  `attestation_ref` hints preserve validity with provenance unverified (fail
  on disproof, note on absence). For verify==acceptable, use
  `verify --production` (implies `--strict-current`) or `evaluate` with
  `not_superseded` / v2 `evidence_usable` / `no_conflicting_evidence`.

## 7. Exit codes and triage (M1 contract, Fix 6)

- `verify`: 0 = crypto valid AND evidence valid AND (if `--strict-current`/`--production`) currently acceptable (+ JSON `currently_acceptable` for automation); 1 = verdict FAIL/INDETERMINATE/not-current WITH JSON report on stdout; 2 = usage/engine error only (missing file, bad JSON, missing `cbor`, bad hex, unknown wrapper field -- no bytes to verify).
- Malformed CBOR/trailing/truncated/CBOR-unknown-field/envelope-mismatch now emit JSON FAIL (exit 1), not prose-only exit 2. Unknown *wrapper* fields (extra JSON keys outside `cbor`, e.g. `evil`, `proof_id`) are transport errors (exit 2, names the field) -- never a verdict. Automation MUST parse stdout JSON on exit 1 and check `currently_acceptable` before treating VALID as trustworthy.
- `evaluate`: 0 = policy PASS; 1 = FAIL/INDETERMINATE; 2 = usage/engine. Prose (default) prints decision prose ONLY on stdout (no report JSON; use `--out`/`--json` for it); `--json` prints one merged `{policy_outcome, report}` document (authoritative decision is `policy_outcome.decision`, never `report.policy_decision` which stays indeterminate by design).
- Triage order: `PARSE/SCHEMA/CANONICAL` (bytes) → `IDENTIFIERS/SIGNATURES/KEYS`
  (crypto) → `TIME/REVOCATION` (currency) → `EVIDENCE/RELATIONSHIPS/GRAPH`
  (support) → `STATUS` (feed) → `POLICY` (decision).

## 8. Verification transcripts (application pattern)

- The JSON report on stdout is the verification transcript: proof id,
  per-stage checks, lifecycle/evidence/conflict records, `status_inputs_valid`,
  and failure codes. It is **unsigned and verifier-owned** — it proves nothing
  by itself. Anyone re-runs `verify` over the same proof bytes + same context
  and must reproduce the same report byte-for-byte (determinism); that
  re-execution IS the audit trail. Archive (proof bytes, context inputs,
  report) together; never accept a bare report without its proof.
- Evidence blobs stay outside the core (digest-only). Content-type/size
  conventions belong to domain profiles: use `kind` (open vocabulary, e.g.
  `license.pdf`), `hint` (human note, ≤256 B), and claim/metadata fields for
  MIME/size, with the digest as the binding. The core never fetches.
