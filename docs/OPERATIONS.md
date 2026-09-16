# OPERATIONS.md — Normative Adapter Contract (H3 remediation)

> **Status:** NORMATIVE ADAPTER (not core). The neutral core stays stateless;
> this document defines the contract independent adapters MUST meet for
> trust registries, rotation, feeds, replay, and clocks so any two
> implementations interoperate operationally. Checklist form lives in
> `docs/OPERATOR-RUNBOOK.md`; wiring lives in `docs/INTEGRATION.md`.
> On protocol semantics `PROOF-ENGINE-SPEC.md` wins.

Core never holds: trust lists, key validity, feeds, seen-state, wall clock.
Caller supplies all of them per verification (`VerificationContext`).
An adapter that claims conformance MUST implement this section.

## 1. Trust registries (caller-owned, versioned)

- Format: list of `{keyref, valid_from, valid_until, role}` (see
  `examples/trust/registry.example.json`). Bare keyrefs carry no validity
  in core by design; validity lives here.
- Pruning IS the contract: `python3 tools/trust_prune.py --registry ops/trust.json --at <verified_at> --format cli`
  emits `--trusted`/`--authority` for that instant. Historical evaluation
  prunes at the old instant with the historical root. A retired key left in
  the list is as powerful as a current one.
- Rotation: add successor with overlapping window, prune predecessor after
  `valid_until + skew`. Compromise: emit signed `compromise` status AND
  remove from registry; taint is at/after `compromised-at` (history NOT preserved).

## 2. Status feeds (signed only)

- Unsigned id lists are never trusted. Serve signed status objects
  (`revoke`/`supersede`/`withdraw`/`compromise`) via `--status <file>`
  (repeatable) + `--authority <keyref>` (repeatable).
- Freshness: `--revocations-known-at` = feed sync time, MUST be within
  `--skew` of `--clock` or freshness fails closed (`REVOCATION_UNKNOWN`).
  Empty feed fails closed by default; `--no-require-status` asserts
  caller-checked absence (genesis/bootstrap/testing ONLY, warns loudly).
- Hygiene: malformed/unauthorized/future-dated objects emit STATUS failures
  (`status_inputs_valid:false`) without flipping validity. Alert, do not
  treat as revocation. Helper: `python3 tools/status_feed.py --dir ops/status --clock <u>`.
- Historical cutoff: status issued AFTER verifier clock never applies,
  even within skew. Verify at T stays ACTIVE; re-verify at T+delta to see REVOKED.

## 3. Clocks

- CLI never reads wall time. Always pass `--clock <u64>`; `0` = no trustworthy
  clock → every attestation EXPIRED (fail closed). Keep `--skew` small
  (default 300s, drift only). `proof_fresh` bounds self-declared `created_at`
  (bound by `proof_id`; re-stamp → `ID_MISMATCH`) — pair with `not_expired`
  (signed windows) for strong freshness.

## 4. Replay protection (caller contract, PROTOCOL Gate H)

- Engine is stateless: same bytes re-verify. Replay-sensitive callers MUST
  bind each business action to a context (nonce/tx/challenge in claim fields)
  and track seen proof ids per context.
- CLI guardrail: `--seen-store ops/seen.json --seen-context "tx:$ID" --seen-record`
  (check-only without `--seen-record`). Replay → exit 1; FAIL paths skip gate;
  missing/corrupt store with flags = exit 2 (requested guardrail unenforceable
  fails closed). Single-writer file; serialize writers or shard by context.
  Script shape identical: `tools/seen_set.py`. Same proof + same context twice
  IS replay; same proof + new context is not.

## 5. Content availability (H2, storage-neutral)

- Core is digest-only: `DIGEST PRESENT` means proof commits to digest/reference,
  NOT verifier fetched/checked bytes. Core never fetches (`allow_remote` false).
- Adapter contract: content store keyed by digest hex; `evidence_present{kind}`
  checks record presence, `evidence_usable{kind}` (v2) checks AVAILABLE status;
  opt-in `evidence_digest` claim + `evidence_ref` cryptographically ties
  attested values to dataset digests (mismatch fails EVIDENCE closed).
  Equivocation/withholding across contexts needs transparency (V2).

## 6. Adapter conformance checklist

- [ ] Prune trust per evaluation instant; never pass unpruned lists.
- [ ] Supply signed feeds + authorities + freshness; never `--no-require-status` in prod.
- [ ] Pass explicit clock + small skew; never rely on embedded time as truth.
- [ ] Bind business actions to contexts + seen-store on PASS paths.
- [ ] Operate content store for digests policies rely on; use `evidence_digest` where values must match bytes.
- [ ] Alert on `status_inputs_valid:false`; never treat as revocation.
- [ ] Archive (proof bytes, context inputs, JSON report) together; re-execution reproduces report byte-for-byte.
