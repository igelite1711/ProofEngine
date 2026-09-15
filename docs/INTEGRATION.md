# Integration Guide — embedding Proof Engine in your system

> How to call the engine from code, shell, or HTTP, and which operator
> duties come with each surface. Protocol rules live in the spec docs;
> this is the wiring guide. Start with the 5-minute path in the README,
> then come here to productionize it.

## 1. Pick your surface

| Surface | Best for | Verdict source | Strictness |
|---|---|---|---|
| Rust: `verify_and_evaluate` | Services already in Rust | Typed `VerifiedDecision` | Caller-supplied `VerificationContext` (set `require_status_feed` / `require_acyclic_provenance` for production) |
| CLI: `verify` / `evaluate` | Shell pipelines, CI jobs, cron operators | JSON reports + exit codes | `--production` (implies full-DAG + feed gate + currency overlay) |
| HTTP: `POST /v1/verify|evaluate|explain` | Polyglot services | JSON bodies | `production: true` (same implications) |
| Python/TS verifiers (`interop/`) | Forgery detection without the Rust toolchain | Binding-level checks only | Cryptographic interop, not verdicts — pair with `tools/conformance.py` for verdict agreement |

## 2. Rust: one call, paired inputs

The classic integration foot-gun is running policy on the wrong report
(mismatched proof, divergent clock or trust list). Use the one-shot helper
so the pairing is impossible:

```rust
use proof_core::model::EvidenceStatus;
use proof_core::LifecycleStatus;
use proof_policy::{verify_and_evaluate, RevocationSet};
use proof_verify::VerificationContext;

let mut ctx = VerificationContext::default();
ctx.verified_at = 1_700_000_300;              // your trustworthy clock; 0 fails closed
ctx.revocations_known_at = Some(1_700_000_300); // when your status feed synced
ctx.trusted_issuers = vec![issuer_keyref.clone()];
// Production: fail closed on empty feeds and full-graph cycles.
ctx.require_status_feed = true;
ctx.require_acyclic_provenance = true;

let policy = proof_policy::parse_policy(&your_rules_json, &limits)?;
let d = verify_and_evaluate(&proof_bytes, &ctx, &policy, RevocationSet::empty())?;
// History ≠ currency: SUPERSEDED history and unverified provenance hints stay
// VALID by design — gate acceptance explicitly (the CLI/API expose this as
// `currently_acceptable`; `--production` enforces it via exit code):
let current = d.report.lifecycle.iter().all(|l| {
    l.status != LifecycleStatus::Superseded
}) && !d.report.evidence_status.iter().any(|e| {
    e.status == EvidenceStatus::Superseded
        || (e.status == EvidenceStatus::Unknown
            && e.message.contains("provenance hint unverified"))
});

Notes:

- `VerificationContext` is the single normative shape; `VerifyCtx` and
  `EvalInputs` are thin projections, so pipeline and policy can never
  diverge on clock, trust list, or bounds (AUDIT F6).
- `RevocationSet` is the *unsigned* caller denylist (sanctions, incident
  response) — it is NOT the signed lifecycle feed (`status_objects` in the
  context). Supply both: signed feed for authenticated lifecycle, denylist
  for operator overrides.
- `verify_and_evaluate` enforces `max_trusted_issuers` / status bounds for
  you; direct `evaluate_policy` callers enforce them (DoS prevention).
- Prefer `not_superseded` / v2 `evidence_usable` / `no_conflicting_evidence`
  inside policy for portable currency; the `current` snippet above is the
  operator-side equivalent.

## 3. Shell: the production invocation

```sh
# Verify (transcript to file, human summary on stderr):
proof-cli verify --proof proof.json --clock "$NOW" \
  --revocations-known-at "$FEED_TS" --status feed/*.json \
  --authority "$REVOCATION_AUTHORITY" --production --out report.json
# Decide (prose by default; --json for one merged machine document):
proof-cli evaluate --proof proof.json --policy policy.json --clock "$NOW" \
  --revocations-known-at "$FEED_TS" --status feed/*.json \
  --trusted "$ISSUER" --production
# Replay-sensitive actions add the guardrail (see §5):
proof-cli evaluate --proof proof.json --policy policy.json --clock "$NOW" \
  --revocations-known-at "$FEED_TS" --trusted "$ISSUER" --production \
  --seen-store ops/seen.json --seen-context "tx:$TX_ID" --seen-record
```

Machine contracts: `verify` stdout is always the JSON report (parse it on
exit 1 too); `evaluate` prose prints decision lines only (`--json` for the
merged `{policy_outcome, report}` document); exit 0 = PASS, 1 =
FAIL/INDETERMINATE/not-current/replay, 2 = usage/engine error. Never treat
bare `VALID` as trustworthy without `currently_acceptable` (or `--production`, which enforces it via exit code). Bare-verify VALID on SUPERSEDED history prints human `HISTORICALLY_VALID` (exit 0, JSON `currently_acceptable:false`); unknown JSON wrapper fields are transport errors (exit 2, names the field).

## 4. Feeds, rotation, replay, blobs, keys, PII

- **Status feeds** (`--status` + `--authority` + `--revocations-known-at`):
  poll your issuers' status endpoints into `ops/status/`, validate with
  `python3 tools/status_feed.py --dir ops/status --clock $NOW` (emits the
  CLI fragment), alert on `status_inputs_valid:false` (broken feed, not a
  revoked proof). Empty feed + asserted freshness means caller-asserted
  absence — `--production` fails it closed.
- **Trust rotation**: pin `--trusted` roots; express delegation with v2
  `delegated_authority` and aliases with `identity_bound`; prune retired
  keys per evaluation time with `tools/trust_prune.py` against
  `examples/trust/registry.example.json` (a retired key left listed stays
  powerful — pruning IS the contract).
- **Replay**: bind each business action to a context (nonce/tx/challenge in
  claim fields or metadata), then either pass `--seen-store`/
  `--seen-record` (CLI guardrail, single-writer store, same file shape as
  `tools/seen_set.py`) or run the script around other surfaces. Same proof
  + same context twice is a replay; same proof + new context is not.
- **Content store**: evidence is digest-only — operate the blob store your
  policies rely on; `evidence_present` checks the digest record,
  `evidence_usable` (v2) checks AVAILABLE status. Opt into claim
  `evidence_digest` binding for values that must match bytes.
- **Keys**: `--seed-file`, never `--seed` (argv is visible); HSM/KMS-backed
  signers in production; keyrefs are public identifiers.
- **PII**: claims, subjects, and metadata are plaintext hashed into ids —
  attest coarse predicates (`cohort:eligible=true`), keep fine-grained facts
  behind the gated store (see `docs/CONFIDENTIALITY.md`).

## 5. Conformance for second implementations

`make conformance` replays every golden proof/policy vector (bytes +
embedded context) and compares recorded verdict triples, failure codes, and
policy decisions — 22 checks green at last cut. Mirror
`tools/conformance.py` (stdlib-only) against your engine: same fixtures,
same context mapping, same comparison rules (extra report fields ignored).
Binding-level agreement stays covered by `make interop`. See
`INTEROPERABILITY.md` ("Verdict-reproduction recipe").

## 6. Adoption checklist

Clock (never wall-read by the engine) · trust list pinned + pruned ·
status feed synced + freshness within skew · `--production` (or explicit
gates) · replay store + bound contexts · content store operated · keys in
KMS · PII out of claims · reports archived with proof bytes + inputs
(reports are unsigned transcripts — re-execution is the audit trail).
