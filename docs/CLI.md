# CLI.md — Command Surface (remediation H4/§9)

> **Status:** REFERENCE IMPLEMENTATION guide. Protocol semantics unchanged.
> Primary path first; everything else secondary but working. On semantics
> `PROOF-ENGINE-SPEC.md` wins.

## Primary path (new users start here)

```
create-event → attest → add-evidence → relate → build → verify → evaluate → explain
```

- `create-event --payload-file` hashes file bytes (no hex math).
- `attest --seed test|--seed-file` signs a claim (production: `--seed-file` + `--production`).
- `add-evidence --digest-file` binds a digest (digest present ≠ content checked; see OPERATIONS §5).
- `relate --from <id> --type <TYPE> --to <id>` links members (trust-relevant types require grounding).
- `build` assembles members into a proof (`proof_id` binds sorted sets + `created_at`).
- `verify --clock --revocations-known-at [--status --authority | --no-require-status(genesis only)] [--production]`
  answers integrity: VALID (currently acceptable) / HISTORICALLY_VALID (history only) / INVALID.
- `evaluate --policy --trusted` answers claim decision: PASS/FAIL/INDETERMINATE.
- `explain --policy` narrates reasoning (pure projection, never contradicts report).
- Helpers: `init-policy` (infer policy), `id` (plumbing), `inspect` (read-only), `graph` (visualize).

Production MUST use `--production` (verify==acceptable) or check
`currently_acceptable` in JSON; bare VALID means historically valid.
Genesis `--no-require-status` is bootstrap/testing only.

## Full classification (36 verbs; no deletions in remediation)

- CORE (protocol verbs): `create-event`, `attest`, `add-evidence`, `relate`, `build`, `verify`, `evaluate`, `explain`
- ESSENTIAL (lifecycle): `revoke`, `supersede`, `withdraw`, `compromise`
- CONVENIENCE (DX, no semantics): `init-policy`, `id`, `inspect`, `graph`, `commit`, `doctor`, `version`, `completion`, `demo`
- PORTABILITY (envelopes/composition): `export`, `import`, `convert`, `compose`, `resolve`, `batch-verify`, `ingest`
- PERIMETER (0.1.x, not V1 promise): HTTP via `proof-api` crate (loopback reference; V1 core performs zero network I/O)
- EXPERIMENTAL (perimeter crates): `proof-bench` harness flags
- DEBUG: `--verbose` (Layer-2 stages), `--json/--out/--quiet` (machine contract)

`proof-api` HTTP exists as a thin reference perimeter (0.1.x); V1 non-goal
“No HTTP server in core” stands — HTTP never participates in `verify_proof()`.
