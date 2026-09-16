# Phase 3 Report — Graph (2026-09-06)

## Delivered
- `proof-core`: `Relationship` struct; three new append-only codes
  (`RELATIONSHIP_UNGROUNDED`, `DANGLING_REFERENCE`, `CYCLE_DETECTED`).
- `proof-format`: relationship codec (FORMAT §4.4, self-edges rejected, unknown types rejected).
- `proof-crypto`: `relationship_id` + `make_relationship` / `verify_relationship`
  (same canonical+schema+id discipline as other artifacts).
- `proof-graph` (new crate, depends only on `proof-core`): `validate_graph` over
  pre-verified `EdgeRecord`s — endpoint/ref resolution, grounding for
  OWNS/CREATED/SETTLES/EXECUTED, node/edge limits, SUPERSEDES linearity +
  acyclicity (iterative Kahn's, no recursion on hostile input) + chain depth bound.
- `fixtures/golden-09..10.json` (valid grounded chain, supersedes cycle) + e2e
  `chain.rs` (Company→Account→Payment→Invoice with real builder ids).
- Quality: 64/64 tests, fmt clean, clippy zero warnings, `build --locked` ok.

## Gate (plan §Phase 3): PASS
valid chain ok; 2-cycle → `CYCLE_DETECTED`; dangling endpoint/ref → `DANGLING_REFERENCE`;
bare SETTLES → `RELATIONSHIP_UNGROUNDED`; 300 edges vs `max_edges: 256` → `LIMIT_EXCEEDED`;
branching SUPERSEDES → `SCHEMA_VIOLATION` (linearity); over-long chain → `LIMIT_EXCEEDED`.

## Spec bug found and fixed (hostile-review catch)
FORMAT §3 hashed relationship ids over `{from,type,to,evidence_ref}` only, leaving
`attestation_ref` outside the id binding — an attacker could re-ground an edge to a
different attestation without changing its id. Fixed: id covers the FULL canonical
content. FORMAT.md amended; `id.rs` documents the deviation rationale.

## Explicitly NOT done (later phases)
- Referenced evidence/attestations are checked for *membership* only, not for
  cryptographic validity/freshness — the full pipeline (Phase 4) verifies artifacts
  before graph validation, in that order.
- Non-SUPERSEDES cycles (e.g. mutual REFERENCES) are allowed in V0.1; only the
  supersession subgraph must be acyclic. Depth bound applies to supersedes chains.
- Policy-gated edge requirements (e.g. "policy X demands SETTLES") are Phase 5.
