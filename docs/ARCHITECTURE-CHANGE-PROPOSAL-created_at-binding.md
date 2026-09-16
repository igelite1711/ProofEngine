# Architecture Change Proposal: `created_at` Binding in `proof_id`

**Classification: CORE DEVIATION (breaking, pre-V1.0 wire fix) — §11 PENDING**

| | |
|---|---|
| Proposal | Bind the proof's `created_at` timestamp into `proof_id` |
| Layer | `proof-crypto` (foundation): `proof_id` preimage + `ProofFresh` evaluation |
| Trigger | External review (2026-09-12), finding F2: "proof freshness without binding" |
| Status | Implemented; merge requires maintainer decision (ARCHITECTURE-FREEZE.md §6) |

## 1. Problem

`proof_id` currently preimages `[spec, verifier, holder, nonce, expires_at]`.
The creation timestamp lives only in the envelope, evaluated by `proof_fresh`
at verification time. A holder can re-stamp `created_at` on an expired-but-
otherwise-valid proof and obtain fresh readability — the id is stable, so the
envelope change is invisible to any resolution keyed on it.

## 2. Foundation deficiency (why not extension/adapters/profiles)

The binding is the semantic foundation: any fix outside it requires every
resolver, adapter and profile to agree on a side-channel timestamp contract —
precisely the coordination §3 extensions cannot impose. The id itself must
cover the timestamp:

- **F2 re-worded (§2 F2)**: `proof_id` preimage gains `"created_at"`;
- **F3 re-worded (§2 F3)**: `proof_fresh` compares against the bound value;
  re-stamping changes the id, so stale bindings resolve to nothing.

## 3. Change

```text
proof_id preimage: [spec, verifier, holder, nonce, created_at, expires_at]
                                             ^^^^^^^^^^ new
```

Byte-level: `created_at` (CBOR `uint`, epoch seconds) appended before
`expires_at` in the canonical preimage. Format version unchanged — the value
space is additive and every produced id changes (breaking by design).

## 4. What breaks

| Item | Impact | Action |
|---|---|---|
| Every existing `proof_id` | All change | Goldens regenerated (17 of 31) |
| Restamp-attack test (py + ts) | Flipped to fail-closed | Updated in lockstep |
| Soak test `created_at` exception | Removed | Updated |
| Pre-V1.0 compat layer | None (not yet shipped) | N/A — no wire compat required |

## 5. Verification

| Gate | Result |
|---|---|
| Goldens | 31/31 (17 regenerated) |
| Differentials (py) | 37/37 |
| Differentials (ts) | 33/33 |
| Restamp attack | fail-closed both languages |
| Soak (binding coverage) | fail-closed both languages |

## 6. Alternatives rejected

| Alternative | Why rejected |
|---|---|
| `proof_fresh` only (no id change) | Restamp invisible to id-keyed resolution — F2 remains |
| Nonce-only (holder-supplied) | Holder controls it; no verifier assurance |
| Side-channel timestamp map | Coordination outside foundation; §3 violation |

## 11. Maintainer Decision (PENDING)

| | |
|---|---|
| Decision | PENDING — ARCHITECTURE-FREEZE.md §6 row added |
| Rationale | Foundation-level binding deficiency; unfixable by extension |
| Breaking | Yes — all `proof_id` values change |
| Compat | None required (pre-V1.0) |
| Pin action | Re-evaluated at merge; goldens + differentials are the record |
