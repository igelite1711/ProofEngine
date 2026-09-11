# COMPATIBILITY.md — Versioning, Migration, Longevity

> **Status:** Normative consolidation (2026-09-10). Index over `VERSIONING.md`,
> `docs/LONGEVITY.md`, `INTEROPERABILITY.md`, `docs/format.cddl`. Answers §50:
> how historical verification and independent verification are preserved.

---

## 1. Version signals (all fail closed)

| Layer | Signal | On mismatch |
|---|---|---|
| Objects | `v` | `UNSUPPORTED_VERSION` |
| Ids | `:vN:` infix | PARSE reject |
| Policy | `policy_version` | `UNSUPPORTED_VERSION` |
| HashRef | `v` + `alg` enum | `SCHEMA_VIOLATION` / `UNKNOWN_ALGORITHM` |
| Algs | COSE numbers | unknown/deprecated fail |

Unknown versions/fields/algs/states never become PASS. Canonical subset only
shrinks; fixtures append-only; same bytes + same inputs ⇒ same report
byte-for-byte across V1.x.

## 2. Migration rules (§52)

Additive-only semantics; new behavior = versioned capability row. Existing
artifacts never change meaning. Breaking change requires: migration rule +
historical preservation + compat tooling + documented breaking change +
safe conversion utility. Never silently reinterpret old proofs.
`created_at` excluded from `proof_id` by design (informational); policies
must not treat it as authenticated (`proof_fresh` documents this).

## 3. Interop (I2/I3)

Conformant impl MUST: reject the forbidden subset; derive ids exactly;
verify COSE profile; run stages in order; never PASS from pipeline alone;
fail closed on all invariants; agree with Rust on all golden vectors given
equal contexts. `interop/differential.py` checks both directions (37 checks);
vectors `fixtures/golden-01..31` normative with expected triples+codes. Envelope
(`ArtifactEnvelope`) standardizes the ad-hoc CLI `{"kind","id","cbor"}` JSON
so Python/TS/Go exchange files, not just bytes.

## 4. 2126 / no-PE / no-domain tests

A 2126 verifier must determine meaning, claims, evidence, issuers, algs used,
historical validity, current acceptability, external deps, and uncertainty —
from bytes + spec alone, no servers, no authors. Removing domain profiles
must leave a coherent core (no payment/AI/copyright words in core). Removing
Proof Engine servers must not break verification (offline-first, zero fetch).

## 5. Pointers

`VERSIONING.md`; `docs/LONGEVITY.md`; `INTEROPERABILITY.md`;
`docs/capability-map.md`; `docs/requirements-matrix.md`; `MIGRATION-PLAN.md`.
