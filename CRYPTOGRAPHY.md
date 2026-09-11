# CRYPTOGRAPHY.md — Suites, Agility, Lifecycle

> **Status:** Normative consolidation (2026-09-10). Sub-reference of
> `PROOF-ENGINE-SPEC.md` §§5–6. Extends `CRYPTO.md` (which remains accurate
> for V1 wire details). Answers §50: how future algorithms are introduced.

---

## 1. What exists (frozen)

* Canonical CBOR subset + re-encode-and-compare (`FORMAT.md` §1).
* Ids `<prefix>:v1:<b64uNoPad(sha256(canonical))>`; `proof_id` binds sorted
  member sets + proposition; `created_at` excluded (informational).
* COSE_Sign1 untagged, protected exactly `{1:alg,4:kid}`, unprotected `{}`,
  payload embedded, `external_aad=h'504531'` ("PE1").
* Registry: `-19 Ed25519 REQUIRED default-on`; `-9 ESP256 OPTIONAL
  default-off`; `-8/-7/-35/-36 DEPRECATED` → `DEPRECATED_ALGORITHM`;
  other → `UNKNOWN_ALGORITHM`. `HashRef {v,alg:0/1,digest}` lengths 32/48.
* Deterministic signatures required (RFC 8032, RFC 6979); randomized scheme
  = MAJOR change. `kid` is a hint; `issuer==keyref` binding enforced.

## 2. How new algorithms enter

1. New COSE number + new `key:<name>:` prefix, closed registry row.
2. Default-off in every verifier; opt-in via `allowed_algs` / context.
3. Hybrid bridging via existing multi-issuer AND (classical + PQ attestations).
4. No auto-re-sign; historical bytes never rewritten.
5. Removal = major version + migration window + dual-verify period.

## 3. Hash migration

Content digests agile (`alg` carried); object ids pinned to SHA-256 under
`:v1:` — migration bumps `:v2:` with dual-verify window (`LONGEVITY.md` §3).
`nint` restricted to `i64`; bignums forbidden.

## 4. Historical vs current (§20)

"Was valid then?" (signature + binding under contemporary registry) vs
"Acceptable now?" (current `allowed_algs`/policy). Implemented:
`AllowedAlgs::allow_deprecated` verifies `-8` via Ed25519 and `-7` via P-256
(with P-256 enabled), labeled historical-only in SIGNATURES records; default
stays fail-closed (`DEPRECATED_ALGORITHM`); `-35`/`-36` have no verifier
support (decodable, never verifiable). History is never rewritten; policy
decides currentness. Pattern: verify once with contemporary-equivalent
context (was-valid-then), once with current context (acceptable-now).

## 5. Implementation pointers

`crates/proof-crypto/src/{alg,cose,hash,id,keys,claim,build}.rs`;
`crates/proof-format/src/cbor.rs`; `fixtures/golden-04/05/21/22/23`;
`interop/pengine.py` (independent Ed25519 + P-256; golden-21/22/23 both
directions, 28-check differential).
