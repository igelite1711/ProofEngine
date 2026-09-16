# Proof Engine — Standards References (Phase 0, verified 2026-09-06)

> Rule: no crypto number is trusted from memory. This file is the single source of truth for Phase 1 code.
> Fetch method: `webfetch` of `rfc-editor.org` + `iana.org` on 2026-09-06. Snapshots below.

## 1. CBOR deterministic encoding — RFC 8949 (STD 94, obsoletes 7049, Dec 2020)

- **Source**: https://www.rfc-editor.org/rfc/rfc8949.html (verified live, Table of Contents shows §4.1/§4.2.1/§4.2.2/§4.2.3).
- **Normative choice for V0.1**: `§4.1 Preferred Serialization` + `§4.2.1 Core Deterministic Encoding Requirements`.
  - Shortest-form ints, definite lengths, **map keys sorted by bytewise lexicographic order of deterministic encodings**.
  - Confirmed by §4.2.3 text: "core requirements (§4.2.1) sort map keys in a different order from [RFC7049 §3.9 Canonical CBOR]… this document simplifies to lexicographic ordering."
- **CORRECTION to FORMAT.md v1**: it cited "§4.2 (and §5.4 length-first)". Wrong on two counts: (a) §5.4 is "Validity and Evolution", not ordering; (b) length-first (§4.2.3) is legacy RFC7049-compat only. V0.1 MUST use §4.1+§4.2.1 lexicographic, MUST reject length-first-only inputs via re-encode-and-compare (`NON_CANONICAL`).
- Duplicate map keys: RFC 8949 §3.1 major type 5 + §5.6: duplicates are well-formed but **not valid** → V0.1 decoder MUST reject (`DUPLICATE_MAP_KEY`).
- Indefinite lengths (§3.2): forbidden in deterministic encoding → reject (`FORBIDDEN_CBOR_CONSTRUCT`).
- Tags: V0.1 forbids all tags including 0/1/2/3/4/5 on the signing path. Time is `uint` epoch seconds, not tag 1, to avoid int-vs-float ambiguity (RFC 8949 §3.4.2 allows int OR float in tag 1 — unacceptable for deterministic ids).
- Floats: forbidden in V0.1 objects (preferred-serialization float rules exist but add interop risk; no use case needs them).

## 2. COSE structures — RFC 9052 (Aug 2022, obsoletes 8152) + RFC 9360 updates

- **Source**: https://www.rfc-editor.org/rfc/rfc9052.html (verified: "This document, along with RFC 9053, obsoletes RFC 8152").
- **CORRECTION**: FORMAT.md cited "RFC 8152 §4.2". RFC 8152 is obsolete. V0.1 MUST cite:
  - RFC 9052 §4.2 (COSE_Sign1 array `[protected:bstr, unprotected:map, payload:bstr/nil, signature:bstr]`, tag 18),
  - RFC 9052 §4.4 (Sig_structure `["Signature1", body_protected:bstr, external_aad:bstr, payload:bstr]`, encoded per §9 CBOR restrictions),
  - RFC 9052 §3/§3.1 (protected/unprotected buckets, labels 1=alg, 2=crit, 3=content-type, 4=kid, 5=IV, 6=Partial IV),
  - RFC 9052 §9 (CBOR encoding restrictions for ToBeSigned).
- **CRITICAL FIX**: FORMAT.md proposed protected header `{1, 4, 6: "proof-engine/v1"}`. Label **6 is Partial IV** per RFC 9052 §3.1 + IANA registry (verified live). V0.1 MUST NOT use label 6 for anything else. Protected header is exactly `{1: alg:int, 4: kid:bstr}`; domain separation goes in `external_aad = h'504531' ("PE1")`, never in a fake header label. Any other header label → `UNEXPECTED_HEADER_PARAM`.
- `kid` is a hint only (RFC 9052 §3.1: "MUST NOT assume kid values are unique") — verifier MUST try all matching keys / fail closed, never trust `kid` alone.

## 3. COSE algorithms — IANA registry (live 2026-08-25) + RFC 9053 + RFC 9864

- **Sources**: https://www.iana.org/assignments/cose/cose.xhtml (fetched 2026-证明; entries below match live snapshot); RFC 9864 "Fully-Specified Algorithms for JOSE and COSE" (Oct 2025, datatracker verified); draft-ietf-jose-fully-specified-algorithms search excerpts.
- **FINDING — FORMAT.md was outdated**: it specified `EdDSA (-8) REQUIRED, ES256 (-7) OPTIONAL`. Current IANA state:
  - `-8 EdDSA` → **Deprecated** (polymorphic: curve not bound; refs RFC 9053 + RFC 9864),
  - `-7 ES256` → **Deprecated** (polymorphic; refs RFC 9053 + RFC 9864),
  - `-19 Ed25519` (EdDSA with Ed25519, RFC 8032 §5.1) → **Recommended: Yes**,
  - `-9 ESP256` (ECDSA P-256+SHA-256) → **Recommended: Yes**,
  - `-16 SHA-256`, `-43 SHA-384` hash algs → Recommended: Yes,
  - `-35 ES384`, `-36 ES512` → Deprecated (same polymorphic reason).
- **V0.1 DECISION (binding)**:
  - REQUIRED: `-19 Ed25519` (Ed25519 + SHA-512 per RFC 8032; COSE `crv:1/Ed25519`, `kty:OKP(1)`).
  - OPTIONAL (config-gated, default off): `-9 ESP256` (P-256 + SHA-256; `kty:EC2(2)`).
  - `-8`, `-7`, `-35`, `-36` MUST be rejected with `DEPRECATED_ALGORITHM` (fail closed, no downgrade negotiation). Rationale recorded: polymorphic ids break negotiation (WebAuthn precedent: `-8 where crv=6`), per RFC 9864 §4.2.2.
- Key params (RFC 9052 §7.1 + IANA COSE Key Common/Types): `kty:1`, `kid:2`, `alg:3`; OKP: `crv:-1, x:-2, d:-4`; EC2: `crv:-1, x:-2, y:-3, d:-4`. Curves registry: Ed25519=6, P-256=1 (verify at code time against IANA COSE Elliptic Curves page).

## 4. Hashes — FIPS 180-4 + COSE alg ids

- **Source**: NIST FIPS PUB 180-4 (Secure Hash Standard, Aug 2015; verified via csrc.nist.gov listing: SHA-1/224/256/384/512/512-224/512-256).
- V0.1 allows `sha-256` (32B digest) and `sha-384` (48B). SHA-1 forbidden. SHA-3 family deferred (no use case, keep audit surface small).
- Display `hash:v1:sha-256:<lowerhex>`; CBOR enum `0↔sha-256, 1↔sha-384` is engine-local (never wire-compatible with COSE `-16/-43` — mapping table in code must be explicit + tested).

## 5. Base64url ids — RFC 4648 §5

- **Source**: https://www.rfc-editor.org/rfc/rfc4648 (verified §3.2 padding rule + §5 base64url).
- Alphabet `A–Z a–z 0–9 - _`, padding `=` omitted in ids (data length implicit: 32/48B hashes → fixed-length ids). Decoder MUST reject `+`, `/`, whitespace, non-canonical pad bits (`INVALID_BASE64URL`). This matches JWS unpadded convention (RFC 7515) referenced in research.

## 6. Time

- Wire: `uint` seconds since 1970-01-01T00:00Z (POSIX, leap-second handling per POSIX, cf. RFC 8949 §3.4.2 discussion). No RFC 3339 strings on signing path (display only). Fractional seconds forbidden in V0.1. `verified_at` is explicit VerifyCtx input; skew leeway default 300s, logged.

## 7. Phase 0 spec amendments required before Phase 1 code

1. FORMAT.md §1: replace "§4.2 (and §5.4 length-first)" with "RFC 8949 §4.1 + §4.2.1 bytewise-lexicographic; §4.2.3 length-first explicitly NOT accepted".
2. FORMAT.md §5: replace RFC 8152 refs with RFC 9052 §4.2/§4.4/§3.1/§9; header `{1,4}` only; `external_aad=h'504531'`; algs `-19` required / `-9` optional / `-8/-7/-35/-36` → `DEPRECATED_ALGORITHM`; forbid all tags on signing path.
3. ARCHITECTURE.md §3.5: `proof_id` vague text replaced by FORMAT §3 member-set binding (single definition).
4. ARCHITECTURE.md §3.1 vs FORMAT §4.1: unify field name to `effective_at` (drop bare `timestamp`).
5. IMPLEMENTATION_PLAN.md: fix typo "onlyбеж" → "only happening-record"; check Phase 0 boxes.
6. New error codes locked: `DEPRECATED_ALGORITHM`, `DUPLICATE_MAP_KEY`, `UNEXPECTED_HEADER_PARAM`, `INVALID_BASE64URL` (add to error table in Phase 1).

Snapshot date: 2026-09-06. Re-verify IANA pages at Phase 4 (registry moves fast: last update 2026-08-25 observed).
