# Proof Engine — Cryptography (V1 draft — in development)

> No custom cryptography. Primitives: SHA-256/384 (FIPS 180-4) via `sha2`,
> Ed25519 (RFC 8032) via `ed25519-dalek`, P-256/ECDSA via `p256`.
> Standards anchors: `docs/standards-refs.md`.

## Algorithms

| COSE alg | Meaning | Status |
|----------|---------|--------|
| -19 | Ed25519 | REQUIRED, default-on |
| -9 | ESP256 (P-256) | OPTIONAL, default-off (`AllowedAlgs::strict`) |
| -8, -7, -35, -36 | EdDSA/ES256/ES384/ES512 (deprecated) | rejected `DEPRECATED_ALGORITHM` |

Unknown alg → `UNKNOWN_ALGORITHM`. `kid` length must match the alg's key
shape (32 B for -19, 64 B `X\|\|Y` for -9) else `ALGORITHM_CONFUSION`.

## COSE_Sign1 profile (RFC 9052 §4.2)

- Untagged outer array (tag 18 MUST NOT be used; all tags rejected).
- Protected header exactly `{1: alg:int, 4: kid:bstr}` (raw pubkey bytes).
  Any other label (including 6/Partial-IV) → `UNEXPECTED_HEADER_PARAM`.
- Unprotected header MUST be the empty map.
- Embedded payload only (detached `nil` rejected); payload is the canonical
  `AttestationContent` bytes; outer and protected header MUST be canonical
  (re-encode-and-compare).
- `Sig_structure = ["Signature1", body_protected, external_aad, payload]`
  per RFC 9052 §4.4, encoded per §9, with `external_aad = h'504531'`
  ("PE1").

## Key binding (trust never comes from `kid` alone)

1. `kid` is a hint: expected issuer is derived from it.
2. The key must parse as the header alg's shape; mismatch → fail.
3. The signature must verify over the exact `Sig_structure`.
4. The payload `issuer` MUST equal the verifying key's KeyRef
   (`attest` refuses to sign otherwise; `verify_attestation` re-checks).
5. KeyRefs: `key:ed25519:<b64u(32B)>`, `key:p256:<b64u(64B X\|\|Y)>`
   (canonical base64url, no-pad).

## Hashes and identifiers

- `HashAlgorithm`: SHA-256 (CBOR enum 0, 32 B) / SHA-384 (enum 1, 48 B);
  `HashRef::new` enforces digest length.
- Object id: `<prefix>:v1:<b64u-nopad(sha256(canonical CBOR)))>`.
- `proof_id` binds the proposition plus the *sorted* member id sets
  (events, attestations, evidence, relationships); `created_at` excluded.
- `verify_id` recomputes from bytes: any bit flip → `ID_MISMATCH`.

## P-256 note

P-256 signing/verification is implemented and tested but default-off and
thinly covered relative to Ed25519. Production use requires explicit
`AllowedAlgs` opt-in and independent test vectors (withheld: fail-closed
until then).

Traceability: PE-CRYPTO-001..008 (`docs/requirements-matrix.md`).
