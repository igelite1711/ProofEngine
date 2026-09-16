# Proof Engine — Format Specification (V1.0 Draft)

> Wire-format authority with `docs/format.cddl` (the CDDL wins on bytes;
> `PROOF-ENGINE-SPEC.md` §4 wins on semantics). All "MUST" below are enforced by `proof-format` + `proof-crypto`.
> Verified Phase 0 (2026-09-06): see `docs/standards-refs.md`. Normative: RFC 8949 §4.1+§4.2.1, RFC 9052 §3/§4.2/§4.4/§9, IANA COSE registry (2026-08-25), RFC 9864, FIPS 180-4, RFC 4648 §5.

## 1. Canonical serialization (CBOR deterministic)

V1.0 uses **CBOR deterministic encoding** per RFC 8949 §4.1 Preferred Serialization + §4.2.1 Core Deterministic Encoding Requirements (bytewise lexicographic map ordering). Length-first (§4.2.3, legacy RFC7049 compat) is NOT accepted — re-encode-and-compare rejects it as NON_CANONICAL.

- Integers: shortest-form (RFC 8949 §4.2.1). No leading-zero / non-minimal ints. Bignums forbidden in V1.0. `nint` range is restricted to `i64` (`-2^63..-1`); values below `i64::MIN` MUST be rejected with `FORBIDDEN_CBOR_CONSTRUCT` (no bignum path).
- Maps: keys sorted by **bytewise lexicographic order of deterministic-encoded keys** (RFC 8949 §4.1/§4.2.1); duplicate keys forbidden (decoder MUST reject with DUPLICATE_MAP_KEY).
- Strings: UTF-8 only, validated; no indefinite lengths; `text != bytes` (major type 3 vs 2 never conflated).
- Allowed types only: `uint, nint, text, bytes, array, map, bool, null`. Floats, bignums, indefinite items, ALL tags (including 0/1) → reject with `FORBIDDEN_CBOR_CONSTRUCT`.
- Time: `uint` seconds since Unix epoch (no fractional, no implicit TZ). Human display converts separately.
- Length caps: max 1 MiB proof, max 64 KiB single text/bytes field, max depth 16, max array 256 items, max map 64 entries (configurable, enforced in decoder). Schema-level tightening also enforced: text values ≤1024 B, map keys ≤64 B, evidence `hint` ≤256 B, `metadata`/`claim`/`context` ≤16 entries with flat `tstr=>tstr|uint|bool` values only (no nested maps, no `nint`/`bytes`/`array`/`null` inside).
- Canonicalization validation: verifier re-encodes parsed value deterministically and byte-compares to input; mismatch → `NON_CANONICAL`.
- **Text: bytes as-given — no normalization, no folding, no trimming anywhere in the engine (V1 invariant; see §3.1).** Applications own any NFC/NFD equivalence decisions *before* object creation; verifiers never fold.

Rationale: JSON is for policy files and debug display only. Wire + signing input is always deterministic CBOR bytes. This gives reproducible ids/signatures across Rust/Go/TS/Python.

## 2. Hash abstraction

```
HashRef = { "v": 1, "alg": "sha-256", "digest": "<hex lowercase>" }
```

- V1.0 `alg ∈ { "sha-256", "sha-384" }` (SHA-2 only). Unknown → `UNKNOWN_ALGORITHM`.
- Display form: `hash:v1,sha-256:<hex>`. CBOR form: `{"v":1,"alg":0,"digest":h'…'}` with `alg` enum (`0=sha-256, 1=sha-384`) to keep canonical bytes small; JSON mapping table in §7.
- Digest computed over **canonical CBOR bytes** of the referenced object/payload, never over pretty JSON.
- Hash agility: object ids are `<prefix>:v1:<b64u>` over SHA-256 canonical bytes; only `v` versions the id scheme (algorithm migration = bump `v`). `HashRef` values additionally carry their own `alg` (`0=sha-256, 1=sha-384`). Verifiers MUST NOT assume `sha-256` forever.

## 3. Identifiers

Deterministic, versioned, hash-derived. Never auto-increment DB ids.

| Object | ID construction |
|---|---|
| Event | `evt:v1:<b64uNoPad(sha256(canonical(EventContent)))>` where `EventContent` = all Event fields except `event_id` |
| Attestation | `att:v1:<…>` over `AttestationContent` = all fields except `attestation_id` and `signature` (signature covers content + protected header, see §5) |
| Evidence | `evd:v1:<…>` over content without `evidence_id` |
| Relationship | `rel:v1:<…>` over full canonical `RelationshipContent` (`from`, `type`, `to`, `evidence_ref` AND `attestation_ref`) without `rel_id` |
| Proof | `prf:v1:<b64uNoPad(sha256(canonical(binding)))>` where `binding` is the canonical CBOR map `{"v":1, "proposition":<Proposition>, "created_at":<uint>, "events":[sorted event ids], "attestations":[sorted attestation ids], "evidence":[sorted evidence ids], "relationships":[sorted relationship ids]}` (id lists ascending). `created_at` IS covered by the binding (V1 CORE freeze deviation, pre-V1.0 wire fix): a holder re-stamping it changes the recomputed id and fails `ID_MISMATCH`, so `proof_fresh` cannot be forged by rewrites. Composition linkage: when `referenced_proofs` is non-empty, the binding gains one more sorted key `"referenced_proofs":[sorted prf ids]`; empty linkage encodes the identical map as V1 (byte-identical ids). Optional bound `vocabularies` declarations behave the same (absent → byte-identical). |
| Keys | `key:ed25519:<b64u(pubkey)>` / `key:p256:<b64u(uncompressed without 0x04)>`; issuer field uses full KeyRef |

- `b64uNoPad` = RFC 4648 base64url without padding.
- Verifier recomputes every id; `ID_MISMATCH` on any difference (primary tamper signal).
- Collision resistance: the preimage-resistance strength of SHA-256 (≈2^128 against deliberate collision). Every id carries exactly one full SHA-256 digest — **no truncation, no shortening, no "short id" alias in V1**; `verify_id` rejects any digest that is not exactly 32 bytes. Future algorithm migration changes `v`, never the length.
- Identifier length is bounded: `<prefix>:v1:` + 43 base64url chars (3-char prefix, `evt`/`att`/`evd`/`rel`/`prf`; `key:` refs are longer by key type and not hash-derived). Full ids are 50 chars (`7+43`). Consumers MAY reject ids longer than 64 chars as malformed (never 48 — that would reject all valid ids).

### 3.1 Text normalization (normative for identifiers)

**Bytes-in, bytes-out: identifiers bind the exact UTF-8 bytes as given. Proof Engine V1 performs NO normalization (no NFC/NFD folding, no case folding, no whitespace trimming, no percent-decoding) on any string before canonical encoding, hashing, or id derivation.**

- `café` encoded NFC (bytes `63 61 66 C3 A9`) and NFD (`63 61 66 65 CC 81`) are **two different canonical byte strings** → two different ids. Both are individually valid; they never unify.
- Rationale: (a) UTF-8 byte equality is the only comparison every independent implementation agrees on without a Unicode-version dependency; (b) normalization is a *meaning* decision that belongs to the application layer (§54 principle: the core knows how to bind, not what strings mean); (c) post-hoc normalization would silently rewrite already-issued ids.
- Consequence for applications: producers that want normalization-equivalence MUST normalize at the application boundary **before** creating objects (and say so in their domain schema/profile); verifiers MUST NOT normalize (it would break id binding and signature coverage).
- Consequence for implementers: two implementations receiving the same logical object with different byte spellings MUST produce different ids — agreement on this rule is part of interop testing.

## 4. Object schemas (CBOR maps, closed — unknown fields reject)

Field order on wire is irrelevant (map sorting canonicalizes) but docs list canonical key order for readability.

### 4.1 EventContent (v1)

```
{ "v": 1, "type": tstr (open vocabulary — transported verbatim, PE-FMT-008), "subject": tstr,
  "effective_at": uint, "payload_ref": HashRef, "metadata": {* tstr => tstr|uint|bool} }
```

`metadata` max 16 entries, keys ≤64 chars. No nested maps.

### 4.2 AttestationContent (v1)

```
{ "v": 1, "issuer": tstr (KeyRef), "subject": tstr (ObjectRef),
  "claim": { "type": tstr, * tstr => tstr|uint|bool },
  "issued_at": uint, "expires_at": uint|nil, "evidence_ref": tstr|nil }
```

`expires_at` nil = no expiry (policy may still require expiry → FAIL). `claim` max 16 entries.
`evidence_ref`, when present, must name `evd:v1:…` (typed at schema).

### 4.3 Evidence (v1)

```
{ "v": 1, "kind": tstr (open vocabulary — transported verbatim, PE-FMT-008), "digest": HashRef,
  "attestation_ref": tstr|nil, "hint": tstr|nil }
```

Content-type/size conventions belong to domain profiles (`kind`/`hint`/claim
fields carry them; the digest binds the bytes). The core never fetches —
`attestation_ref` must name `att:v1:…` (typed at schema; wrong-typed ids fail
`SCHEMA_VIOLATION`, dangling correct-prefix hints read `Unknown` with validity
preserved — see §4.6 portability rule and `--strict-current`).

### 4.4 Relationship (v1)

```
{ "v": 1, "from": tstr, "type": tstr (open vocabulary — transported verbatim, PE-FMT-008), "to": tstr,
  "evidence_ref": tstr|nil, "attestation_ref": tstr|nil }
```

Trust-relevant types (`SETTLES, OWNS, CREATED, EXECUTED, EQUIVALENT, CONTRADICTS`) REQUIRE one of `evidence_ref|attestation_ref`, else `RELATIONSHIP_UNGROUNDED`. Backing refs are typed (`evidence_ref` → `evd:v1:…`, `attestation_ref` → `att:v1:…`; wrong-typed ids fail `SCHEMA_VIOLATION`). Extra future kinds plug in via `extra_grounded` without a core change.

### 4.5 Proposition (v1)

```
{ "v": 1, "kind": tstr, "subject": tstr, "predicate": tstr,
  "object": tstr|nil, "at_time": uint|nil, "context": {* tstr => tstr|uint|bool} }
```

### 4.6 Proof (v1)

```
{ "v": 1, "proof_id": tstr, "proposition": Proposition,
  "events": [EventContent+], "attestations": [AttestationEntry+],
  "evidence": [Evidence], "relationships": [Relationship],
  "referenced_proofs": [tstr] (optional, sorted prf:v1: ids; absent in V1 bytes),
  "created_at": uint }
```

`AttestationEntry = {"content": AttestationContent, "sign1": bytes(COSE_Sign1)}`.
Arrays sorted by id at build time (deterministic member order).
Portability rule: relationship endpoints and attestation `evidence_ref`s MUST
resolve to member ids within the same Proof (no database lookup); anything else
is `DANGLING_REFERENCE`. External payload content stays outside — digests only.

### 4.7 Revocation / Supersession / Withdrawal / Compromise (signed attestations, not deletes)

```
Revocation  = Attestation with claim.type="revoke", claim.target=<id>, claim.reason, issued_at
Supersession = Attestation with claim.type="supersede", claim.old=<id>, claim.new=<id>
Withdrawal  = Attestation with claim.type="withdraw", claim.target=<any artifact id>, claim.reason, issued_at
Compromise  = Attestation with claim.type="compromise", claim.target=<keyref|id>, claim.at_time=<uint instant>, claim.reason, issued_at
```

Must be signed by original issuer OR a key in `revocation_authorities` (explicit VerifyCtx input), except: withdrawal additionally accepts the issuer of the target's bound attestation (evidence), and compromise additionally accepts the target identity itself (self-report; compromise only invalidates, never grants). Unsigned status lists are never trusted.

Reserved statement-level conventions (no lifecycle effect, projected for policy): `delegate` (subject = grantee, optional `scope`), `identity.bind` (subject ≡ `equivalent`), `transparency.checkpoint` (issuer = log identity), the `denies` claim field (opposition to an attestation id), and the opt-in `evidence_digest` claim field (`<64|96 hex>` with `evidence_ref`; pipeline verifies equality with the bound evidence digest, mismatch/missing/malformed fails EVIDENCE closed).

## 5. Signatures (COSE_Sign1, detached-ish enveloped)

- Envelope: **COSE_Sign1** (RFC 9052 §4.2; RFC 8152 is obsolete). Stored untagged: tag 18 MUST NOT be used — all CBOR tags are rejected (canonical subset §1). Stored as CBOR bytes alongside AttestationContent.
- Protected header (exact, closed): `{ 1: alg (int), 4: kid (bstr=raw pubkey) }` only. Label 6 is Partial IV per RFC 9052 §3.1 — MUST NOT be reused. Domain separation uses `external_aad = h'504531' ("PE1")`. Any other label → `UNEXPECTED_HEADER_PARAM`.
- Algs (verified 2026-09-06 vs IANA + RFC 9864): `Ed25519 (-19, REQUIRED)`; `ESP256 (-9, OPTIONAL, default-off)`. Deprecated polymorphic `-8 (EdDSA), -7 (ES256), -35, -36` → `DEPRECATED_ALGORITHM`, never negotiated. See docs/standards-refs.md §3.
- Signing input: `Sig_structure = ["Signature1", body_protected_bytes, external_aad=h'504531', canonical(AttestationContent)]` per RFC 9052 §4.4, encoded per §9. Signs canonical bytes, not JSON.
- Key representation: raw bytes in `kid`; full `COSE_Key` (`kty: OKP crv Ed25519 / EC2 P-256`) exchanged out-of-band or in `VerifyCtx.trusted_issuers`. No JWK with `use` confusion; `alg` in key MUST equal attestation `alg` else `ALGORITHM_CONFUSION`.
- Verification procedure: (1) parse+validate header closed, (2) recompute content id, (3) rebuild `Sig_structure` exactly, (4) verify with stated alg/key, (5) check `issued/expires` separately (signature does not imply timeliness).
- Deprecation: alg registry versioned; verifier config `allowed_algs`; adding new alg = minor version, removing = major with migration note.

## 6. Versioning

Every object carries `v`. `proof_format_version==1` dispatch to v1 parser/verifier. Unknown version → `UNSUPPORTED_VERSION`, never reinterpret under new rules. Canonicalization rules, hash display, policy language each versioned independently.

## 7. JSON mappings (policy + debug only)

Policy files are JSON (not CBOR) for readability; engine validates then converts to internal structs. `alg` name table: `0↔sha-256, 1↔sha-384`; COSE algs by number (`-19, -9`). JSON never signed; only CBOR canonical bytes are signed.

## 8. Golden-vector record shape

```
{ "name", "input_json", "canonical_hex", "object_id", "cose_sign1_hex",
  "verify_ctx (clock, trust list)", "expected": {crypto, evidence, policy, codes[]} }
```

At least one vector per error-code in ERROR-MODEL.md (24 stable codes). Vectors are normative for interop.
