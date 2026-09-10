# Proof Engine - LONGEVITY.md: surviving decades, including the quantum era (V1)

> This is a **migration contract**, not a promise. Nobody can truthfully assert
> that any 2026 cryptographic algorithm is secure “for 100 years.” What V1 CAN
> guarantee is: the machinery to migrate **without rewriting the data model**,
> fail-closed behavior for anything unknown, and an explicit decision path for
> every layer. This page makes that path concrete and pre-committed.

## 1. What is anchored today (V1, in development)

| Layer | Binding | Reference |
|-------|---------|-----------|
| Object ids | `prefix:v1:<b64u(sha256(canonical))>` - one full SHA-256 digest | FORMAT §3, PE-CRYPTO-009 |
| Content digests | `HashRef {v, alg: “sha-256”, digest}` (alg is an open enum) | FORMAT §2 |
| Signatures | COSE -19 Ed25519 (RFC 8032, deterministic, REQUIRED); -9 ECDSA-P-256 (RFC 6979, deterministic, opt-in) | FORMAT §5, PE-CRYPTO-001 |
| Key-references | `key:ed25519:<b64u>` / `key:p256:<b64u>` (length-checked) | PE-SEC-005, PE-CRYPTO-011 |
| Canonical encoding | RFC 8949 subset, byte-identity round-trip enforced by tests | PE-FMT-001..009 |

Every layer carries an explicit version signal that **fails closed when
unknown** (`v`, `:vN:`, `policy_version`, COSE alg registry, HashRef.alg):
an artifact from the future is rejected loudly, never misread.

## 2. Longevity risk register

| Risk | Exposure | State in V1 |
|------|----------|-------------|
| SHA-256 collision/preimage degradation in a quantum era | Ids bind content bytes; an attacker who finds a SHA-256 **collision** on a chosen prefix could substitute one object for another under the same id; **second-preimage** hardness is also needed to re-map an *existing* id | No known practical break; the `:vN:` id version exists and the dual-verify migration window (below) is the ready path |
| Shor-style quantum attack on discrete logs (Ed25519, ECDSA P-256) | A large-scale quantum computer would recover signing keys from public keys and forge attestations | Not here today; the answer is **post-quantum signature algorithms on the existing registry**, not a different proof model |
| Algorithm/library drift | Old implementations rot; specs must be complete enough for a from-scratch reimplementation | FORMAT.md claims “second implementer” completeness; golden vectors + independent verifier back it |
| Time representation drift | u64 Unix seconds are unambiguous for ~584 billion years; fixed, caller-supplied clocks | explicit-input clock rules |
| Byte preservation | The engine verifies *bytes*; keeping them (storage, transport, re-signing) is the owner’s duty | canonical round-trip identity is a test contract, so preserves any copy |

## 3. Hash migration contract (object ids and content digests)

Trigger (any of): a chosen-prefix or second-preimage attack on SHA-256 becomes
academically credible below ~2^100 work; NIST/ISO/RFC deprecates SHA-256 for
long-term commitments; or a deployment needs stronger preimage margins for
truly long-lived archives.

Procedure (all pre-committed; no model changes, no data rewrites):

1. **Add** a new digest and new id version: `evt:v2:<b64u>` … `prf:v2:`; the
   `v2` infix is the signal. Old `v1` artifacts keep their bytes, ids, signatures
   and historical validity (nowhere is rewritten).
2. **Dual-verify window**: verifiers accept `:v1:` **and** `:v2:` ids for a
   documented transition period (both digests allow-listed); unknown versions
   still fail closed. Producers emit new objects under `v2`.
3. **Cutover**: a major release retires `:v1:`; older proofs remain verifiable
   under an explicit “legacy” mode if the ecosystem needs it, and are otherwise
   still *decodable* - decodable does not mean verified.
4. At every step the same rule from §1 applies: nothing is silently assumed
   open; the spec says which versions are accepted and when.

Content digests (`HashRef.alg`) already migrate additively - accepting a new
digest algorithm is a verifier configuration change, and the dual-verify story
is the same.
## 4. Signature migration and the hybrid bridge

Post-quantum signature schemes (e.g., NIST FIPS 204 ML-DSA, FIPS 205 SLH-DSA,
or whatever the ecosystem converges on) enter the existing closed registry:

- New COSE algorithm number + new key-ref prefix (`key:ml-dsa-44:...`), both
  documented in FORMAT §5 / key-ref rules, **default off** in every verifier
  until deployments opt in.
- Allow-lists (`AllowedAlgs`) and trust lists already give per-verifier
  control; nothing becomes implicitly trusted because a number exists.
- **Hybrid bridge (dual-sign)**: during transition, issuers sign the SAME
  canonical artifacts with both a classical and a PQ key. That is engine-native
  today: two attestations, two `issuer_trusted` requirements - the existing
  AND-of-issuers semantics (POLICY.md). Policies can require “classical AND
  PQ” until PQ-only is safe, giving migration without a trust cliff.
- The engine never “resigns” or “upgrades” old artifacts automatically.
  Migration = issuers reissue attestations (the revocation/supersession
  lifecycle exists precisely so a reissue is a normal event, and history is
  preserved).

## 5. Determinism across eras

V1’s byte-level reproducibility claim (same bytes + same inputs ⇒ same
report, enforced by CI) is built on **deterministic signature schemes**: RFC
8032 (Ed25519) and RFC 6979 (ECDSA) - both tested to be byte-identical for a
fixed key+message (**PE-CRYPTO-010**), and cross-checked by the independent
Python ECDSA verifier on golden-21/22/23.

Consequence for the future: a randomized-signature algorithm (or a
non-deterministic mechanism anywhere else) is allowed only as a **documented
MAJOR change** that re-scopes the reproducibility claim from byte-level to
verdict-level. It will never be introduced silently.

## 6. Time

All time inputs are `u64` Unix seconds, caller-supplied, never the wall clock.
The 64-bit horizon (~584 billion years) is immaterial; the explicit-input rule
is what keeps verification deterministic and reproducible for a century.

## 7. Threats we deliberately do not address in V1 (and why)

- **Zero-knowledge proofs.** ZK could later prove *knowledge of evidence*
  without revealing it (privacy), but V1’s privacy story is: separate proof /
  evidence / references now; ZK is an additive future layer, never a silent
  V1 claim.
- **Blockchain / anchoring / transparency logs.** They extend trust; they are
  not part of the proof engine. Long-term extrapolation of who *asserted
  what* stays with the application that owns the records.
- **“Quantum-proof everything today.”** No serious scheme has both formal
  standardization and deployment maturity equal to Ed25519’s; the V1 answer is
  the migration machinery above, not writing ML-DSA or SHA-3 numbers into the
  spec before the ecosystem converges.

## 8. Honest status

This document is a **plan with decision triggers**, not a guarantee. It cannot
predict cryptanalysis; it *does* assure that when a trigger fires, the change
path is: additive registry entry, dual-verify window, authored transition,
cutover - with every unknown version failing closed at every step. That is the
only honest definition of "survives the quantum era": the architecture is
**migratable**, and its failure mode is **loud refusal, never silent trust**.

## 9. Crypto-agility test evidence

The following tests in `crates/proof-crypto/src/cose.rs` verify the
architecture handles PQ algorithm numbers correctly:

| Test | What it proves |
|------|----------------|
| `pq_mldsa44_unknown_alg_rejected` | ML-DSA-44 (alg -45) parsed, rejected as `UNKNOWN_ALGORITHM` |
| `pq_slhdsa128s_unknown_alg_rejected` | SLH-DSA-128s (alg -18) parsed, rejected as `UNKNOWN_ALGORITHM` |
| `pq_algorithm_header_is_parsed_correctly` | Parser extracts PQ alg number from protected header |
| `pq_and_classical_same_structure` | PQ and classical COSE_Sign1 use identical wire structure |

These tests prove:
1. The parser is algorithm-neutral (handles any COSE alg number)
2. Unknown PQ algorithms fail closed with explicit error codes
3. The COSE_Sign1 structure is identical for classical and PQ algorithms
4. Adding PQ support = new alg constant + key prefix + AllowedAlgs entry + sign/verify functions

No core rewrite needed. This is crypto-agility by construction.
