# Proof Engine — Threat Model (V1.0)

> Scope: local library + CLI verifying portable CBOR/COSE proofs. No network service, no chain in V1.0.
> Final for V1.0: describes implemented behavior (see docs/phase7-report.md and VERIFICATION.md for how to check).
> Guarantee: tamper-evidence, correct crypto/policy evaluation, fail-closed. Non-guarantee: real-world truth, honest issuers/sensors.

## 1. Attackers

- **A1 Malicious issuer**: signs false claims with its own valid key.
- **A2 Key thief**: holds compromised legitimate key.
- **A3 Proof forger/mutator**: tampers bytes, swaps algs/keys/hashes, replays proofs.
- **A4 Malicious input supplier**: feeds giant/malformed proofs, evil policies, bad UTF-8, deep nesting to verifier.
- **A5 External-evidence liar**: serves different content than digest, equivocation, withholding.
- **A6 Clock manipulator / verifier misconfigurer**: wrong `verified_at`, overly-trusting policy/trust list.
- **A7 Revocation suppressor**: withholds revocation, replays pre-revocation proof as fresh.

Engine does NOT defend against compromised caller host, stolen trusted-key list, or broken SHA-256/Ed25519 primitives (relies on standard primitives + agility).

## 2. Assets & security properties

Assets: canonical bytes, private keys (outside engine), trust lists, revocation sets, policy files, explanation integrity.
Properties: **integrity** (tamper → FAIL + code), **authenticity** (sig binds key+bytes, not truth), **freshness** (expiry/revocation enforced), **binding** (ids bind member sets), **availability of verification** (bounded resources, no panic/OOM), **decision integrity** (explanation derived from state, policy AND-semantics).

## 3. Threats → attack / impact / mitigation / residual

1. **Forged evidence / tampered payload** — flip bytes, keep sig. Impact: false PASS. Mit: re-encode canonical + recompute ids + COSE verify; any mismatch → `SIGNATURE_INVALID`/`ID_MISMATCH`. Residual: none if primitives hold.
2. **Signature/key confusion, algorithm downgrade** — swap `alg`, cross-protocol key reuse. Impact: bypass. Mit: closed alg set (Ed25519 `-19` required, ESP256 `-9` accepted; deprecated `-8/-7/-35/-36` rejected), `allowed_algs` config, key `alg==header alg` check, `external_aad="PE1"` domain separation, unknown → fail. Residual: misconfigured `allowed_algs` (caller's responsibility; documented in ARCHITECTURE.md and POLICY.md — the CLI does not warn today).
3. **Canonicalization ambiguity** — duplicate map keys, non-minimal ints, float/JSON drift. Impact: two meanings, one sig. Mit: deterministic CBOR per RFC 8949 §4.2, duplicate-key reject, forbidden constructs, re-encode-and-compare. Residual: implementation bug → golden vectors + cross-impl test required.
4. **Replay** — same valid proof presented as new event. Impact: double-settle. Mit: `event_id` uniqueness per context, validity intervals, and id-bound member sets; binding context can ride in claim fields / metadata (flat string→scalar), but binding *state* (nonces, seen ids) is the caller's — V1.0 has no global store. Residual: caller that ignores binding → misuse, not an engine PASS; express replay constraints in the policy and caller bookkeeping.
5. **Expired / revoked / superseded treated as valid** — stale PASS. Impact: honoring dead credential. Mit: explicit states ACTIVE/REVOKED/EXPIRED/SUPERSEDED/UNKNOWN; signed revocations only; missing freshness info → UNKNOWN → fail closed; `verified_at` explicit + skew leeway logged. Residual: revocation-suppression (A7) — needs freshness policy/transparency in future; V1.0 marks `REVOCATION_UNKNOWN` when set is stale.
6. **Graph abuse: cycles, explosion, dangling refs, ungrounded edges** — DoS or fake SETTLES edge. Impact: OOM/hang or false trust. Mit: hard limits (size/nodes/edges/depth/evidence), cycle reject on SUPERSEDES (non-SUPERSEDES cycles are allowed by design and tested), dangling-ref reject, trust-relevant edges require backing attestation. Residual: none within limits; tune limits per deployment.
7. **Parser/decoder DoS** — giant proof, deep nesting, bad UTF-8, int overflow. Impact: crash/OOM. Mit: streaming size cap, depth cap, UTF-8 validation, checked arithmetic, no recursion without bound, negative-tested decoders + proptests + stable mutation-soak + cargo-fuzz 600s smoke green (4/4 no findings; run id in CI). Residual: allocator pressure — CLI inputs additionally capped at 8 MiB (`MAX_INPUT_FILE_BYTES`, H1).
8. **Policy abuse / injection** — evil policy file grants PASS, unknown requirement silently skipped. Impact: false trust. Mit: closed requirement set, schema-validate before eval, implicit AND, unknown → `POLICY_INVALID`, evaluation is pure/deterministic, no fetch/eval of code. Residual: overly-broad trust list — caller's responsibility, surfaced in explanation.
9. **External-reference confusion** — URL/digest mismatch, silent fetch (SSRF/equivocation). Impact: trusting attacker's bytes. Mit: digests mandatory, evidence is digest-only, the engine performs no fetch at all (no network code exists in V1.0); any external content is fetched, digested, and compared by the caller. Residual: caller fetches malicious content matching digest? Digest binds content; equivocation across contexts needs transparency (future).
10. **Version confusion** — old bytes reinterpreted under new rules. Impact: silent semantic change. Mit: versioned parsers/verifiers, unknown version → `UNSUPPORTED_VERSION`. Residual: downgrade by attacker stripping to v1 — verifier `min_version` config.
11. **Clock manipulation** — backdated `issued_at`, future `expires_at`. Impact: extend validity. Mit: never trust embedded time alone; compare against explicit `verified_at` + leeway; document that `verified_at` must come from trustworthy clock; transparency receipts (future) anchor time. Residual: verifier with bad clock — out of scope, must be documented in SECURITY.md.
12. **Explanation spoofing / AI override** — display says PASS while core says FAIL. Impact: human fooled. Mit: `explain_result()` is pure projection of `VerifyReport`, tested by assertion (explanation decision == report decision); AI layer cannot call into verifier to override. Residual: downstream UI ignoring codes — provide stable error codes, warn integrators.
13. **Key/identity over-trust** — "valid sig ⇒ trusted". Impact: A1 succeeds. Mit: architecture + API separate `issuer_trusted` (policy trust list) from `signature_valid`; demo shows valid-sig + FAIL-policy case. Residual: none in engine; deployment risk remains.

## 4. Attack surfaces (V1.0)

- CBOR decoder, COSE verifier, id recomputation, policy JSON parser, graph ingester, CLI file loaders. All negative-tested (golden vectors + unit tests + proptests + stable soak); cargo-fuzz 600s smoke green, 4/4 no findings (VERIFICATION.md). CLI input files are capped at 8 MiB before buffering (`MAX_INPUT_FILE_BYTES`, H1). No network listener in V1.0.
- **Out of scope but documented**: host keystore, OS clock, storage backend, future HTTP API (authN/Z, rate limits deferred to Phase 8).

## 5. Resource limits (enforced, not advisory)

`max_proof_size 1MiB | max_evidence_items 64 | max_nodes 128 | max_edges 256 | max_depth 16 | max_policy_requirements 32 | max_sig_size 256B | max_payload_ref_size 64KiB`. Exceed → `LIMIT_EXCEEDED` with object path. All configurable downward.

## 6. Top-3 risks to watch first

1. Canonical-CBOR divergence between implementations (highest interop risk).
2. Revocation freshness without online status (suppression window).
3. Caller misconfiguration of trust list / clock (turns correct engine into wrong decision) — mitigate with loud explanation headers.
