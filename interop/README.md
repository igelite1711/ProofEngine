# Interop package — independent verifier + creator (Gate I)

Second implementation of the cryptographic interop core, written without
reference to the Rust source (only FORMAT.md, INTEROPERABILITY.md, and
`fixtures/`). Proves a second engineer can do it.

## Layout

```text
interop/minicbor.py     strict CBOR subset (rejects floats/tags/indefinite/
                        bignums/simples/non-shortest/dup-keys/misorder/
                        trailing/bad-utf8; depth cap 16 like engine default)
interop/pengine.py      ids (sha256+b64u), COSE_Sign1 verify (Ed25519 +
                        independent secp256r1 ECDSA), proof verify
                        (stages 1-6 + proof_id binding incl. composition
                        refs and vocabulary declarations), RFC 8032 sign,
                        artifact creators
                        (event/attestation/evidence/relationship/proof)
interop/differential.py I2 (all 31 golden vectors) + I3a + I3b +
                         negative-differential runner (37 checks, incl. closed-schema parity)
interop/ts/             third implementation: independent TypeScript/Node
                        verifier (minicbor.ts strict CBOR, pengine.ts COSE +
                        proof binding via @noble/curves) with its own
                        differential runner over the same golden corpus
```

## Rules

- **Stdlib only** (CI greps for third-party imports). No `pip install`
  exists between a new machine and a green run. The TypeScript package is
  the deliberate exception: it lives in `interop/ts/` (excluded from the
  stdlib grep), needs one dependency (`@noble/curves`), and documents that
  trade-off below.
- **Scope is cryptographic interop**: parse, canonicality, identifiers,
  signatures, proof binding. Time/lifecycle/graph/policy take
  caller-supplied inputs and live engine-side by design — the Python side
  never guesses them.
- Known divergences from engine limits (all fail-closed direction):
  decoder depth cap is fixed at 16 (no configurable `Limits`); no size caps
  (inputs here are fixtures and own outputs, never hostile streams).
  Time/lifecycle/graph-pipeline/policy verdicts stay engine-side; Python
  cross-checks their vectors at binding level (well-formed + binding holds).

## Run

```console
python3 interop/differential.py --repo . \
    --proof-cli ./target/debug/proof-cli --work /tmp/proof-interop
```

Expects `make demo` output at `demo/out/proof.cbor.json` for the I3b leg.
Exit 0 with `DIFFERENTIAL: N pass, 0 fail`, else 1.

## Audit notes (mistakes this package caught or survived)

- Compressed Edwards points store **y** with top bit = x parity (an early
  draft swapped the roles; differential tests pin the correct form).
- Sig_structure is a **4-array** (`0x84`), not 3.
- Object id prefixes are bare (`evt`, not `evt:v1` — the `:v1:` comes from
  the `id_with` format, DATA-MODEL.md).
- `external_aad` is the three bytes `50 45 31` ("PE1").

## TypeScript implementation (`interop/ts/`)

A third, independent implementation in TypeScript/Node 18+ covering the
same cryptographic scope: strict CBOR decode/canonical re-encode, Ed25519 +
P-256 COSE_Sign1 verification, and full proof verification (stages 1-6 +
proof_id binding, incl. composition refs and vocabulary declarations).
Written against FORMAT.md / INTEROPERABILITY.md / DATA-MODEL.md and the
golden corpus.

- **One runtime dependency**: `@noble/curves` (audited, pure JS, no
  transitive deps) for Ed25519/P-256; everything else is Node stdlib
  (`node:crypto` for SHA-256). This breaks the stdlib-only rule that the
  Python package holds; it is accepted because a third independent
  implementation with an independent curve library is worth more than
  dependency-count purity, and it stays out of the Python stdlib CI gate.
- **Run**: `cd interop/ts && npm install && npm run differential`
  (typechecks, then runs). Exit 0 = all checks green.
- **Checks** (31): generically re-verifies every golden vector whose
  recorded expectation names a stage this package implements
  (parse/canonical/id/signature/binding — 21 of 31 vectors; the other 10
  pin engine-side time/lifecycle/graph/policy verdicts and are exercised by
  the Python differential instead), then 9 TS-crafted mutants on golden-11
  (unknown field in every member slot + top-level, mutated proof_id,
  version bump) must all be rejected, then I3b (the Rust demo proof
  verifies under TS). Golden-04/05 (Ed25519 Sign1 + flipped byte) and
  golden-21/22/23 (P-256 Sign1 set) exercise both curves directly.
- **Divergences, same fail-closed direction as the Python package**: depth
  cap fixed at 16, no size caps, integers only within Number.MIN/MAX_SAFE
  range for encoding.
