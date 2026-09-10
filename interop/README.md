# Interop package — independent verifier + creator (Gate I)

Second implementation of the cryptographic interop core, written without
reference to the Rust source (only FORMAT.md, INTEROPERABILITY.md, and
`fixtures/`). Proves a second engineer can do it.

## Layout

```text
interop/minicbor.py     strict CBOR subset (rejects floats/tags/indefinite/
                        bignums/simples/non-shortest/dup-keys/misorder/
                        trailing/bad-utf8; depth cap 16 like engine default)
interop/pengine.py      ids (sha256+b64u), COSE_Sign1 verify, proof verify
                        (stages 1-6 + proof_id binding), RFC 8032 sign,
                        artifact creators (event/attestation/evidence/
                        relationship/proof)
interop/differential.py I2 + I3a + I3b + negative-differential runner
```

## Rules

- **Stdlib only** (CI greps for third-party imports). No `pip install`
  exists between a new machine and a green run.
- **Scope is cryptographic interop**: parse, canonicality, identifiers,
  signatures, proof binding. Time/lifecycle/graph/policy take
  caller-supplied inputs and live engine-side by design — the Python side
  never guesses them.
- Known divergences from engine limits (all fail-closed direction):
  decoder depth cap is fixed at 16 (no configurable `Limits`); no
  P-256 ECDSA verification (independent secp256r1; golden-21..23 cross-check); no size caps (inputs here
  are fixtures and own outputs, never hostile streams).

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
