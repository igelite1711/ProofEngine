# examples/live — a worked payment example (real artifacts)

A complete, working payment proof: **`payment:p1` settles `invoice:i9`**, built
with the shipped CLI and stored as production-format artifacts (a JSON wrapper
around canonical CBOR bytes plus its content-derived id).

Unlike a snippet, these files are *real*: every loader re-verifies the bytes,
recomputes the id, and re-checks the signature. You can verify this directory
exactly as it sits in the repository.

## Scenario

| Artifact | What it is |
|---|---|
| `payloads/payment.bin`, `payloads/invoice.bin` | The bytes the two events point at (hashed by the CLI; the core never stores content) |
| `payloads/receipt.bin` | The settlement receipt whose digest the evidence records |
| `ev1.json` | Event `payment.created` → `payment:p1` |
| `inv1.json` | Event `invoice.issued` → `invoice:i9` |
| `att.json` | Issuer attestation `payment.settled {amount: 4200}` over `payment:p1` |
| `evd.json` | Evidence `transaction_record`, digest-bound to `receipt.bin`, backed by `att.json` |
| `rel.json` | Relationship `SETTLES` from the payment event to the invoice event, grounded by the evidence **and** the attestation |
| `proof.json` | The sealed proof binding both events, the attestation, the evidence, the edge, and `created_at` |
| `policy.json` | `settlement_v1`: signature valid + issuer trusted + not expired + not revoked + `SETTLES` edge + `transaction_record` evidence |

## Verify it yourself

```console
proof-cli verify examples/live/proof.json --clock 1700000300 \
    --revocations-known-at 1700000300 --no-require-status
proof-cli evaluate examples/live/proof.json --policy examples/live/policy.json \
    --clock 1700000300 --revocations-known-at 1700000300 --no-require-status \
    --trusted key:ed25519:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg
proof-cli inspect examples/live/proof.json   # read-only view, no verdict
```

`--seed test` produced the issuer key above: **demo-grade, fixed, and public —
never use it for anything real** (`SECURITY.md`). `--no-require-status` is the
genesis/demo escape hatch for a genuinely empty revocation feed; a production
run supplies `--status` files and drops the flag.

## Regenerate (do not hand-edit)

These files are byte-bound: any wire-format or id-binding change makes every
stored artifact stale, and a stale example verifies with `ID_MISMATCH` — it
teaches the wrong thing. Regenerate instead of patching:

```console
bash tools/gen_examples_live.sh           # rewrites examples/live/
bash tools/gen_examples_live.sh --check   # CI rot guard: diff vs fresh generation
```

`cargo test -p proof-cli --test examples_live` pins the same invariant inside
the test suite (artifacts load, proof verifies, policy passes).