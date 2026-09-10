# Example Policies

These are example verification policies you can adapt for your use case.

> Schema (fail-closed): only `policy_version`, `policy_id`, `requirements`
> are allowed at the top level. `description` and any other extra field is
> rejected with `POLICY_INVALID` (see `crates/proof-policy/src/policy.rs`
> `parse_policy`). Keep human notes in this README, not in the JSON.

## How to use

1. Copy the policy that best matches your needs
2. Replace **only the suffix** `REPLACE_WITH_YOUR_ISSUER_KEY` with your issuer's
   key id, keeping the `key:ed25519:` prefix exactly once:
   - file has: `"issuer": "key:ed25519:REPLACE_WITH_YOUR_ISSUER_KEY"`
   - your `attest` printed: `issuer key:ed25519:_RckO…p9hg`
   - result: `"issuer": "key:ed25519:_RckO…p9hg"`
   - ❌ wrong: `"issuer": "key:ed25519:key:ed25519:_RckO…p9hg"` (doubled prefix —
     `evaluate` rejects this as `POLICY_INVALID: malformed issuer`)
   - `evaluate`/`explain` also fail fast with exit 2 and a hint if any
     `REPLACE_WITH` placeholder is still present.
3. Adjust requirements as needed

## Available policies

| Policy | Use when |
|--------|----------|
| [basic-payment.json](basic-payment.json) | Simple payment verification |
| [strict-document.json](strict-document.json) | Document signing with full checks |
| [settlement.json](settlement.json) | Payment settling an invoice |
| [fresh-only.json](fresh-only.json) | Proof must be recent (replay protection) |

## Requirements reference

| Requirement | What it checks |
|-------------|----------------|
| `signature_valid` | Signature is cryptographically valid |
| `issuer_trusted` | Signed by someone you trust |
| `issuer_excluded` | NOT signed by a specific issuer |
| `not_expired` | Proof hasn't passed its expiry date |
| `not_revoked` | Proof hasn't been revoked |
| `not_superseded` | Proof hasn't been replaced by a newer one |
| `relationship_exists` | A specific relationship type exists in the proof |
| `evidence_present` | Evidence of a specific type is attached |
| `transparency_present` | A transparency receipt is attached |
| `proof_fresh` | Proof was created within N seconds |

## Writing your own

A policy is a JSON file with a list of requirements. All requirements must pass (implicit AND).

```json
{
  "policy_version": 1,
  "policy_id": "my_custom_policy",
  "requirements": [
    {"type": "signature_valid"},
    {"type": "not_expired"}
  ]
}
```

See [POLICY.md](../../POLICY.md) for the full specification.
