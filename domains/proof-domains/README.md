# domains/proof-domains — PE-NEUT-003 domain proof-suite

> The constructive proof of core neutrality. This crate is a **pure consumer**
> of the V1 core API (`proof-core`/`proof-crypto`/`proof-verify`/
> `proof-policy`): it adds four unrelated industries on top of the engine with
> **zero mechanism modifications** — only new vocabulary strings, new domain
> journeys, and caller-supplied policies.
>
> It is deliberately **not a workspace member**. It builds against the
> core exactly the way an external domain application would.

## What it proves

| Question (docs/NEUTRALITY.md Test 2) | Test |
|---|---|
| Can radically different domains share one core? | `differential::four_domains_same_core_same_verdict_shape` |
| Does a domain-relevant edge fail closed without its grounding evidence? | `differential::grounding_rule_is_domain_independent` |
| Do unknown domain vocabularies survive the pipeline and stay policy-governed? | `differential::unknown_domain_vocabulary_survives_pipeline` |
| Do unknown vocabularies fail closed under policy by default? | `differential::unknown_domain_vocabulary_policy_fail_closed` |
| Does the verdict shape stay identical when a domain journey fails? | `differential::cross_domain_failure_verdict_shape_identical` |

Run:

```bash
cd domains/proof-domains
cargo test
```

CI runs this via `make domain-tests` (see `.github/workflows/ci.yml`).

## The four domains

1. **Payment** (`payment.rs`) — the V1 reference journey: `payment.created` →
   `invoice.issued`, merchant attestation, `SETTLES` edge, `transaction_record`
   evidence, `merchant_payment_v1` policy.
2. **Credential lifecycle** (`credential.rs`) — identity domain: a credential
   grant, `ISSUED` edge, revocation by signed status object, `credential_issuer_v1`
   policy. Proves the lifecycle dimension (ACTIVE → REVOKED) is industry-agnostic.
3. **Media licensing** (`media.rs`) — media provenance: a licensed work, rights
   holder attestation, `OWNS` edge (grounding required), `licensing_v1` policy
   requiring domain vocabulary via `relationship_exists`/`evidence_present`.
4. **AI-action provenance** (`ai.rs`) — an agent action chain: user request →
   tool call, operator attestation, `EXECUTED` edge (grounding required),
   `ai_action_v1` policy.

Each domain file is **domain data only**: vocabulary constants, a journey
builder, and a caller-supplied policy. No `Cargo.toml` dependency may point at
a mechanism crate's internals; no domain file may re-implement pipeline stages.
