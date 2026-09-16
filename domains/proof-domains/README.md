# domains/proof-domains — PE-NEUT-003 domain proof-suite

> The constructive proof of core neutrality. This crate is a **pure consumer**
> of the V1 core API (`proof-core`/`proof-crypto`/`proof-verify`/
> `proof-policy`): it adds twelve unrelated industries on top of the engine
> with **zero mechanism modifications** — only new vocabulary strings, new
> domain journeys, and caller-supplied policies.
>
> It is deliberately **not a workspace member**. It builds against the
> core exactly the way an external domain application would.

## What it proves

| Question (docs/NEUTRALITY.md Test 2) | Test |
|---|---|
| Can radically different domains share one core? | `differential::twelve_domains_same_core_same_verdict_shape` (plus `ten_…` / `science_and_cybersecurity_…` compat wrappers) |
| Does a domain-relevant edge fail closed without its grounding evidence? | `differential::grounding_rule_is_domain_independent` |
| Do unknown domain vocabularies survive the pipeline and stay policy-governed? | `differential::unknown_domain_vocabulary_survives_pipeline` |
| Do unknown vocabularies fail closed under policy by default? | `differential::unknown_domain_vocabulary_policy_fail_closed` |
| Does the verdict shape stay identical when a domain journey fails? | `differential::cross_domain_failure_verdict_shape_identical` (all 12 revoked) |
| Does supersession preserve history identically in every domain? | `differential::cross_domain_supersession_preserves_history` (all 12: evidence stays Valid, `not_superseded` fails) |
| Does one flipped byte fail closed identically in every domain? | `differential::tamper_breaks_every_domain_identically` |
| Does a stranger policy fail in every domain while own policies pass? | `differential::foreign_policy_fails_closed_in_every_domain` |

Run:

```bash
cd domains/proof-domains
cargo test
```

CI runs this via `make domain-tests` (see `.github/workflows/ci.yml`).

## The demonstrated industries

Twelve journeys ride the same core, each in its own module
(`tests/<domain>.rs`), exercised together by `tests/differential.rs`:

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
5. **Sensor calibration** (`sensor.rs`) — device measurement, calibration
   attestation, `PRODUCED`/`REFERENCES` edges, sensor policy.
6. **Logistics** (`logistics.rs`) — shipment provenance, `CREATED`/`REFERENCES`
   edges with grounding, logistics policy.
7. **Legal** (`legal.rs`) — document signing and supersession, `SUPERSEDES`
   semantics, legal policy.
8. **Supply chain** (`supplychain.rs`) — batch production and provenance,
   manufacturing vocabulary, supplychain policy.
9. **Healthcare** (`health.rs`) — clinical event/measurement attestation,
   healthcare vocabulary, health policy.
10. **Government** (`gov.rs`) — administrative authorization, government
    vocabulary, gov policy.
11. **Cybersecurity** (`cyber.rs`) — incident observation, signed event +
    evidence chain, cyber policy.
12. **Science** (`science.rs`) — measurement replication and corroboration,
    scientific vocabulary, science policy.

Each of the twelve domains asserts the **same verdict shape** (crypto Valid,
evidence Valid, policy INDETERMINATE at the pipeline), proving the core never
cares which industry's vocabulary rides on it.

Each domain file is **domain data only**: vocabulary constants, a journey
builder, and a caller-supplied policy. No `Cargo.toml` dependency may point at
a mechanism crate's internals; no domain file may re-implement pipeline stages.
