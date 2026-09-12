# Domain: Science (independent replication)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. An experiment result
> confirmed by an independent replication backed by its dataset
> (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/science.rs`.

## Vocabulary -> core mapping

| Science noun | Core mapping |
|--------------|--------------|
| experiment completion | `Event` (`research.experiment.completed`, metadata `method`/`sample_n`) |
| replication completion | `Event` (`research.replication.completed`, metadata `lab`/`sample_n`) |
| "result confirmed" claim | `Attestation` (`research.result.confirmed`, fields `effect`/`p_value`) |
| replication dataset | `Evidence` (`dataset`, bound to the attestation) |
| replication relation | `Relationship` (`REPLICATES`, grounded) |

## Journey

1. Create `experiment.completed` + `replication.completed` events.
2. Replicating lab (issuer key) attests `result.confirmed` over the
   replication subject.
3. Ground with dataset evidence + `REPLICATES` edge.
4. Build a Proof: proposition "replication confirms result" + member sets.
5. Verify fresh (PASS under `lab_replication_v1`).

## What this proves about the engine

Methods, p-values, and labs are claim fields and metadata. Confirmation
is corroboration in the core's own terms (identical re-assertion stays
silent; divergence would record a conflict for policy to adjudicate).
