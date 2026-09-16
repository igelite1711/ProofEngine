# Domain: Supply chain / manufacturing

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Batch production -> shipment
> with production record (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/supplychain.rs`.

## Vocabulary -> core mapping

| Supply-chain noun | Core mapping |
|--------------|--------------|
| production run | `Event` (`supplychain.batch.produced`) |
| shipment event | `Event` (`supplychain.batch.shipped`) |
| production assertion | `Attestation` over the batch subject |
| production record | `Evidence` (`receipt`, bound to the attestation) |
| production relation | `Relationship` (`PRODUCED`, grounded) |

## Journey

1. Create `produced` + `shipped` events for the batch subject.
2. Manufacturer (issuer key) attests over the production event id.
3. Ground with receipt evidence + `PRODUCED` edge.
4. Build a Proof: proposition "batch shipped" + member id sets.
5. Verify fresh (PASS under `supplychain_shipment_v1`).

## What this proves about the engine

Batches, plants, and lots are subjects and metadata. The identical edge
shape carries a shipment here, a delivery in logistics, and an execution
in legal — structure, never vocabulary.
