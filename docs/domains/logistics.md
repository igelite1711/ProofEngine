# Domain: Logistics (chain of custody)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Dispatch -> delivery with
> receipt evidence (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/logistics.rs`.

## Vocabulary -> core mapping

| Logistics noun | Core mapping |
|--------------|--------------|
| dispatch scan | `Event` (`logistics.shipment.dispatched`, metadata `origin`) |
| delivery scan | `Event` (`logistics.shipment.delivered`, metadata `dest`) |
| custody assertion | `Attestation` over the dispatch subject |
| handover receipt | `Evidence` (`receipt`, bound to the attestation) |
| custody relation | `Relationship` (`PRODUCED`, grounded) |

## Journey

1. Create `dispatched` + `delivered` events for the shipment subject.
2. Carrier (issuer key) attests over the dispatch event id.
3. Ground with receipt evidence + `PRODUCED` edge.
4. Build a Proof: proposition "shipment delivered" + member id sets.
5. Verify fresh (PASS under `logistics_delivery_v1`).

## What this proves about the engine

Custody, carriers, ports, and hubs are labels on events and metadata. The
same `PRODUCED` edge and receipt pattern serves manufacturing and legal
journeys unchanged.
