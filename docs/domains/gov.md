# Domain: Government (permit workflow)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Application -> permit
> issuance (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/gov.rs`.

## Vocabulary -> core mapping

| Government noun | Core mapping |
|--------------|--------------|
| application event | `Event` (`gov.permit.applied`) |
| issuance event | `Event` (`gov.permit.issued`) |
| issuance assertion | `Attestation` over the application subject |
| issuance record | `Evidence` (`receipt`, bound to the attestation) |
| issuance relation | `Relationship` (`PRODUCED`, grounded) |

## Journey

1. Create `applied` + `issued` events for the permit subject.
2. Authority (issuer key) attests over the application event id.
3. Ground with receipt evidence + `PRODUCED` edge.
4. Build a Proof: proposition "permit issued" + member id sets.
5. Verify fresh (PASS under `gov_permit_v1`).

## What this proves about the engine

Permits, citizens, and agencies are subjects and labels. Authorization
chains (office delegates to officer) would reuse generic `delegate`
links — no government model in the core.
