# Domain: Legal (document execution)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Draft -> signature with
> execution record (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/legal.rs`.

## Vocabulary -> core mapping

| Legal noun | Core mapping |
|--------------|--------------|
| draft event | `Event` (`legal.document.drafted`) |
| signing event | `Event` (`legal.document.signed`) |
| execution assertion | `Attestation` over the draft subject |
| execution record | `Evidence` (`receipt`, bound to the attestation) |
| execution relation | `Relationship` (`PRODUCED`, grounded) |

## Journey

1. Create `drafted` + `signed` events for the document subject.
2. Signatory (issuer key) attests over the draft event id.
3. Ground with receipt evidence + `PRODUCED` edge.
4. Build a Proof: proposition "document executed" + member id sets.
5. Verify fresh (PASS under `legal_execution_v1`).

## What this proves about the engine

Signatures-in-the-legal-sense, parties, and authorization are domain
readings of attestations and edges. Supersession (a new document replacing
an old one) reuses the core lifecycle, not legal logic.
