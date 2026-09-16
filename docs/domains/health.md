# Domain: Health (consent-gated records)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Record creation gated by
> patient consent (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/health.rs`.

## Vocabulary -> core mapping

| Health noun | Core mapping |
|--------------|--------------|
| record creation | `Event` (`health.record.created`) |
| consent grant | `Event` (`health.consent.granted`) |
| consent assertion | `Attestation` over the record subject |
| consent receipt | `Evidence` (`receipt`, bound to the attestation) |
| consent relation | `Relationship` (`PRODUCED`, grounded) |

## Journey

1. Create `record.created` + `consent.granted` events.
2. Provider (issuer key) attests over the record event id.
3. Ground with receipt evidence + `PRODUCED` edge.
4. Build a Proof: proposition "consent granted" + member id sets.
5. Verify fresh (PASS under `health_consent_v1`).

## What this proves about the engine

Consent, patients, and providers are policy-scoped readings: the engine
binds who asserted what and when, while access rules live in the caller's
policy. No health concept enters the mechanism crates (PE-NEUT-001).
