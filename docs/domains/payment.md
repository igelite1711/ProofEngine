# Domain: Payment (the reference instantiation)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. Proof that the engine is not a
> payment engine -- payments are what *this* domain does *with* the engine
> (`docs/domains/README.md`). Journey test: `domains/proof-domains/tests/payment.rs`.

## Vocabulary -> core mapping

| Payment noun | Core mapping |
|--------------|--------------|
| payment event | `Event` (`payment.created`) |
| invoice event | `Event` (`invoice.issued`) |
| "payment settled" claim | `Attestation` (`payment.settled`, fields `amount`/`currency`) |
| settlement receipt | `Evidence` (`transaction_record`) |
| settles relation | `Relationship` (`SETTLES`, grounded) |

## Journey

1. Create `PaymentCreated` + `InvoiceIssued` events.
2. Merchant (issuer key) attests `payment.settled` over the payment subject.
3. Ground with receipt evidence + `SETTLES` edge (backing evidence required).
4. Build a Proof: proposition "payment settles invoice" + member id sets.
5. Verify fresh (PASS under a permissive policy).
6. Re-evaluate under a stricter policy (failure) -- counterfactual proof of
   Evidence != Policy (golden-13/14 parallel).

## What this proves about the engine

Nothing here is engine logic: every token above is data in a domain test. The
mechanism crates contain no `payment` branch (PE-NEUT-001).
