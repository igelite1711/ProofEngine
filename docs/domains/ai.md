# Domain: AI-Action Provenance (J-E')

> Request -> tool call -> attestation, as events + a grounded edge. AI is the
> *domain*, not a primitive: the engine core contains no `ai` branch (PE-NEUT-001).
> Journey: `domains/proof-domains/tests/ai.rs`.

## Vocabulary mapping

| AI noun | Core mapping |
|---------|----------------|
| user request | `Event` (`document.signed`) |
| tool call | `Event` (`ai.action.executed`) |
| request -> tool call | `Relationship` (`EXECUTED`, grounding required) |
| "assistant executed it" | `Attestation` (`ai.tool.executed`) |
| execution log | `Evidence` (`measurement` / `signed_event`) |

## Policy

```json
{
  "policy_version": 1,
  "policy_id": "tool_call_provenance_v1",
  "requirements": [{"type":"signature_valid"},
    {"type":"relationship_exists", "relationship": "EXECUTED"},
    {"type":"issuer_trusted", "issuer": "key:ed25519:..."},
    {"type":"not_revoked"}] }
```

The same policy shape answers "did the assistant actually execute the call?"
and "did the carrier actually ship the parcel?" - the engine never needs to
know which.
