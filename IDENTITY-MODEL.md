# IDENTITY-MODEL.md — Contextual Identity Without an Identity Provider

> **Status:** Normative consolidation (2026-09-11). Sub-reference of
> `PROOF-ENGINE-SPEC.md` §§3.1, 12b. Answers master §§8–10: how external
> identity systems are represented without becoming mandatory.

---

## 1. Rule

Proof Engine is **not** an identity provider and holds no identity registry.
Entities are addressed by **opaque reference strings** (`subject`, `object`,
relationship endpoints) transported verbatim; the core never interprets
reference semantics. Reference-syntax recommendation (SHOULD):
`ref:<namespace>:<kind>:<id>` (`PROOF-ENGINE-SPEC.md` §3.1).

`identifier = universally trusted identity` is never assumed.

## 2. Mechanisms (all contextual, all policy-judged)

| Mechanism | Form | Honored when |
|---|---|---|
| `identity.bind` assertion | `claim.type="identity.bind"`, subject ≡ equivalent | Asserter is trust-listed AND link is ACTIVE (verified, timely, fresh status) |
| `EQUIVALENT` edge | Typed edge, identity-ref endpoints allowed | Grounded (backed by evidence/attestation) + trusted-asserter binding; shaped-but-unknown ids → `DANGLING` |
| `identity_bound{a,b}` leaf (policy v2) | BFS over bindings + grounded edges | Trusted-asserter path exists; untrusted asserters fail; reflexive |
| `delegate` chain (policy v2) | subject = grantee, opaque scope, ACTIVE links | Chain resolves from a trust-listed root; cycle-safe BFS; scope-exact when set |
| KeyRef registry | `key:<name>:` prefixes, single plug-point `KEYREF_PREFIXES` | `is_supported_keyref` funnel; `did:key:` and unknown prefixes fail closed today, plug in at exactly one place tomorrow |

Merging is **policy**, never transitive-by-core: expired/superseded bindings
merge nothing. Attacker-grounded mergers fail (untrusted asserter).

## 3. Pointers

`crates/proof-core/src/model.rs` (`RelType::EQUIVALENT`, `requires_grounding`);
`crates/proof-crypto/src/{claim.rs:identity.bind/delegate,keys.rs:registry}`;
`crates/proof-policy/src/{eval.rs:identity_path/delegation_chain,policy.rs:leaves}`;
`crates/proof-graph/src/lib.rs` (grounding/dangling/no-inflation);
`crates/proof-policy/tests/policy_v2.rs` (trusted path, untrusted fails,
reflexivity, 3-link chain, cycle-termination, scope tests);
`SECURITY-MODEL.md` T13b; `FREEZE-CANDIDATE.md` elevations 1–2.
