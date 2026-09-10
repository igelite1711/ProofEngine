# Proof Engine — Domain Mapping Guide (V1)

> How ANY industry maps its nouns onto the five neutral primitives, the ten
> relationship types, and the generic policy language — without touching the
> engine. The core knows no industry; every industry shown below is an
> *instantiation*, not a specialization. Each mapping is exercised by real
> tests in `domains/proof-domains/tests/` (see `PE-NEUT-*`).

## The base vocabulary (neutral, defined in `proof-core`)

| Primitive | Id prefix | Role |
|-----------|-----------|------|
| Event | `evt:v1:` | unsigned happening-record: type, subject, effective time, payload digest, metadata |
| Attestation | `att:v1:` | issuer-signed claim over a subject + validity window |
| Evidence | `evd:v1:` | digest-bound external reference (+ optional attestation ref/hint) |
| Relationship | `rel:v1:` | typed directed edge from→to (+ optional backing evidence/attestation) |
| Proof | `prf:v1:` | proposition + sorted member id sets + canonical bytes |

| RelType | Typical industry reading |
|----------|----------------------------|
| OWNS | holds / controls / is responsible for |
| CREATED | produced / generated / initiated (grounding required) |
| SETTLES | discharges / satisfies / clears (grounding required) |
| REFERENCES | cites / points at / evidences |
| CONTAINS | bundles / embeds / lists |
| PRODUCED | emitted by / output of |
| EXECUTED | performed / ran / executed by (grounding required) |
| ISSUED | granted / issued by / attested by |
| SUPERSEDES | replaces / supersedes (its own semantics: currency) |
| REVOKES | invalidates / retracts / withdraws |

## The mapping recipe (universal)

1. **Nouns → subjects.** People, orgs, machines, accounts, documents,
   datasets, devices, services, processes, events, licenses, models,
   payloads → stable subject/object ids (external ids or keyrefs; the engine
   stores references, not semantics).
2. **Events → happening-records.** "X happened" (signed later by an
   attestation, never trusted by default): created, signed, executed,
   observed, sent, received, granted, revoked.
3. **Claims → attestations.** "Who asserts what about which subject, when,
   until when?" → `claim_type` (industry string,e.g. `license.granted`),
   scalar `fields` (the facts), issuer keyref, validity window.
4.. **Backing material → evidence.** Digests of payloads/docs/records/system
   outputs/how logs; kinds are generic (`transaction_record`, `signed_document`,
   `measurement`, `credential`, …).
5.. **Connections → relationships.** Typed edges with optional grounding
   (trust-relevant edges require evidence/attestation backing).
6.. **Rules → policies.** A JSON policy over the closed requirement set
   (`signature_valid`, `issuer_trusted`, `issuer_excluded`, `relationship_exists`,
   `not_expired`, `not_revoked`, `not_superseded`, `evidence_present`,
   `transparency_present`). Industries express *their* rules via these
   generic knobs — never new engine code.## Worked mappings (each proven by a domain journey test)

### 1. Payment (reference -- `payment.rs`)

| Domain noun | Engine mapping |
|-------------|----------------|
| payment / invoice | two Events (`payment.created`, `invoice.issued`) |
| merchant\'s statement "paid" | `Attestation` claim_type `payment.settled`, fields `amount`/`currency`, issuer = merchant key |
| settlement record | `EvidenceKind::TransactionRecord`, digest of receipt |
| "payment settles invoice" | `RelType::SETTLES` edge (grounded by the evidence) |
| policy | merchant-shaped requirements (trusted issuer + SETTLES + not_expired + not_revoked) |

### 2. Credential lifecycle (identity -- `credential.rs`)

| Domain noun | Engine mapping |
|-------------|----------------|
| credential issuance | `Event(document.signed)` + `Attestation` claim_type `credential.active`, issuer = authority key |
| the credential itself | `EvidenceKind::Credential` (digest of the credential payload) |
| authority grants to holder | `RelType::ISSUED` edge authority-issued->credential |
| expiry | attestation `expires_at` -> lifecycle `EXPIRED` at verifier clock |
| reissue / replacement | second attestation + `RelType::SUPERSEDES` -> old is historically valid, not current (`not_superseded`) |
| blocked/sanctioned issuer | `issuer_excluded` requirement -> listed issuer fails closed even when the chain is otherwise valid |

### 3. Media provenance `media.rs`

| Domain noun | Engine mapping |
|-------------|----------------|
| license grant | `Attestation` claim_type `license.granted`, issuer = rights-holder, subject = license id; `RelType::ISSUED` edge |
| deepfake response / takedown | signed `revoke` status over the PSA attestation -> lifecycle `REVOKED` -> downstream policy fails |
| transcode chain | three Events (`document.signed` master, h264, hls), `RelType::PRODUCED` edges (master->h264->hls) |
| provenance record | `EvidenceKind::SignedDocument`, digest of the manifest |

### 4. AI-action provenance `ai.rs`

| Domain noun | Engine mapping |
|-------------|----------------|
| user request | `Event(document.signed)`, payload digest of the request |
| request -> tool call | second `Event(ai.action.executed)`, subject = tool-call id; `RelType::EXECUTED` edge (grounding required -- backed by evidence) |
| "the assistant executed it" | `Attestation` claim_type `ai.tool.executed`, issuer = the AI system operator key |
| observation log | `EvidenceKind::Measurement` (or `SignedEvent`), digest of the execution log |
| policy | `relationship_exists(EXECUTED)` + `issuer_trusted` + `not_revoked` |
## Spot checks (same recipe, no new mechanism)

| Industry | nouns -> mapping |
|----------|---------------------|
| Healthcare | lab result = `Event` + `EvidenceKind::Measurement`; order = `Event`; "clinician attested result" = `Attestation` + `ISSUED`; HIPAA-style rules = policy |
| Supply chain | PO/shipment/receipt = Events; "carrier shipped" = `Attestation` + `EXECUTED` edge; lot record = `EvidenceKind::TransactionRecord` |
| Software SBOM | source = `Event`; build = `Attestation` + `PRODUCED`; artifact = `EvidenceKind::SignedDocument`; release signer = `Attestation` + `ISSUED` |
| IoT sensing | device observation = `Event` + `EvidenceKind::Measurement`; device attestation = `EvidenceKind::DeviceAttestation`; "device is authorized" = policy + `issuer_trusted` |

## Governance rule(enforced by `make neutrality`)

Domain vocabulary -- and *domain branches* -- MAY appear:

- as wire *labels* in the closed enums (`model.rs`),
- in tests (`#[cfg(test)]`, `*/tests/`, `domains/proof-domains/tests/`),
- in fixtures (`pub mod fixtures`, golden vectors),
- in the demo (`proof-cli/src/demo.rs` -- the V1 reference application),
- in `docs/`.

It MUST NOT appear as logic in mechanism crate sources (`tools/check_neutrality.py`).

## Truth-between-layers

Same core, four industries, one code path: the differential test
(`domains/proof-domains/tests/differential.rs`) verifies four unrelated journeys
produce *identical* report shapes -- neutrality by construction, not by
prose (PE-NEUT-003).
