# PROVENANCE-MODEL.md — Lineage as Topology Plus Bindings

> **Status:** Normative consolidation (2026-09-11). Sub-reference of
> `PROOF-ENGINE-SPEC.md` §§7–9. Answers master §§14–16: how origin,
> transformation, dependency, and composition lineage are first-class
> without domain semantics.

---

## 1. Rule

Provenance is **topology plus cryptographic bindings**, never narrative.
The core validates that lineage structure is well-formed and tamper-evident;
what lineage *means* is domain policy. No AI/creator/royalty/token semantics
live in the core.

## 2. Mechanisms

| Mechanism | Guarantees |
|---|---|
| Typed edges (12 well-known + open) + grounding | Trust-relevant edges (`OWNS/CREATED/SETTLES/EXECUTED/EQUIVALENT/CONTRADICTS` + `extra_grounded`) carry backing evidence; bare edges of other kinds ride as asserted structure |
| `referenced_proofs` linkage | Sorted, deduped, `proof_id`-bound composition references; linkage-only (content never embedded/fetched, always `REFERENCED` never `VERIFIED`); empty = byte-identical V1 |
| `Bundle` + `CONTAINS` + `ArtifactStore` | Ordered sibling proofs + optional blobs + status objects; reference-availability matrix (`PRESENT/REFERENCED/UNAVAILABLE`) at the bundle layer |
| Provenance dimension | `GRAPH` + composition records projected to `VALID/INVALID/NOT_APPLICABLE` alongside the frozen triple |
| Conflicts as lineage | `divergent_claims`/`denial`/`contradiction` records preserve who asserted what, when — validity unchanged, adjudication in policy v2 |

Transitive cross-bundle resolution (fetch-and-verify chains, depth
accounting, ancestry/descendant traversal APIs) is explicitly V2: it needs
resolver traits + transport, not new semantics.

## 3. Pointers

`crates/proof-graph/src/lib.rs` (`validate_graph_with_grounding`);
`crates/proof-format/src/{bundle.rs,envelope.rs,store.rs}`;
`crates/proof-verify/src/{pipeline.rs:RELATIONSHIPS/GRAPH/composition,report.rs:dimensions/conflicts}`;
`crates/proof-policy/tests/policy_v2.rs` (adjudication);
`fixtures/golden-24/25/26` (linkage) + `golden-28` (conflict quorum);
`FREEZE-CANDIDATE.md` elevation 5 + §4 perimeter.
