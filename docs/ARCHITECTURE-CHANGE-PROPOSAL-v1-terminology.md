# ARCHITECTURE-CHANGE-PROPOSAL: V1 terminology conformance (human strings only)

> Class: DOCUMENTATION (zero behavior change). Frozen wire codes, ids, bindings,
> verification order, verdicts, lifecycle, policy semantics untouched. Only human
> messages/comments saying "V0.1" become "V1" to match the shipped V1 promise.
> Maintainer decision: APPROVED pre-V1.0 (external review L1, 2026-09-13).

## 1. Requirement

Human messages must name the shipped version (V1), not the draft (V0.1), so
operators and auditors are not misled about which contract they run.

## 2. Why existing primitives cannot represent it

N/A (documentation, not representability). Extension/adapter cannot rewrite
human strings inside frozen crates.

## 3. Affected semantics

None. F1–F11 unchanged. Wire codes (`MALFORMED`, `FORBIDDEN_CBOR_CONSTRUCT`,
etc.) unchanged; only `message` text after the code changes (messages are
explicitly mutable per ERROR-MODEL.md). Ids, bindings, stages, verdicts identical.

## 4. Security implications

None (messages never trusted; codes drive automation). Reduces confusion-driven
misconfiguration (residual top-3 #3).

## 5. Compatibility implications

No version boundary. Golden vectors assert codes + validity, not message substrings
(verified by grep before landing). Second implementations match on codes/bytes.

## 6. Migration requirements

None. Old proofs verify identically; only stderr prose changes.

## 7. Alternatives considered

Leave stale strings: rejected (perpetuates V0.1/V1 confusion flagged in review).

## 8. Extension-based solution attempted

N/A.

## 9. Independent verification impact

None (interop matches on codes/bytes, not prose).

## 10. Long-term durability impact

One-time rename; future code must say V1 (enforced by review).

## 11. Decision

APPROVED 2026-09-13 (architect, pre-V1.0 external-review hardening). Pin re-evaluated
at release; change recorded in docs/freeze-manifest.json as DOCUMENTATION.
