# ARCHITECTURE-CHANGE-PROPOSAL TEMPLATE (freeze-reopen procedure, §54)

> Copy to `docs/ARCHITECTURE-CHANGE-PROPOSAL-<topic>.md` and complete every
> section. A proposal that cannot answer all sections is not ready. Only a
> genuine foundational deficiency may reopen `ARCHITECTURE-FREEZE.md` §2.

## 1. Requirement

What must be representable, and for whom? (One paragraph, no solution.)

## 2. Why existing primitives cannot represent it

Show the attempted encoding with current primitives/relationships/extensions
and exactly where it fails (bytes, verification, or policy).

## 3. Affected semantics

Which frozen element (F1–F11) changes, and precisely how? Old vs new meaning
for identical historical bytes.

## 4. Security implications

Threats introduced/removed (forgery, confusion, downgrade, replay,
resource, parser-differential). Fuzz + negative-matrix plan.

## 5. Compatibility implications

Version boundary, dual-verify window, golden-vector additions (append-only),
second-implementation impact, 2126 interpretability of old proofs.

## 6. Migration requirements

Tooling, conversion rules, what happens to proofs written before the change.
Migration ≠ reinterpretation: state both.

## 7. Alternatives considered

At least one extension/adapter/profile/application design, and why it is
insufficient (with evidence, not assertion).

## 8. Extension-based solution attempted

What was prototyped outside the core, and the measured shortfall.

## 9. Independent verification impact

Changes required in `interop/` + differential checks; second-implementer
recipe updates.

## 10. Long-term durability impact

Why this change, once frozen, will not need reopening again in a decade.

## 11. Decision

Maintainer verdict + date + new freeze pin (commit, vectors, checks).
