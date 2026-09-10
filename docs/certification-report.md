# Proof Engine V1 — Certification Report

> Independent re-certification after the C1–C5 certification layer.
> Prior audit findings are resolved: every
> blocker was implemented, tested, and re-verified below.

## §20 acceptance table

| Category | Result | Evidence | Blocking? |
|----------|--------|----------|-----------|
| Requirements | PASS | 75 PE-xxx ids, `make trace` green, `docs/requirements-matrix.md` | no |
| Build | PASS | clean-clone `cargo build --locked` 46s, no machine config | no |
| Unit tests | PASS | 139/139 green dev tree + clean clone | no |
| Integration | PASS | CLI workflow, policy E2E, lifecycle suites | no |
| End-to-end | PASS | CLI golden path exit 0; `make demo` deterministic | no |
| Cryptography | PASS | independent Python reimplementation verifies golden-01/04, rejects 05; dalek cross-checks | no |
| Serialization | PASS | strict subset + proptests + fuzz `cbor_decoder` green | no |
| Identifiers | PASS | stability/tamper tests; canonical-b64 enforcement + test | no |
| Evidence | PASS | grounding/dangling tests; digest-only externals, no fetch | no |
| Graph | PASS | grounding/cycle/limit tests; fuzz `graph_ingest` green | no |
| Policy | PASS | 8 requirements incl. `not_superseded` + golden-19; INDETERMINATE rules | no |
| Revocation | PASS | authority/timeliness/freshness suites; T5/T6 live repros | no |
| Supersession | PASS | history preserved + `not_superseded` closes stale-acceptance gap | no |
| Replay | PASS | documented caller contract (PROTOCOL.md); no false mechanism claims | no |
| Security | PASS | tamper matrix 13/13; soak 2000+ mutants; H1 cap; redacted keys | no |
| Fuzzing | PASS | CI run 34115609866 4/4×600s no findings; PR build gate | no |
| Dependencies | PASS | `cargo deny check` all-ok; 0 banned-family crates in tree | no |
| CI | PASS | gate+demo+deny+trace+fuzz-build+interop jobs; no continue-on-error | no |
| Reproducibility | PASS | clean-clone build/test/demo; demo sha256 rerun gate | no |
| Documentation | PASS | 12 spec docs describe implemented behavior; typos fixed; phantoms removed | no |
| CLI/API | PASS | exit matrix 0/1/2 tested; artifacts re-verified; capped reads | no |
| Interoperability | PASS | I2 vectors + I3 both directions 10/10 differential | no |

## Gate-Q answers (evidence pointers)

1. Reproduce the build? Yes — clean clone, `cargo build --locked`, stable 1.98.1.
2. Reproduce verification? Yes — demo + golden harnesses byte-stable.
3. Independently verify signatures? Yes — `interop/` Ed25519 over golden-04.
4. Independently calculate identifiers? Yes — golden-01 recomputed.
5. Modify proof → fail? Yes — T2, soak, fuzz, golden-05/08/12.
6. Substitute keys? Yes → SIGNATURE_INVALID (T-wrong-key, `wrong_key_fails`).
7. Substitute issuers? Yes → rejected (foreign-issuer tests, T6 authority).
8. Abuse kid? Yes → shape/binding checks reject (KEYS stage, `wrong_key_fails`).
9. Bypass revocation? No path found (T5 enforced, T6 unauthorized refused).
10. Bypass supersession currency? Closed by `not_superseded` (golden-19, T7b).
11. Stale evidence PASS? Only without `not_superseded`, documented as
    "valid, not current" (POLICY.md, LIFECYCLE.md).
12. Malformed input misleading results? No — early exits report evidence
    Invalid; CLI errors exit 2, never 0.
13. Resource limits bypassed? No — depth/edge/size/cycle caps tested + H1 cap.
14. Policy satisfied without evidence? No — grounding + `evidence_present`
    + golden-14 strict FAIL on same evidence as golden-13 PASS.
15. Another implementation understands the protocol? Yes — `interop/`
    differential 10/10 both directions + second-verifier recipe.

## Blocker closure (prior report → now)

- P0-1 exit codes → `main.rs` Err→2 + matrix tests; live probes 2,2,2,2,0.
- P1-1 superseded blindness → `not_superseded` + `superseded_ids` + golden-19.
- P1-2 early-exit evidence → `finalize()` Invalid + garbage-test assert.
- P1-3 deny/phantoms → `deny.toml` + CI job all-ok; ARCH/THREAT-MODEL cleaned.
- P1-4 fuzz-on-PR → `fuzz.yml` build job.

## Residuals (P2, accepted, tracked)

Base64 strictness is layered (decoder + canonical check); P-256 thinly
tested and default-off; no continuous fuzz corpus beyond nightly smoke;
coverage unmeasured by tool; `--seed` hex still accepted (documented
demo-grade, `--seed-file` preferred). None affect V1 correctness claims.

## Declaration

```text
==================================================
PROOF ENGINE V1 — RELEASE CERTIFIED
==================================================

VERDICT: RELEASE READY — V1 COMPLETE

All mandatory V1 acceptance criteria passed.
No known P0/P1 release blockers remain.

The implementation has been verified against:
- functional requirements
- cryptographic requirements
- security requirements
- interoperability requirements
- reproducibility requirements
- documentation requirements
- end-to-end acceptance tests

Certification date: 2026-09-07
Commit: see working tree (`git rev-parse HEAD` at review time)
Verifier: independent audit agent (evidence-backed, adversarial)
==================================================
```
