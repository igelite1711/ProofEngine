# SECURITY.md

> V1 guarantee statements within the `THREAT-MODEL.md` scope. The consolidated
> view (threats, mitigations, residuals) is `SECURITY-MODEL.md`; on semantics
> `PROOF-ENGINE-SPEC.md` §18 wins.

## What this software guarantees (V1.0)

Within the trust model of `THREAT-MODEL.md`, and given an honest verifier
clock and an honest revocation-information source, the engine guarantees:

1. **Tamper evidence.** Any modification of the bytes a proof id covers —
   the proposition, event/attestation/evidence/relationship member sets and
   their contents — fails verification, even one bit. Ids are recomputed from
   canonical bytes (`ID_MISMATCH`); signatures are checked against the key
   named in the COSE header (`SIGNATURE_INVALID`). One documented exception:
   the proof's own `created_at` field is informational (FORMAT.md §6) and
   deliberately outside the id binding, so mutating it does not change any
   verification decision; a mutation-soak test
   (`crates/proof-verify/tests/soak.rs`) pins this boundary from both sides —
   every covered byte fails closed, the informational field does not.
2. **No unsigned trust statements.** An attestation is trusted only if its
   signature verifies, its issuer equals the signing key's KeyRef, and a
   caller-supplied policy lists that issuer. A valid signature alone never
   yields PASS.
3. **Deterministic decisions.** Same bytes + same inputs → same report, same
   policy outcome, same explanation, byte-for-byte (enforced by tests).
4. **Bounded resources.** Size, depth, entry, and item limits are enforced
   before allocation-heavy work (`LIMIT_EXCEEDED`); graphs reject cycles in
   SUPERSEDES (`CYCLE_DETECTED`).
5. **Fail closed.** Unknown versions, unknown or deprecated algorithms,
   non-canonical encodings, duplicate map keys, stale/missing revocation
   info, unauthorized revokers: all produce failures with stable codes, never
   a silent PASS.

## What this software does NOT guarantee (V1.0)

- **Freshness of revocation information.** The engine evaluates revocation
  status only against status objects the *caller* supplies, as of the
  timestamp the caller asserts. Stale or absent info → `REVOCATION_UNKNOWN`
  → FAIL, but "no status objects supplied" is a caller decision, not a
  guarantee.
- **Clock honesty.** All time checks use the caller-provided `--clock`.
  A lying clock produces garbage-in/garbage-out verdicts (bounded by the
  skew leeway for drift, not for lies).
- **Key custody.** `--seed` handling in the CLI is for demos/tests. Production
  key management (keystores, HSMs, rotation) is out of scope.
- **External evidence.** Evidence content lives outside the proof (digests
  only). Nothing here fetches, stores, or vouches for external content.
- **Confidentiality.** Artifacts are unsigned-in-transit files; transport
  encryption and access control belong to the caller.
- **Network/DB isolation claims** for deployments that add Phase 8 adapters
  (not present in V1.0).

## Reporting a vulnerability

**Do not open a public issue for exploitable findings.**

Report privately via GitHub's *Security → Report a vulnerability* (private
vulnerability reporting) on
[igelite1711/ProofEngine](https://github.com/igelite1711/ProofEngine/security),
or contact the maintainers directly if that is unavailable.

Include: affected crate/version or commit, a minimal repro (input bytes + the
exact command), and expected vs. actual verdict. For anything touching
signature handling, canonical encoding, id binding, or the policy engine, say
so explicitly — those are the trust-critical paths.

You will get an acknowledgement within 7 days and a triage decision within 14.
Please allow 90 days for a fix before public disclosure. Fixes land on the
main branch and are noted in `docs/phase*-report.md` and release notes, with
credit in the changelog unless you prefer to stay anonymous.

## Verification of a release

Follow `VERIFICATION.md`: run `make demo`, the full test suite, the golden
vector gate, and the nightly fuzz smoke (see `.github/workflows/fuzz.yml`; latest green run id recorded in CI).
A release whose `report.json`
outputs differ byte-for-byte from a previous build of the same version
indicates non-determinism — treat as a defect.
