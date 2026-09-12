# Domain: Cybersecurity (incident response)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. A detected intrusion alert
> mitigated by a released patch, backed by a signed vulnerability report
> (`docs/domains/README.md`). Journey test:
> `domains/proof-domains/tests/cyber.rs`.

## Vocabulary -> core mapping

| Security noun | Core mapping |
|--------------|--------------|
| intrusion alert | `Event` (`security.alert.raised`, metadata `severity`/`detector`) |
| patch release | `Event` (`security.patch.released`, metadata `version`/`channel`) |
| "patch fixes" claim | `Attestation` (`security.patch.fixes`, fields `cve`/`rollout_pct`) |
| vulnerability report | `Evidence` (`vulnerability_report`, bound to the attestation) |
| mitigation relation | `Relationship` (`MITIGATES`, grounded) |

## Journey

1. Create `alert.raised` + `patch.released` events.
2. Vendor (issuer key) attests `patch.fixes` over the patch subject.
3. Ground with vulnerability-report evidence + `MITIGATES` edge.
4. Build a Proof: proposition "patch mitigates alert" + member id sets.
5. Verify fresh (PASS under `soc_mitigation_v1`).

## What this proves about the engine

Alerts, CVEs, and rollouts are telemetry shaped as events and claims.
Severity never becomes engine logic: triage thresholds belong in policy,
and a compromised detector would be handled by lifecycle markings, not
special cases.
