# Domain: Sensor calibration (physical-world vertical)

> Mapping: BUSINESS TERM -> NEUTRAL PRIMITIVE. A device calibration event
> whose attestation is backed by a lab calibration certificate — the core
> handling hardware identity, physical measurement, and device provenance
> (`docs/domains/README.md`). Journey test: `domains/proof-domains/tests/sensor.rs`.

## Vocabulary -> core mapping

| Sensor noun | Core mapping |
|--------------|--------------|
| device registration | `Event` (`sensor.device.registered`, metadata `model`/`serial`) |
| measurement | `Event` (`sensor.measurement.recorded`, metadata `unit`/`value`) |
| "sensor calibrated" claim | `Attestation` (`sensor.calibrated`, fields `standard`/`interval_days`) |
| calibration certificate | `Evidence` (`calibration_certificate`, bound to the attestation) |
| calibrated-by relation | `Relationship` (`CALIBRATED_BY`, grounded) |

## Journey

1. Create `device.registered` + `measurement.recorded` events.
2. Lab (issuer key) attests `sensor.calibrated` over the device subject.
3. Ground with calibration-certificate evidence + `CALIBRATED_BY` edge.
4. Build a Proof: proposition "measurement calibrated" + member id sets.
5. Verify fresh (PASS under `sensor_calibration_v1`).

## What this proves about the engine

Physical devices, NIST-traceable standards, and units of measure are all
data: no device, physics, or metrology concept lives in the mechanism
crates (PE-NEUT-001).
