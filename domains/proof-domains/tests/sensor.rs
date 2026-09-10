// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sensor calibration domain journey (physical-world vertical).
//! A device calibration event whose attestation is backed by a lab
//! calibration certificate — proving the core handles hardware
//! identity, physical measurement, and device provenance. Domain DATA
//! only (NEUTRALITY §2).

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, make_evidence, make_relationship, CreatedAttestation, CreatedEvent,
    CreatedRelationship,
};
use proof_verify::BuiltProof;
use std::sync::OnceLock;

pub const CLOCK_OK: u64 = 1_700_000_200;

pub fn issuer_key() -> &'static proof_crypto::Ed25519Key {
    static KEY: OnceLock<proof_crypto::Ed25519Key> = OnceLock::new();
    KEY.get_or_init(proof_crypto::build::fixtures::test_key)
}

pub fn issuer() -> &'static str {
    static ISSUER: OnceLock<String> = OnceLock::new();
    ISSUER.get_or_init(|| issuer_key().key_ref())
}

pub fn event_device_registered(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("sensor.device.registered"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x77u8; 32]).unwrap(),
            metadata: vec![
                ("model".into(), MetaValue::Text("thermocouple-tc4".into())),
                ("serial".into(), MetaValue::Text("SN-2026-042".into())),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_measurement_recorded(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("sensor.measurement.recorded"),
            subject: subject.into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x77u8; 32]).unwrap(),
            metadata: vec![
                ("unit".into(), MetaValue::Text("celsius".into())),
                ("value".into(), MetaValue::Text("36.8".into())),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn calibration_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "sensor.calibrated".into(),
                fields: vec![
                    ("standard".into(), MetaValue::Text("NIST-traceable".into())),
                    ("interval_days".into(), MetaValue::Uint(365)),
                ],
            },
            issued_at: 1_700_000_100,
            expires_at: Some(1_800_000_000),
            evidence_ref: None,
        },
        issuer_key(),
        &Limits::default(),
    )
    .unwrap()
}

pub fn calibration_certificate(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("calibration_certificate"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x88u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn calibrated_by_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new("CALIBRATED_BY"),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let device = event_device_registered("sensor:device:d1");
    let measurement = event_measurement_recorded("sensor:measurement:m1");
    let att = calibration_attestation(&device.id);
    let evd = calibration_certificate(&att.id);
    let edge = calibrated_by_edge(&device.id, &measurement.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "sensor.measurement.calibrated".into(),
            subject: "sensor:measurement:m1".into(),
            predicate: "measured-by".into(),
            object: Some("sensor:device:d1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(device);
    b.add_event(measurement);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "sensor_calibration_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": "CALIBRATED_BY"},
            {"type": "evidence_present", "kind": "calibration_certificate"},
            {"type": "not_expired"},
            {"type": "not_revoked"}
        ]
    })
}

pub fn inputs() -> proof_policy::EvalInputs {
    proof_policy::EvalInputs {
        trusted_issuers: vec![issuer().to_string()],
        verified_at: CLOCK_OK,
        ..proof_policy::EvalInputs::default()
    }
}

/// Recompute the journey's attestation id exactly as the pipeline does.
pub fn attestation_id() -> String {
    let j = journey();
    let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(
        &j.proof.attestations[0].content,
    ));
    proof_crypto::id::attestation_id(&canon)
}
