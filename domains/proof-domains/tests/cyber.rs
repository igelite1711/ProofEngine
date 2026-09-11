// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cybersecurity response domain journey.
//! A detected intrusion alert mitigated by a released patch whose fixing
//! attestation is backed by a signed vulnerability report — proving the core
//! handles security telemetry, patch provenance, and incident response
//! without security-specific semantics. Domain DATA only (NEUTRALITY §2).

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

pub fn event_alert_raised(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("security.alert.raised"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xC1u8; 32]).unwrap(),
            metadata: vec![
                ("detector".into(), MetaValue::Text("ids-cluster-3".into())),
                ("severity".into(), MetaValue::Text("high".into())),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_patch_released(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("security.patch.released"),
            subject: subject.into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xC1u8; 32]).unwrap(),
            metadata: vec![
                ("channel".into(), MetaValue::Text("stable".into())),
                ("version".into(), MetaValue::Text("7.4.1".into())),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn fixes_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "security.patch.fixes".into(),
                fields: vec![
                    ("cve".into(), MetaValue::Text("CVE-2026-0001".into())),
                    ("rollout_pct".into(), MetaValue::Uint(100)),
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

pub fn vulnerability_report(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("vulnerability_report"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xC2u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn mitigates_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new("MITIGATES"),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let alert = event_alert_raised("soc:alert:a1");
    let patch = event_patch_released("soc:patch:p1");
    let att = fixes_attestation(&patch.id);
    let evd = vulnerability_report(&att.id);
    let edge = mitigates_edge(&patch.id, &alert.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "security.patch.mitigates-alert".into(),
            subject: "soc:patch:p1".into(),
            predicate: "mitigates".into(),
            object: Some("soc:alert:a1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(alert);
    b.add_event(patch);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "soc_mitigation_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": "MITIGATES"},
            {"type": "evidence_present", "kind": "vulnerability_report"},
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
