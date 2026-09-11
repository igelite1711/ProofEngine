// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scientific replication domain journey.
//! An experiment result confirmed by an independent replication whose
//! confirming attestation is backed by the replication dataset — proving the
//! core handles research claims, independent confirmation, and dataset
//! provenance without science-specific semantics. Domain DATA only
//! (NEUTRALITY §2).

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

pub fn event_experiment_completed(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("research.experiment.completed"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xD1u8; 32]).unwrap(),
            metadata: vec![
                ("method".into(), MetaValue::Text("double-blind".into())),
                ("sample_n".into(), MetaValue::Uint(1200)),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_replication_completed(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("research.replication.completed"),
            subject: subject.into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xD1u8; 32]).unwrap(),
            metadata: vec![
                ("lab".into(), MetaValue::Text("independent-lab-2".into())),
                ("sample_n".into(), MetaValue::Uint(800)),
            ],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn confirms_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "research.result.confirmed".into(),
                fields: vec![
                    ("effect".into(), MetaValue::Text("reproduced".into())),
                    ("p_value".into(), MetaValue::Text("0.03".into())),
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

pub fn replication_dataset(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("dataset"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xD2u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn replicates_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new("REPLICATES"),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let experiment = event_experiment_completed("lab:experiment:e1");
    let replication = event_replication_completed("lab:replication:r1");
    let att = confirms_attestation(&replication.id);
    let evd = replication_dataset(&att.id);
    let edge = replicates_edge(&replication.id, &experiment.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "research.replication.confirms-result".into(),
            subject: "lab:replication:r1".into(),
            predicate: "confirms".into(),
            object: Some("lab:experiment:e1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(experiment);
    b.add_event(replication);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "lab_replication_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": "REPLICATES"},
            {"type": "evidence_present", "kind": "dataset"},
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
