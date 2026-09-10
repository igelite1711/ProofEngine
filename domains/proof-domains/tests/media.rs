//! Media-licensing domain journey (media provenance vertical).
//! A licensed work whose ownership edge uses the domain vocabulary
//! `RIGHTS_TRANSFERRED` for the relationship label (a well-known grounding
//! type is deliberately NOT reused here: domain labels are free strings) and
//! `license_certificate` for the evidence kind. Domain DATA only.

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

pub fn event_work_registered(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("media.work.registered"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x33u8; 32]).unwrap(),
            metadata: vec![("title".into(), MetaValue::Text("Scene 42".into()))],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_license_granted(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("media.license.granted"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x33u8; 32]).unwrap(),
            metadata: vec![],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn rights_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "media.license.granted".into(),
                fields: vec![("territory".into(), MetaValue::Text("EU".into()))],
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

pub fn license_certificate(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("license_certificate"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x44u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn rights_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new("RIGHTS_TRANSFERRED"),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let work = event_work_registered("media:work:w1");
    let lic = event_license_granted("media:license:l1");
    let att = rights_attestation(&work.id);
    let evd = license_certificate(&att.id);
    let edge = rights_edge(&work.id, &lic.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "media.license.covers".into(),
            subject: "media:work:w1".into(),
            predicate: "licensed-under".into(),
            object: Some("media:license:l1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(work);
    b.add_event(lic);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "licensing_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": "RIGHTS_TRANSFERRED"},
            {"type": "evidence_present", "kind": "license_certificate"},
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
