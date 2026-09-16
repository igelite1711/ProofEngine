//! Credential-lifecycle domain journey (identity vertical).
//! A credential grant whose revocation is expressed with a signed status
//! object — proving lifecycle enforcement (ACTIVE → REVOKED) is
//! industry-agnostic. Domain DATA only (NEUTRALITY §2).

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

pub fn event_credential_issued(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("credential.granted"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x11u8; 32]).unwrap(),
            metadata: vec![(
                "subject_id".into(),
                MetaValue::Text("did:example:123".into()),
            )],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_holder_registered(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("holder.registered"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x11u8; 32]).unwrap(),
            metadata: vec![],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn grant_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "credential.granted".into(),
                fields: vec![("level".into(), MetaValue::Text("l2".into()))],
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

pub fn registry_record(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("registry_entry"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x22u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn issuance_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new(RelType::ISSUED),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let cred = event_credential_issued("credential:c1");
    let holder = event_holder_registered("holder:h1");
    let att = grant_attestation(&cred.id);
    let evd = registry_record(&att.id);
    let edge = issuance_edge(&cred.id, &holder.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "credential.holds".into(),
            subject: "credential:c1".into(),
            predicate: "issued-to".into(),
            object: Some("holder:h1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(cred);
    b.add_event(holder);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "credential_issuer_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": RelType::ISSUED},
            {"type": "evidence_present", "kind": "registry_entry"},
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
