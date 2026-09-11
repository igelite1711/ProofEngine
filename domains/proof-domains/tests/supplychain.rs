//! Supply-chain domain journey (manufacturing vertical). Domain DATA only.

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, CreatedAttestation,
    CreatedEvent, CreatedRelationship,
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

pub fn journey() -> BuiltProof {
    let lim = Limits::default();
    let e1 = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("supplychain.batch.produced"),
            subject: "batch:b77".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x44u8; 32]).unwrap(),
            metadata: vec![("origin".into(), MetaValue::Text("port-a".into()))],
        },
        &lim,
    )
    .unwrap();
    let e2 = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("supplychain.batch.shipped"),
            subject: "batch:b77".into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x55u8; 32]).unwrap(),
            metadata: vec![("dest".into(), MetaValue::Text("hub-b".into()))],
        },
        &lim,
    )
    .unwrap();
    let att: CreatedAttestation = attest(
        fixtures::fixed_attestation_content(issuer(), &e1.id),
        issuer_key(),
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new("receipt"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x66u8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge: CreatedRelationship = make_relationship(
        Relationship {
            v: 1,
            from: e1.id.clone(),
            rel_type: RelType::new(RelType::PRODUCED),
            to: e2.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "supplychain.batch.shipped".into(),
            subject: e1.id.clone(),
            predicate: "produced".into(),
            object: Some(e2.id.clone()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(e1);
    b.add_event(e2);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&lim).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "supplychain_shipment_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": RelType::PRODUCED},
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

#[allow(dead_code)]
pub fn _shapes(e: CreatedEvent, a: CreatedAttestation, r: CreatedRelationship) {
    let _ = (e, a, r);
}
