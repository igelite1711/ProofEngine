//! Election domain journey (election vertical). Domain DATA only.
//!
//! Ballot batch cast → counted → tally certified: a three-event chain with
//! two grounded PRODUCED edges, one election-authority attestation, and
//! pollbook evidence. Exercises chain length > 2 plus the `evidence_present`
//! leaf in a new vocabulary — the verdict shape must still be identical.

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
            event_type: EventType::new("election.ballot.cast"),
            subject: "ballot:batch-b12".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x41u8; 32]).unwrap(),
            metadata: vec![("precinct".into(), MetaValue::Text("p-07".into()))],
        },
        &lim,
    )
    .unwrap();
    let e2 = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("election.ballot.counted"),
            subject: "ballot:batch-b12".into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x42u8; 32]).unwrap(),
            metadata: vec![("tabulator".into(), MetaValue::Text("t-03".into()))],
        },
        &lim,
    )
    .unwrap();
    let e3 = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("election.tally.certified"),
            subject: "contest:mayor-2026".into(),
            effective_at: 1_700_000_090,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x43u8; 32]).unwrap(),
            metadata: vec![("canvass".into(), MetaValue::Text("final".into()))],
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
        EvidenceKind::new("pollbook_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x44u8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge1: CreatedRelationship = make_relationship(
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
    let edge2: CreatedRelationship = make_relationship(
        Relationship {
            v: 1,
            from: e2.id.clone(),
            rel_type: RelType::new(RelType::PRODUCED),
            to: e3.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "election.tally.certified".into(),
            subject: e1.id.clone(),
            predicate: "produced".into(),
            object: Some(e3.id.clone()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(e1);
    b.add_event(e2);
    b.add_event(e3);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge1);
    b.add_relationship(edge2);
    b.build(&lim).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "election_certification_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": RelType::PRODUCED},
            {"type": "evidence_present", "kind": "pollbook_record"},
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

/// Recompute the journey's attestation id exactly as the pipeline does —
/// identifiers are a pure function of canonical bytes (PE-CRYPTO-006), so a
/// domain never needs to remember one.
pub fn attestation_id() -> String {
    let j = journey();
    let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(
        &j.proof.attestations[0].content,
    ));
    proof_crypto::id::attestation_id(&canon)
}
