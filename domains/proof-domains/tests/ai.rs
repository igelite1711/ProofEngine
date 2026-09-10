//! AI-action provenance domain journey (AI/agent vertical).
//! User request → tool call, with the operator attesting the executed action
//! over a grounding-required `EXECUTED` edge and a `training_log` evidence
//! kind. Domain DATA only (NEUTRALITY §2).

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

pub fn event_request_received(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("agent.request.received"),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x55u8; 32]).unwrap(),
            metadata: vec![("session".into(), MetaValue::Text("s-1".into()))],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_tool_executed(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("agent.tool.executed"),
            subject: subject.into(),
            effective_at: 1_700_000_050,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x55u8; 32]).unwrap(),
            metadata: vec![("tool".into(), MetaValue::Text("search.v2".into()))],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn action_attestation(subject: &str) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: issuer().into(),
            subject: subject.into(),
            claim: proof_core::model::Claim {
                claim_type: "agent.tool.executed".into(),
                fields: vec![("model".into(), MetaValue::Text("planner-7".into()))],
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

pub fn execution_log(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new("training_log"),
        HashRef::new(HashAlgorithm::Sha256, vec![0x66u8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

pub fn execution_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new(RelType::EXECUTED),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn journey() -> BuiltProof {
    let req = event_request_received("agent:request:r1");
    let call = event_tool_executed("agent:toolcall:tc1");
    let att = action_attestation(&call.id);
    let evd = execution_log(&att.id);
    let edge = execution_edge(&req.id, &call.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "agent.action.performed".into(),
            subject: "agent:request:r1".into(),
            predicate: "executed-as".into(),
            object: Some("agent:toolcall:tc1".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(req);
    b.add_event(call);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "ai_action_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": RelType::EXECUTED},
            {"type": "evidence_present", "kind": "training_log"},
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
