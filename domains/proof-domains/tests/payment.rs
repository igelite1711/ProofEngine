//! Payment domain journey (the V1 reference domain).
//! Domain DATA only: vocabulary + a journey builder + a caller-supplied
//! policy. No mechanism logic lives here (NEUTRALITY §2).

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, CreatedAttestation,
    CreatedEvent, CreatedRelationship,
};
use proof_verify::BuiltProof;
use std::sync::OnceLock;

pub const CLOCK_OK: u64 = 1_700_000_200;

/// Test key (fixed, deterministic — V1 demo/test key, never production).
pub fn issuer_key() -> &'static proof_crypto::Ed25519Key {
    static KEY: OnceLock<proof_crypto::Ed25519Key> = OnceLock::new();
    KEY.get_or_init(proof_crypto::build::fixtures::test_key)
}

pub fn issuer() -> &'static str {
    static ISSUER: OnceLock<String> = OnceLock::new();
    ISSUER.get_or_init(|| issuer_key().key_ref())
}

pub fn event_payment_created(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn event_invoice_issued(subject: &str) -> CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::INVOICE_ISSUED),
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn merchant_attestation(subject: &str) -> CreatedAttestation {
    attest(
        fixtures::fixed_attestation_content(issuer(), subject),
        issuer_key(),
        &Limits::default(),
    )
    .unwrap()
}

pub fn settlement_edge(from: &str, to: &str, evidence_id: &str) -> CreatedRelationship {
    make_relationship(
        Relationship {
            v: 1,
            from: from.into(),
            rel_type: RelType::new(RelType::SETTLES),
            to: to.into(),
            evidence_ref: Some(evidence_id.into()),
            attestation_ref: None,
        },
        &Limits::default(),
    )
    .unwrap()
}

pub fn transaction_record(attestation_id: &str) -> proof_crypto::build::CreatedEvidence {
    make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(attestation_id.into()),
        None,
        &Limits::default(),
    )
    .unwrap()
}

/// Full payment journey as a built proof: two events, one attestation, one
/// evidence item, one grounding-backed SETTLES edge.
pub fn journey() -> BuiltProof {
    let pay = event_payment_created("payment:p9");
    let inv = event_invoice_issued("invoice:i9");
    let att = merchant_attestation(&pay.id);
    let evd = transaction_record(&att.id);
    let edge = settlement_edge(&pay.id, &inv.id, &evd.id);
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&Limits::default()).unwrap()
}

/// Caller-supplied policy for the payment domain (requirements 1..5 mirror the
/// reference `merchant_payment_v1` policy used across the repo docs).
pub fn policy() -> serde_json::Value {
    serde_json::json!({
        "policy_version": 1,
        "policy_id": "merchant_payment_v1",
        "requirements": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer()},
            {"type": "relationship_exists", "relationship": RelType::SETTLES},
            {"type": "not_expired"},
            {"type": "not_revoked"}
        ]
    })
}

/// Inputs for policy evaluation at the trustworthy clock.
pub fn inputs() -> proof_policy::EvalInputs {
    proof_policy::EvalInputs {
        trusted_issuers: vec![issuer().to_string()],
        verified_at: CLOCK_OK,
        ..proof_policy::EvalInputs::default()
    }
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
