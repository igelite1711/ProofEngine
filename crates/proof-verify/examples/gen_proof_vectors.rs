// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proof golden-vector generator (vectors 11–12).
//! Run: `cargo run -p proof-verify --example gen_proof_vectors`

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_verify::{verify_proof, ProofBuilder, VerifyCtx};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

/// Verification context embedded in the vector (FORMAT §8 `verify_ctx`):
/// trustworthy clock inside the attestation validity window and revocation
/// information known up to the verification instant.
fn vector_ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        ..VerifyCtx::default()
    }
}

fn ctx_json() -> serde_json::Value {
    serde_json::json!({
        "verified_at": 1700000200,
        "skew_leeway": 300,
        "revocation_authorities": [],
        "revocations_known_at": 1700000200
    })
}

// PE-INTEROP-001: golden vectors pin bytes/ids/verdicts.
fn main() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let event = |t: EventType, subject: &str| {
        create_event(
            proof_core::model::EventContent {
                v: 1,
                event_type: t,
                subject: subject.into(),
                effective_at: 1_700_000_000,
                payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
                metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
            },
            &lim,
        )
        .unwrap()
    };
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge = make_relationship(
        Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: RelType::new(RelType::SETTLES),
            to: inv.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();

    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // Self-check before publishing: the embedded context must yield the
    // expected triple (evidence valid; lifecycle ACTIVE).
    let report = verify_proof(&built.canonical, &vector_ctx()).unwrap();
    assert_eq!(
        report.evidence_validity,
        proof_verify::Validity::Valid,
        "vector-11 ctx must produce a valid report"
    );
    assert!(report
        .lifecycle
        .iter()
        .all(|l| l.status == proof_core::LifecycleStatus::Active));

    std::fs::write(
        dir.join("golden-11.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "11-valid-proof",
            "description": "Full payment-settles-invoice proof; crypto+evidence valid, policy indeterminate.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "valid",
                "policy_decision": "indeterminate"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    println!("wrote golden-11.json {}", built.id);

    // Vector 12: same bytes with event metadata mutated (proof id stale).
    let mut v: proof_format::CborValue =
        proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        let events = pairs
            .iter_mut()
            .find(|(k, _)| matches!(k, proof_format::CborValue::Text(s) if s == "events"))
            .map(|(_, v)| v)
            .unwrap();
        if let proof_format::CborValue::Array(items) = events {
            if let proof_format::CborValue::Map(epairs) = &mut items[0] {
                let meta = epairs
                    .iter_mut()
                    .find(|(k, _)| matches!(k, proof_format::CborValue::Text(s) if s == "metadata"))
                    .map(|(_, v)| v)
                    .unwrap();
                if let proof_format::CborValue::Map(mpairs) = meta {
                    for (k, val) in mpairs.iter_mut() {
                        if matches!(k, proof_format::CborValue::Text(s) if s == "order") {
                            *val = proof_format::CborValue::Text("ord-2".into());
                        }
                    }
                }
            }
        }
    }
    let bad = proof_format::encode_canonical(&v);
    std::fs::write(
        dir.join("golden-12.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "12-mutated-proof",
            "description": "Vector 11 with event metadata changed and proof id stale; must fail ID_MISMATCH at IDENTIFIERS.",
            "proof_canonical_hex": hex::encode(&bad),
            "verify_ctx": ctx_json(),
            "expected": {
                "cryptographic_validity": "invalid",
                "stage": "IDENTIFIERS",
                "code": "ID_MISMATCH"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    println!("wrote golden-12.json");
}
