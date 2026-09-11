// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proof golden-vector generator (vectors 11–12, 24–26).
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

    // Vectors 24–26: composition linkage (SPEC §7).
    // 24: the vector-11 members rebuilt with referenced_proofs=[REF24], where
    // REF24 is a deterministic, well-formed `prf:v1:` id whose content is
    // intentionally NOT embedded (linkage only — the verifier never fetches).
    // Triple must stay valid; the report echoes the linkage as REFERENCED.
    let ref24 = format!(
        "prf:v1:{}",
        proof_crypto::id::b64u_nopad(&proof_crypto::hash::sha256(
            b"proof-engine:golden-24-referenced-proof"
        ))
    );
    let mut b24 = ProofBuilder::new(
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
    // Rebuild members (builders consume inputs; recreate deterministically).
    let pay24 = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv24 = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let att24 = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay24.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd24 = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(att24.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge24 = make_relationship(
        Relationship {
            v: 1,
            from: pay24.id.clone(),
            rel_type: RelType::new(RelType::SETTLES),
            to: inv24.id.clone(),
            evidence_ref: Some(evd24.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    b24.add_referenced_proof(ref24.clone()).unwrap();
    b24.add_event(pay24);
    b24.add_event(inv24);
    b24.add_attestation(att24);
    b24.add_evidence(evd24);
    b24.add_relationship(edge24);
    let built24 = b24.build(&lim).unwrap();
    let report24 = verify_proof(&built24.canonical, &vector_ctx()).unwrap();
    assert_eq!(
        report24.evidence_validity,
        proof_verify::Validity::Valid,
        "vector-24 must stay valid with linkage"
    );
    assert_eq!(report24.referenced_proofs, vec![ref24.clone()]);
    std::fs::write(
        dir.join("golden-24.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "24-composed-proof-with-references",
            "description": "Vector-11 members plus referenced_proofs=[REF24] (content not embedded); triple valid, linkage echoed as REFERENCED.",
            "proof_canonical_hex": hex::encode(&built24.canonical),
            "proof_id": built24.id,
            "referenced_proofs": [ref24],
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
    println!("wrote golden-24.json {}", built24.id);

    // 25: stale self-link — vector-11 bytes plus referenced_proofs=[own id]
    // without rebinding. Must fail ID_MISMATCH *and* carry an explicit
    // CYCLE_DETECTED (a matching self-link is a hash preimage, so the stale
    // envelope is the feasible attack shape).
    let mut v25: proof_format::CborValue =
        proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v25 {
        pairs.push((
            proof_format::CborValue::Text("referenced_proofs".into()),
            proof_format::CborValue::Array(vec![proof_format::CborValue::Text(built.id.clone())]),
        ));
    }
    let bad25 = proof_format::encode_canonical(&v25);
    std::fs::write(
        dir.join("golden-25.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "25-self-referencing-proof",
            "description": "Vector 11 plus referenced_proofs=[own id] without rebinding; must fail ID_MISMATCH with explicit CYCLE_DETECTED.",
            "proof_canonical_hex": hex::encode(&bad25),
            "verify_ctx": ctx_json(),
            "expected": {
                "cryptographic_validity": "invalid",
                "codes": ["ID_MISMATCH", "CYCLE_DETECTED"]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    println!("wrote golden-25.json");

    // 26: malformed reference string. Must fail closed at SCHEMA.
    let mut v26: proof_format::CborValue =
        proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v26 {
        pairs.push((
            proof_format::CborValue::Text("referenced_proofs".into()),
            proof_format::CborValue::Array(vec![proof_format::CborValue::Text(
                "not-a-proof-id".into(),
            )]),
        ));
    }
    let bad26 = proof_format::encode_canonical(&v26);
    std::fs::write(
        dir.join("golden-26.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "26-malformed-reference",
            "description": "Vector 11 plus a malformed referenced_proofs entry; must fail SCHEMA_VIOLATION at SCHEMA.",
            "proof_canonical_hex": hex::encode(&bad26),
            "verify_ctx": ctx_json(),
            "expected": {
                "cryptographic_validity": "invalid",
                "stage": "SCHEMA",
                "code": "SCHEMA_VIOLATION"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    println!("wrote golden-26.json");

    // Vector 27: vocabulary declarations bind. Same shape as vector 11 but
    // with an `acme:`-namespaced vocabulary declared at version 2; the
    // binding covers the declaration set (dropping it changes the id), the
    // triple stays valid, and the report echoes the declaration. Legacy
    // labels alongside trigger an undeclared-vocabulary note (informational).
    let pay27 = event(EventType::new("acme:payment.created"), "payment:p27");
    let inv27 = event(EventType::new("acme:invoice.issued"), "invoice:i27");
    let att27 = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay27.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd27 = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(att27.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge27 = make_relationship(
        Relationship {
            v: 1,
            from: pay27.id.clone(),
            rel_type: RelType::new(RelType::SETTLES),
            to: inv27.id.clone(),
            evidence_ref: Some(evd27.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b27 = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "acme:payment.settles-invoice".into(),
            subject: "payment:p27".into(),
            predicate: "settles".into(),
            object: Some("invoice:i27".into()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b27.add_event(pay27);
    b27.add_event(inv27);
    b27.add_attestation(att27);
    b27.add_evidence(evd27);
    b27.add_relationship(edge27);
    b27.add_vocabulary("acme".into(), 2).unwrap();
    let built27 = b27.build(&lim).unwrap();
    let report27 = verify_proof(&built27.canonical, &vector_ctx()).unwrap();
    assert_eq!(
        report27.evidence_validity,
        proof_verify::Validity::Valid,
        "vector-27 ctx must produce a valid report"
    );
    assert_eq!(
        report27
            .vocabularies
            .iter()
            .map(|vd| (vd.ns.as_str(), vd.version))
            .collect::<Vec<_>>(),
        vec![("acme", 2)]
    );
    std::fs::write(
        dir.join("golden-27.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "name": "27-vocabulary-declaration-binds",
            "description": "Vector-11 shape with acme:-namespaced labels and vocabularies=[acme:2]; binding covers declarations, triple valid, declaration echoed.",
            "proof_canonical_hex": hex::encode(&built27.canonical),
            "proof_id": built27.id,
            "vocabularies": [{"ns": "acme", "version": 2}],
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
    println!("wrote golden-27.json {}", built27.id);
}
