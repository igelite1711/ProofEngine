// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Conformance golden-vector generator (vectors 32–34): portable pins for
//! post-freeze fail-closed behavior that earlier vectors predate.
//! Deterministic: fixed seed, fixed timestamps, fixed payloads.
//! Run: `cargo run -p proof-verify --example gen_conformance_vectors`
//! Writes fixtures/golden-32..34.json (append-only; never rewrites 01–31).
//!
//! 32 derivation-cycle — PRODUCED A→B→A (each edge fine alone) → GRAPH
//!    CYCLE_DETECTED, evidence invalid (fail-closed composition input).
//! 33 digest-mismatch  — claim evidence_digest ≠ bound evidence digest →
//!    EVIDENCE ID_MISMATCH, evidence invalid (semantic forgery caught).
//! 34 future-status    — embedded revoke issued AFTER the verifier clock →
//!    STATUS hygiene note, lifecycle ACTIVE, evidence valid (history
//!    answers "was valid then?"; skew covers drift, not time-travel).

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_verify::{verify_proof, BuiltProof, ProofBuilder, VerifyCtx};
use std::path::PathBuf;

const ISSUED: u64 = 1_700_000_100;
const NOW_OK: u64 = 1_700_000_200;
const SKEW: u64 = 300;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn write(name: &str, json: serde_json::Value) {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    println!("wrote {name}");
}

fn ctx_json(verified_at: u64, known_at: Option<u64>) -> serde_json::Value {
    serde_json::json!({
        "verified_at": verified_at,
        "skew_leeway": SKEW,
        "revocation_authorities": [],
        "revocations_known_at": known_at,
    })
}

fn ctx_from(verified_at: u64, known_at: Option<u64>) -> VerifyCtx {
    VerifyCtx {
        verified_at,
        clock_skew_leeway: SKEW,
        revocations_known_at: known_at,
        ..VerifyCtx::default()
    }
}

/// Self-check helper: the embedded context must reproduce the expected
/// evidence validity and failure codes before a vector is published.
fn expect(
    built: &BuiltProof,
    verified_at: u64,
    known_at: Option<u64>,
    ev: proof_verify::Validity,
    codes: &[proof_core::ErrorCode],
) {
    let report = verify_proof(&built.canonical, &ctx_from(verified_at, known_at)).unwrap();
    assert_eq!(report.cryptographic_validity, proof_verify::Validity::Valid);
    assert_eq!(report.evidence_validity, ev, "{}", built.id);
    let got = report.failure_codes();
    for c in codes {
        assert!(got.contains(c), "{}: missing {c:?} in {got:?}", built.id);
    }
}

fn main() {
    vector_32_derivation_cycle();
    vector_33_digest_mismatch();
    vector_34_future_status_history();
}

/// Vector 32 — derivation cycle across one proof: PRODUCED A→B plus
/// PRODUCED B→A. Each edge is well-formed alone; together they are a
/// supply-chain loop, so GRAPH fails CYCLE_DETECTED (derivation is always
/// acyclic; only REFERENCES/EQUIVALENT linkage may cycle).
fn vector_32_derivation_cycle() {
    // NOTE: construction lives in vector_32_build so the cycle under test
    // stays visible next to its expectation, not hidden in helpers.
    let built = vector_32_build();
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::CycleDetected],
    );
    write(
        "golden-32.json",
        serde_json::json!({
            "name": "32-derivation-cycle",
            "description": "PRODUCED A→B plus PRODUCED B→A in one proof: each edge well-formed alone, together a derivation loop. GRAPH fails CYCLE_DETECTED (derivation always acyclic); evidence invalid.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["CYCLE_DETECTED"]
            }
        }),
    );
}

fn vector_32_build() -> BuiltProof {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let a = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("step.completed"),
            subject: "item:a".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let b = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("step.completed"),
            subject: "item:b".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &a.id),
        &key,
        &lim,
    )
    .unwrap();
    let fwd = make_relationship(
        Relationship {
            v: 1,
            from: a.id.clone(),
            rel_type: RelType::new(RelType::PRODUCED),
            to: b.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let back = make_relationship(
        Relationship {
            v: 1,
            from: b.id.clone(),
            rel_type: RelType::new(RelType::PRODUCED),
            to: a.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut builder = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "lineage.chain".into(),
            subject: a.id.clone(),
            predicate: "derived".into(),
            object: Some(b.id.clone()),
            at_time: Some(ISSUED),
            context: vec![],
        },
        NOW_OK,
    );
    builder.add_event(a);
    builder.add_event(b);
    builder.add_attestation(att);
    builder.add_relationship(fwd);
    builder.add_relationship(back);
    builder.build(&lim).unwrap()
}

/// Vector 33 — semantic forgery: the attestation names the evidence AND
/// asserts a claim digest that does NOT match it. EVIDENCE fails ID_MISMATCH.
fn vector_33_digest_mismatch() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: "payment:p9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        None,
        None,
        &lim,
    )
    .unwrap();
    let mut content = fixtures::fixed_attestation_content(&key.key_ref(), &pay.id);
    content.evidence_ref = Some(evd.id.clone());
    content
        .claim
        .fields
        .push(("evidence_digest".into(), MetaValue::Text("ff".repeat(32))));
    let att = attest(content, &key, &lim).unwrap();
    let mut builder = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: None,
            at_time: Some(ISSUED),
            context: vec![],
        },
        NOW_OK,
    );
    builder.add_event(pay);
    builder.add_attestation(att);
    builder.add_evidence(evd);
    let built = builder.build(&lim).unwrap();
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::IdMismatch],
    );
    write(
        "golden-33.json",
        serde_json::json!({
            "name": "33-digest-mismatch",
            "description": "Attestation names the evidence but asserts a claim digest (ff…ff) that does not match it (ee…ee). EVIDENCE fails ID_MISMATCH: values without bound bytes never pass.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["ID_MISMATCH"]
            }
        }),
    );
}

/// Vector 34 — future-status history: an embedded revoke issued AFTER the
/// verifier clock. At the past clock the attestation is ACTIVE (history
/// answers "was valid then?"); the future object is STATUS hygiene only.
/// Skew covers clock drift, not time-travel.
fn vector_34_future_status_history() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: "payment:p9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        &lim,
    )
    .unwrap();
    let inv = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::INVOICE_ISSUED),
            subject: "invoice:i9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xCDu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        &lim,
    )
    .unwrap();
    let st = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(st.id.clone()),
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
    // Revocation from the "future" relative to the verification clock below
    // (100s ahead, inside the 300s skew leeway — the old rule applied it).
    let revoke = proof_crypto::build::revoke_attestation(
        &st.id,
        Some("key rotation"),
        &key,
        NOW_OK + 100,
        &lim,
    )
    .unwrap();
    let mut builder = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: Some(inv.id.clone()),
            at_time: Some(ISSUED),
            context: vec![],
        },
        NOW_OK,
    );
    builder.add_event(pay);
    builder.add_event(inv);
    builder.add_attestation(st);
    builder.add_attestation(revoke);
    builder.add_evidence(evd);
    builder.add_relationship(edge);
    let built = builder.build(&lim).unwrap();
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Valid,
        &[],
    );
    write(
        "golden-34.json",
        serde_json::json!({
            "name": "34-future-status-history",
            "description": "Embedded revoke issued 100s after the verifier clock (inside skew): it is STATUS hygiene, never applied — lifecycle ACTIVE, evidence valid. History answers 'was valid then?'.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "valid",
                "codes": []
            }
        }),
    );
}
