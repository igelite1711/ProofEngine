// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lifecycle golden-vector generator (vectors 15–18, 29–30).
//! Deterministic: fixed seed, fixed timestamps, fixed payloads.
//! Run: `cargo run -p proof-verify --example gen_lifecycle_vectors`
//! Writes fixtures/golden-15..18.json + golden-29..30.json.
//!
//! 15 expired     — attestation leaves its validity window → EXPIRED
//! 16 revoked     — signed revoke status object embedded in the proof → REVOKED
//! 17 superseded  — signed supersede old→new; historical record preserved
//! 18 unknown     — no revocation information supplied → REVOCATION_UNKNOWN
//! 29 withdrawn   — signed withdraw of evidence → WITHDRAWN (history preserved)
//! 30 compromised — signed compromise marking → COMPROMISED (tainted, no history)

use proof_core::model::{
    AttestationContent, Claim, EventType, EvidenceKind, MetaValue, Proposition, RelType,
    Relationship,
};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, compromise_attestation, create_event, fixtures, make_evidence, make_relationship,
    revoke_attestation, supersede_attestation, withdraw_attestation, CreatedAttestation,
};
use proof_verify::{verify_proof, BuiltProof, ProofBuilder, VerifyCtx};
use std::path::PathBuf;

const ISSUED: u64 = 1_700_000_100;
const NOW_OK: u64 = 1_700_000_200;
const SKEW: u64 = 300;
/// Clock past vector-15's expiry (the skew window no longer covers it).
const NOW_LATE: u64 = 1_700_001_100;

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

fn event(t: EventType, subject: &str) -> proof_crypto::build::CreatedEvent {
    let lim = Limits::default();
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
}

fn proposition() -> Proposition {
    Proposition {
        v: 1,
        kind: "payment.settles-invoice".into(),
        subject: "payment:p9".into(),
        predicate: "settles".into(),
        object: Some("invoice:i9".into()),
        at_time: Some(ISSUED),
        context: vec![],
    }
}

/// Statement attestation with the fixture default validity window.
fn statement(key_ref: &str) -> CreatedAttestation {
    let lim = Limits::default();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    attest(
        fixtures::fixed_attestation_content(key_ref, &pay.id),
        &proof_crypto::Ed25519Key::from_seed(&[9u8; 32]),
        &lim,
    )
    .unwrap()
}

/// Full payment-settles-invoice proof around the given attestations.
fn build(extra: Vec<CreatedAttestation>) -> proof_verify::BuiltProof {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let st = statement(&key.key_ref());
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
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(st);
    for a in extra {
        b.add_attestation(a);
    }
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&lim).unwrap()
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
fn main() {
    vector_15_expired();
    vector_16_revoked();
    vector_17_superseded();
    vector_18_unknown();
    vector_29_withdrawn();
    vector_30_compromised();
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

/// Vector 15 — expired: statement attestation dies one second after issuance;
/// a live clock past its expiry (revocation info fresh) → TIME fails EXPIRED.
fn vector_15_expired() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let mut dead = fixtures::fixed_attestation_content(&key.key_ref(), "payment:p9");
    dead.issued_at = ISSUED;
    dead.expires_at = Some(ISSUED + 1);
    let dead = attest(dead, &key, &lim).unwrap();
    let built = build(vec![dead]);
    expect(
        &built,
        NOW_LATE,
        Some(NOW_LATE),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::Expired],
    );
    write(
        "golden-15.json",
        serde_json::json!({
            "name": "15-expired-attestation",
            "description": "Proof whose statement attestation left its validity window (issued 1700000100, expires 1700000101); verified at 1700001100 with fresh revocation info. Evidence invalid, code EXPIRED at stage TIME.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_LATE, Some(NOW_LATE)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["EXPIRED"]
            }
        }),
    );
}

/// Vector 16 — revoked: signed revoke status object embedded in the proof,
/// signed by the original issuer of the target; effect applies → REVOKED.
fn vector_16_revoked() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let st = statement(&key.key_ref());
    let revoke = revoke_attestation(
        &st.id,
        Some("issuer compromise suspected"),
        &key,
        NOW_OK,
        &lim,
    )
    .unwrap();
    let built = build(vec![revoke]);
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::Revoked],
    );
    write(
        "golden-16.json",
        serde_json::json!({
            "name": "16-revoked-attestation",
            "description": "Same chain with an embedded signed revoke status object (claim.type=revoke) by the original issuer; applies at stage REVOCATION. Evidence invalid, code REVOKED.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["REVOKED"]
            }
        }),
    );
}

/// Vector 17 — superseded with history preserved: signed supersession
/// old→new by the original issuer; old is SUPERSEDED, evidence stays valid.
fn vector_17_superseded() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let old = statement(&key.key_ref());
    let new_content = AttestationContent {
        issued_at: ISSUED + 1,
        claim: Claim {
            claim_type: "payment.created-observed-v2".into(),
            fields: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        ..fixtures::fixed_attestation_content(&key.key_ref(), "payment:p9")
    };
    let new = attest(new_content, &key, &lim).unwrap();
    let sup = supersede_attestation(&old.id, &new.id, &key, NOW_OK, &lim).unwrap();
    let built = build(vec![new, sup]);
    {
        let report = verify_proof(&built.canonical, &ctx_from(NOW_OK, Some(NOW_OK))).unwrap();
        assert_eq!(report.cryptographic_validity, proof_verify::Validity::Valid);
        // Historical note preserved: evidence validity stays valid.
        assert_eq!(
            report.evidence_validity,
            proof_verify::Validity::Valid,
            "{}",
            built.id
        );
        assert!(report.failure_codes().is_empty(), "{}", built.id);
        assert!(report
            .lifecycle
            .iter()
            .any(|l| l.status == proof_core::LifecycleStatus::Superseded));
    }
    write(
        "golden-17.json",
        serde_json::json!({
            "name": "17-superseded-history-preserved",
            "description": "Chain with a signed supersede status object (old statement -> new statement), both embedded. Old attestation is SUPERSEDED with the historical note preserved; evidence stays valid, no failure codes.",
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

/// Vector 18 — unknown, fail closed: canonical bytes identical to vector 11,
/// but the verify context carries NO revocation information (known_at null)
/// → lifecycle UNKNOWN → REVOCATION_UNKNOWN. Context is explicit input.
fn vector_18_unknown() {
    let built = build(vec![]);
    expect(
        &built,
        NOW_OK,
        None,
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::RevocationUnknown],
    );
    write(
        "golden-18.json",
        serde_json::json!({
            "name": "18-revocation-unknown",
            "description": "Same canonical bytes as vector 11, but verify_ctx carries no revocation information (revocations_known_at null): lifecycle UNKNOWN, fail closed with REVOCATION_UNKNOWN. Never PASS.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, None),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["REVOCATION_UNKNOWN"]
            }
        }),
    );
}

/// Vector 29 — withdrawn: signed withdraw of the evidence item by the issuer
/// of its bound attestation → evidence WITHDRAWN (history preserved, like
/// revocation, but a distinct administrative act). Evidence invalid, WITHDRAWN.
fn vector_29_withdrawn() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let st = statement(&key.key_ref());
    // Evidence id is deterministic: build it first so the withdrawal can name it.
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(st.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let wd = withdraw_attestation(
        &evd.id,
        Some("superseded by audit trail"),
        &key,
        NOW_OK,
        &lim,
    )
    .unwrap();
    // Rebuild the standard chain around the same evidence, plus withdrawal.
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
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
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(st);
    b.add_attestation(wd);
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::Withdrawn],
    );
    write(
        "golden-29.json",
        serde_json::json!({
            "name": "29-withdrawn-evidence",
            "description": "Signed withdraw status object (claim.type=withdraw) by the issuer of the evidence's bound attestation; applies at stage REVOCATION. Evidence WITHDRAWN (history preserved), evidence invalid.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["WITHDRAWN"]
            }
        }),
    );
}

/// Vector 30 — compromised: signed compromise marking of the issuer key with
/// at_time at issuance → statement COMPROMISED (tainted, history NOT
/// preserved, unlike revocation). A pre-instant statement would stay Active;
/// here the marking covers issuance, so the chain fails COMPROMISED.
fn vector_30_compromised() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let st = statement(&key.key_ref());
    let mark = compromise_attestation(
        &key.key_ref(),
        1_700_000_000,
        Some("key material exfiltrated"),
        &key,
        NOW_OK,
        &lim,
    )
    .unwrap();
    let built = build(vec![mark]);
    // Silence unused warning for `st` (build() recreates it identically).
    let _ = st;
    expect(
        &built,
        NOW_OK,
        Some(NOW_OK),
        proof_verify::Validity::Invalid,
        &[proof_core::ErrorCode::Compromised],
    );
    write(
        "golden-30.json",
        serde_json::json!({
            "name": "30-compromised-issuer",
            "description": "Signed compromise marking (claim.type=compromise, at_time at statement issuance) self-reported by the issuer; applies at stage REVOCATION. Statement COMPROMISED, evidence invalid, history not preserved.",
            "proof_canonical_hex": hex::encode(&built.canonical),
            "proof_id": built.id,
            "verify_ctx": ctx_json(NOW_OK, Some(NOW_OK)),
            "expected": {
                "cryptographic_validity": "valid",
                "evidence_validity": "invalid",
                "codes": ["COMPROMISED"]
            }
        }),
    );
}
