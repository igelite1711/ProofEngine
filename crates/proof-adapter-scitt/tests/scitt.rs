// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SCITT adapter tests: mapping fidelity, stable-code rejections, and the
//! end-to-end transparency decision through adapter-built artifacts.

use proof_adapter_scitt::{
    checkpoint_content, receipt_evidence, registration_evidence, statement_content, statement_json,
    ScittStatement, SignedStatement,
};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::id::b64u_nopad;

fn limits() -> Limits {
    Limits::default()
}

fn issuer_key() -> proof_crypto::Ed25519Key {
    proof_crypto::build::fixtures::test_key()
}

/// Deterministic signed statement (fixed test key, fixed fields).
fn signed_statement() -> SignedStatement {
    let st = ScittStatement {
        v: 1,
        feed: "firmware-releases".into(),
        cti: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        payload_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        issued_at: 1_700_000_000,
        kid: issuer_key().key_ref(),
    };
    let bytes = st.canonical_json().unwrap();
    let sig = issuer_key().sign(&bytes);
    SignedStatement {
        statement: st,
        signature_b64u: b64u_nopad(&sig),
    }
}

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

#[test]
fn checked_in_fixtures_verify_and_map() {
    // The P7 differential pair: a signed SCITT envelope and its expected
    // mapping. The independent python check
    // (`crates/proof-adapter-scitt/differential.py`) recomputes the digest
    // from the envelope without touching Rust; here Rust verifies the
    // signature and the full projection.
    let lim = limits();
    let env: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("scitt-statement-01.json")).unwrap(),
    )
    .unwrap();
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixtures_dir().join("scitt-mapping-01.json")).unwrap(),
    )
    .unwrap();
    let signed: SignedStatement = serde_json::from_value(env).unwrap();
    let st = signed.verify().unwrap();
    let digest_hex = st
        .digest()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(
        digest_hex,
        expected["statement_digest_hex"].as_str().unwrap()
    );
    let content = statement_content(&signed, 1_700_000_000, None, &lim).unwrap();
    assert_eq!(content.issuer, expected["issuer"].as_str().unwrap());
    assert_eq!(content.subject, expected["subject"].as_str().unwrap());
    assert_eq!(
        content.claim.claim_type,
        expected["claim_type"].as_str().unwrap()
    );
    let reg = registration_evidence(&st, &lim).unwrap();
    let kinds: Vec<&str> = expected["evidence_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(kinds.contains(&reg.kind.as_str()));
    assert!(kinds.contains(&"transparency_receipt"));
}

#[test]
fn inbound_maps_statement_registration_and_receipt() {
    let lim = limits();
    let signed = signed_statement();
    let st = signed.verify().expect("deterministic fixture must verify");
    assert_eq!(st.feed, "firmware-releases");
    // Statement attestation content carries the binding inspectably.
    let content = statement_content(&signed, 1_700_000_100, None, &lim).unwrap();
    assert_eq!(content.issuer, issuer_key().key_ref());
    assert_eq!(
        content.subject,
        "scitt:firmware-releases:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(content.claim.claim_type, "scitt.statement");
    // Registration evidence is digest-bound to the statement bytes.
    let reg = registration_evidence(&st, &lim).unwrap();
    assert_eq!(reg.kind.as_str(), "transparency_registration");
    let digest = st.digest().unwrap();
    assert_eq!(reg.digest.digest, digest.to_vec());
    // Receipt evidence binds the same digest to a checkpoint id.
    let receipt = receipt_evidence(
        &st,
        "att:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &lim,
    )
    .unwrap();
    assert_eq!(receipt.kind.as_str(), "transparency_receipt");
    assert_eq!(receipt.digest.digest, digest.to_vec());
    assert_eq!(
        receipt.attestation_ref,
        Some("att:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
    );
}

#[test]
fn tampered_and_wrong_key_statements_fail_closed() {
    let mut bad = signed_statement();
    bad.signature_b64u = b64u_nopad(&[7u8; 64]);
    assert!(bad.verify().is_err());
    // Unknown kid shape fails closed (x5chain/did out of scope).
    let mut foreign = signed_statement();
    foreign.statement.kid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();
    assert!(foreign.verify().is_err());
    // Malformed statements fail with stable codes, never approximate.
    let mut malformed = signed_statement();
    malformed.statement.feed = String::new();
    assert!(malformed.verify().is_err());
    let mut malformed = signed_statement();
    malformed.statement.payload_sha256 = "xyz".into();
    assert!(malformed.verify().is_err());
    let mut malformed = signed_statement();
    malformed.statement.v = 2;
    assert!(malformed.verify().is_err());
}

#[test]
fn outbound_round_trips_byte_identically() {
    let lim = limits();
    let signed = signed_statement();
    // issued_at must equal the statement's own: faithful mapping preserves
    // the envelope bytes exactly (checked by the digest, not just fields).
    let content = statement_content(&signed, 1_700_000_000, None, &lim).unwrap();
    let back = statement_json(&content).unwrap();
    assert_eq!(back, signed.statement.canonical_json().unwrap());
    // Non-statement claims are unmappable (stable code, never approximate).
    let mut other = content.clone();
    other.claim.claim_type = "payment.settled".into();
    assert!(statement_json(&other).is_err());
}

#[test]
fn adapter_artifacts_drive_transparency_decision() {
    use proof_crypto::build::{attest, create_event, make_evidence};
    use proof_verify::{verify_proof, ProofBuilder};
    let lim = limits();
    let log = proof_crypto::Ed25519Key::from_seed(&[31u8; 32]);
    let signed = signed_statement();
    // Statement attestation signed by its issuer key.
    let stmt_content = statement_content(&signed, 1_700_000_100, None, &lim).unwrap();
    let stmt_att = attest(stmt_content, &issuer_key(), &lim).unwrap();
    // Log checkpoint covering the feed, signed by the log key.
    let cp_content = checkpoint_content(
        &log.key_ref(),
        "example-log",
        987,
        "scitt:example-log",
        1_700_000_100,
        None,
    )
    .unwrap();
    let checkpoint = attest(cp_content, &log, &lim).unwrap();
    // Receipt binding the statement digest to the checkpoint.
    let st = signed.verify().unwrap();
    let receipt = make_evidence(
        proof_core::model::EvidenceKind::new("transparency_receipt"),
        HashRef::new(HashAlgorithm::Sha256, st.digest().unwrap().to_vec()).unwrap(),
        Some(checkpoint.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        proof_core::model::Proposition {
            v: 1,
            kind: "scitt.statement.registered".into(),
            subject: st.subject(),
            predicate: "registered".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        1_700_000_200,
    );
    let ev = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: proof_core::model::EventType::new("scitt.statement.submitted"),
            subject: st.subject(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    b.add_event(ev);
    b.add_attestation(stmt_att);
    b.add_attestation(checkpoint);
    b.add_evidence(receipt);
    let built = b.build(&lim).unwrap();
    let ctx = proof_verify::VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        // Transparency-decision test, not feed test: explicit absence.
        require_status_feed: false,
        ..Default::default()
    };
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    let state = proof_policy::state_from_report_and_proof(&report, &built.proof).unwrap();
    let policy = proof_policy::parse_policy(
        &serde_json::json!({
            "policy_version": 2,
            "policy_id": "scitt-inclusion",
            "expression": {"type": "transparency_inclusion", "log": log.key_ref()},
        }),
        &lim,
    )
    .unwrap();
    let out = proof_policy::evaluate_policy(
        &state,
        &policy,
        &proof_policy::EvalInputs {
            trusted_issuers: vec![issuer_key().key_ref(), log.key_ref()],
            verified_at: 1_700_000_200,
            ..Default::default()
        },
    );
    assert_eq!(out.decision, proof_verify::PolicyDecision::Pass, "{out:?}");
    // Wrong log: no checkpoint by that identity → FAIL.
    let stranger = proof_crypto::Ed25519Key::from_seed(&[33u8; 32]);
    let policy = proof_policy::parse_policy(
        &serde_json::json!({
            "policy_version": 2,
            "policy_id": "scitt-inclusion-wrong",
            "expression": {"type": "transparency_inclusion", "log": stranger.key_ref()},
        }),
        &lim,
    )
    .unwrap();
    let out = proof_policy::evaluate_policy(
        &state,
        &policy,
        &proof_policy::EvalInputs {
            trusted_issuers: vec![issuer_key().key_ref(), stranger.key_ref()],
            verified_at: 1_700_000_200,
            ..Default::default()
        },
    );
    assert_eq!(out.decision, proof_verify::PolicyDecision::Fail);
}
