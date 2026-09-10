// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden-vector verification (Phase 1 gate: vectors 01–05 pass on clean checkout).
//! Reads `fixtures/*.json` relative to workspace root. No keys embedded here except
//! issuer refs from the fixtures themselves.

use proof_core::Limits;
use proof_crypto::cose::{parse_sign1, verify_sign1};
use proof_crypto::id::verify_id;
use proof_format::decode_strict;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn load(name: &str) -> serde_json::Value {
    let p = fixtures().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
    serde_json::from_str(&s).unwrap()
}

fn lim() -> Limits {
    Limits::default()
}

#[test]
fn golden_01_event_canonical() {
    let v = load("golden-01.json");
    let canon = hex::decode(v["canonical_hex"].as_str().unwrap()).unwrap();
    let val = decode_strict(&canon, &lim()).expect("01 must decode");
    assert_eq!(proof_format::encode_canonical(&val), canon);
    let id = v["object_id"].as_str().unwrap();
    verify_id("evt", id, &canon).expect("01 id must verify");
}

#[test]
fn golden_02_duplicate_key() {
    let v = load("golden-02.json");
    let raw = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
    let e = decode_strict(&raw, &lim()).unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}

#[test]
fn golden_03_non_canonical() {
    let v = load("golden-03.json");
    let raw = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
    let e = decode_strict(&raw, &lim()).unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}

#[test]
fn golden_04_valid_sign1() {
    let v = load("golden-04.json");
    let att = hex::decode(v["attestation_canonical_hex"].as_str().unwrap()).unwrap();
    let att_val = decode_strict(&att, &lim()).expect("04 attestation must decode");
    assert_eq!(proof_format::encode_canonical(&att_val), att);
    verify_id("att", v["attestation_id"].as_str().unwrap(), &att).unwrap();
    let sign1 = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let p = parse_sign1(&sign1, &lim()).expect("04 must parse");
    assert_eq!(p.alg, -19);
    assert_eq!(p.payload, att);
    verify_sign1(
        &sign1,
        v["verify_ctx"]["issuer"].as_str().unwrap(),
        &proof_crypto::alg::AllowedAlgs::strict(),
        &lim(),
    )
    .expect("04 must verify");
}

#[test]
fn golden_05_tampered_sign1() {
    let v = load("golden-05.json");
    let sign1 = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let e = verify_sign1(
        &sign1,
        v["verify_ctx"]["issuer"].as_str().unwrap(),
        &proof_crypto::alg::AllowedAlgs::strict(),
        &lim(),
    )
    .unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}

#[test]
fn golden_06_builder_chain() {
    use proof_crypto::build::{verify_attestation, verify_event, verify_evidence};
    let v = load("golden-06.json");
    let issuer = v["verify_ctx"]["issuer"].as_str().unwrap();
    let algs = proof_crypto::alg::AllowedAlgs::strict();

    let ev = hex::decode(v["event_canonical_hex"].as_str().unwrap()).unwrap();
    let (_, ev_id) = verify_event(&ev, Some(v["event_id"].as_str().unwrap()), &lim()).unwrap();

    let sign1 = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let (att, att_id) = verify_attestation(&sign1, issuer, &algs, &lim()).unwrap();
    assert_eq!(att_id, v["attestation_id"].as_str().unwrap());
    // Attestation must point at the event it observes.
    assert_eq!(att.subject, ev_id);

    let evd = hex::decode(v["evidence_canonical_hex"].as_str().unwrap()).unwrap();
    let (evd_content, evd_id) =
        verify_evidence(&evd, Some(v["evidence_id"].as_str().unwrap()), &lim()).unwrap();
    // Evidence must bind the attestation it supports.
    assert_eq!(
        evd_content.attestation_ref.as_deref(),
        Some(att_id.as_str())
    );
    assert_eq!(evd_id, v["evidence_id"].as_str().unwrap());
}

#[test]
fn golden_07_wrong_issuer() {
    let v = load("golden-07.json");
    let sign1 = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let e = verify_sign1(
        &sign1,
        v["verify_ctx"]["issuer"].as_str().unwrap(),
        &proof_crypto::alg::AllowedAlgs::strict(),
        &lim(),
    )
    .unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}

#[test]
fn golden_08_evidence_tamper() {
    use proof_crypto::build::verify_evidence;
    let v = load("golden-08.json");
    let evd = hex::decode(v["evidence_canonical_hex"].as_str().unwrap()).unwrap();
    let e = verify_evidence(&evd, Some(v["expected_id"].as_str().unwrap()), &lim()).unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}

#[test]
fn golden_21_esp256_valid_sign1() {
    let v = load("golden-21.json");
    let raw = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let issuer = v["verify_ctx"]["issuer"].as_str().unwrap();
    let p = verify_sign1(
        &raw,
        issuer,
        &proof_crypto::alg::AllowedAlgs::strict().with_esp256(),
        &lim(),
    )
    .expect("valid ESP256 vector must verify");
    assert_eq!(p.alg, -9);
    assert_eq!(p.kid.len(), 64);
    assert!(issuer.starts_with("key:p256:"));
}

#[test]
fn golden_22_esp256_tampered_rejected() {
    let v = load("golden-22.json");
    let raw = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let issuer = v["verify_ctx"]["issuer"].as_str().unwrap();
    let e = verify_sign1(
        &raw,
        issuer,
        &proof_crypto::alg::AllowedAlgs::strict().with_esp256(),
        &lim(),
    )
    .unwrap_err();
    assert!(matches!(
        e.code,
        proof_core::ErrorCode::SignatureInvalid
            | proof_core::ErrorCode::NonCanonical
            | proof_core::ErrorCode::Malformed
    ));
}

#[test]
fn golden_23_esp256_wrong_key_rejected() {
    let v = load("golden-23.json");
    let raw = hex::decode(v["cose_sign1_hex"].as_str().unwrap()).unwrap();
    let issuer = v["verify_ctx"]["issuer"].as_str().unwrap();
    let e = verify_sign1(
        &raw,
        issuer,
        &proof_crypto::alg::AllowedAlgs::strict().with_esp256(),
        &lim(),
    )
    .unwrap_err();
    assert_eq!(e.code, proof_core::ErrorCode::SignatureInvalid);
}
