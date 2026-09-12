// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reference API tests: route-level (no sockets) plus one live loopback
//! round-trip proving the serve path behaves identically.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use proof_api::api::route;

fn tiny_proof_bytes() -> Vec<u8> {
    use proof_core::model::{AttestationContent, Claim, EventContent, EventType, Proposition};
    use proof_core::{HashAlgorithm, HashRef, Limits};
    let lim = Limits::default();
    let key = proof_crypto::build::fixtures::test_key();
    let ev = proof_crypto::build::create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("test.event.occurred"),
            subject: "test:api-0".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let att = proof_crypto::build::attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "test:api-0".into(),
            claim: Claim {
                claim_type: "test.occurred".into(),
                fields: vec![],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .unwrap();
    let mut b = proof_verify::ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "test.proposition".into(),
            subject: "test:api-0".into(),
            predicate: "occurred".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(ev);
    b.add_attestation(att);
    b.build(&lim).unwrap().canonical
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_body(hex: &str) -> Vec<u8> {
    serde_json::json!({
        "proof": {"cbor_hex": hex},
        "clock": 1_700_000_200u64,
        "revocations_known_at": 1_700_000_200u64,
    })
    .to_string()
    .into_bytes()
}

#[test]
fn health_and_unknown_paths() {
    let (s, b) = route("GET", "/v1/health", b"");
    assert_eq!(s, 200);
    assert!(b.contains("\"ok\":true"));
    let (s, _) = route("GET", "/v1/version", b"");
    assert_eq!(s, 200);
    let (s, _) = route("GET", "/nope", b"");
    assert_eq!(s, 404);
    let (s, _) = route("DELETE", "/v1/health", b"");
    assert_eq!(s, 405);
    let (s, _) = route("POST", "/v1/verify", b"not-json");
    assert_eq!(s, 400);
}

#[test]
fn verify_reports_explicit_validity_with_200() {
    let hex = hex_of(&tiny_proof_bytes());
    let (s, b) = route("POST", "/v1/verify", &verify_body(&hex));
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    // Attested proof, fresh revocation info: fully valid, decision left open.
    assert_eq!(v["cryptographic_validity"], "Valid");
    assert_eq!(v["evidence_validity"], "Valid");
    assert_eq!(v["policy_decision"], "Indeterminate");
    assert!(v["proof_id"].as_str().unwrap().starts_with("prf:v1:"));
}

#[test]
fn verify_rejects_bad_input_with_400() {
    // Missing clock (the server never reads a wall clock).
    let hex = hex_of(&tiny_proof_bytes());
    let body = serde_json::json!({"proof": {"cbor_hex": hex}})
        .to_string()
        .into_bytes();
    let (s, b) = route("POST", "/v1/verify", &body);
    assert_eq!(s, 400, "{b}");
    // Malformed hex.
    let body = serde_json::json!({
        "proof": {"cbor_hex": "zz"},
        "clock": 1_700_000_200u64,
    })
    .to_string()
    .into_bytes();
    let (s, _) = route("POST", "/v1/verify", &body);
    assert_eq!(s, 400);
    // Missing proof.
    let (s, _) = route("POST", "/v1/verify", br#"{"clock": 1700000200}"#);
    assert_eq!(s, 400);
}

#[test]
fn evaluate_and_explain_decide() {
    let hex = hex_of(&tiny_proof_bytes());
    let key = proof_crypto::build::fixtures::test_key().key_ref();
    let body = serde_json::json!({
        "proof": {"cbor_hex": hex},
        "clock": 1_700_000_200u64,
        "revocations_known_at": 1_700_000_200u64,
        "trusted": [key],
        "policy": {
            "policy_version": 1,
            "policy_id": "api-test",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": key},
                {"type": "not_expired"},
                {"type": "not_revoked"},
            ],
        },
    })
    .to_string()
    .into_bytes();
    let (s, b) = route("POST", "/v1/evaluate", &body);
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["outcome"]["decision"], "Pass");
    let (s, b) = route("POST", "/v1/explain", &body);
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["outcome"]["decision"], "Pass");
    assert!(v["explanation"]
        .as_str()
        .unwrap()
        .contains("cryptographic_validity"));
    // Missing policy is a 400, not a default decision.
    let body = serde_json::json!({
        "proof": {"cbor_hex": hex},
        "clock": 1_700_000_200u64,
    })
    .to_string()
    .into_bytes();
    let (s, _) = route("POST", "/v1/evaluate", &body);
    assert_eq!(s, 400);
}

#[test]
fn live_loopback_round_trip_matches_route() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        proof_api::server::handle(stream);
    });
    let hex = hex_of(&tiny_proof_bytes());
    let body = verify_body(&hex);
    let req = format!(
        "POST /v1/verify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(&body).unwrap();
    let mut raw = vec![];
    stream.read_to_end(&mut raw).unwrap();
    server.join().unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    let json_part = text.split("\r\n\r\n").nth(1).unwrap();
    let (s, expected) = route("POST", "/v1/verify", &body);
    assert_eq!(s, 200);
    assert_eq!(json_part, expected);
}
