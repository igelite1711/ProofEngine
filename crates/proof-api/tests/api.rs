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
        // Explicit caller-asserted absence (genesis-shape tiny proof).
        "no_require_status": true,
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
    // Wire strings aligned to CLI (lowercase validities/policy, UPPER
    // lifecycle/status) + currently_acceptable currency split.
    assert_eq!(v["cryptographic_validity"], "valid");
    assert_eq!(v["evidence_validity"], "valid");
    assert_eq!(v["policy_decision"], "indeterminate");
    assert_eq!(v["currently_acceptable"], true);
    // Conflicts ride as full records (CLI parity), not a bare count.
    assert!(v["conflicts"].is_array());
    assert!(v["proof_id"].as_str().unwrap().starts_with("prf:v1:"));
}

#[test]
fn verify_production_flags_parse_and_gate_empty_feed() {
    // Fresh tiny proof carries no status objects: the fail-closed default
    // rejects the empty feed (UNKNOWN); explicit `no_require_status`
    // restores caller-asserted absence. HTTP stays 200 — verdicts are
    // data, not errors.
    let hex = hex_of(&tiny_proof_bytes());
    let base = serde_json::json!({
        "proof": {"cbor_hex": hex},
        "clock": 1_700_000_200u64,
        "revocations_known_at": 1_700_000_200u64,
    });
    // Bare: fail closed on empty feed.
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&base).unwrap());
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["evidence_validity"], "invalid");
    // Explicit opt-out restores caller-asserted absence.
    let mut allowed = base.clone();
    allowed["no_require_status"] = serde_json::Value::Bool(true);
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&allowed).unwrap());
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["evidence_validity"], "valid");
    // --require_status: no-op affirming the default (still fails closed).
    let mut bare = base.clone();
    bare["require_status"] = serde_json::Value::Bool(true);
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&bare).unwrap());
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["evidence_validity"], "invalid");
    // --production implies the feed gate (+ full-DAG + currency overlay).
    let mut prod = base.clone();
    prod["production"] = serde_json::Value::Bool(true);
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&prod).unwrap());
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["evidence_validity"], "invalid");
    // Explicit opt-out restores historical behavior for the feed gate only.
    prod["no_require_status"] = serde_json::Value::Bool(true);
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&prod).unwrap());
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["evidence_validity"], "valid");
    // Verifier-policy flags parse (no 400): esp256/historical/report_all,
    // vocab, extra_grounded, acyclic, strict currency request.
    let mut flags = base.clone();
    flags["esp256"] = serde_json::Value::Bool(true);
    flags["report_all"] = serde_json::Value::Bool(true);
    flags["require_acyclic"] = serde_json::Value::Bool(true);
    flags["strict_current"] = serde_json::Value::Bool(true);
    flags["accepted_vocab"] = serde_json::json!(["acme:2"]);
    flags["extra_grounded"] = serde_json::json!(["MYEDGE"]);
    let (s, b) = route("POST", "/v1/verify", &serde_json::to_vec(&flags).unwrap());
    assert_eq!(s, 200, "{b}");
    // Malformed vocab is 400, not silent pass.
    flags["accepted_vocab"] = serde_json::json!(["no-colon"]);
    let (s, _) = route("POST", "/v1/verify", &serde_json::to_vec(&flags).unwrap());
    assert_eq!(s, 400);
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
fn verify_rejects_envelope_id_mismatch_with_400() {
    // Envelope consistency (fail closed): a wrapper `id` that disagrees with
    // the canonical bytes is a 400 — never silently verified under a
    // different identity. Mirrors the CLI loader (`load_proof`).
    let hex = hex_of(&tiny_proof_bytes());
    let body = serde_json::json!({
        "proof": {"cbor_hex": hex, "id": "prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        "clock": 1_700_000_200u64,
        "revocations_known_at": 1_700_000_200u64,
    })
    .to_string()
    .into_bytes();
    let (s, b) = route("POST", "/v1/verify", &body);
    assert_eq!(s, 400, "{b}");
    assert!(b.contains("envelope id mismatch"), "{b}");
}

#[test]
fn evaluate_and_explain_decide() {
    let hex = hex_of(&tiny_proof_bytes());
    let key = proof_crypto::build::fixtures::test_key().key_ref();
    let body = serde_json::json!({
        "proof": {"cbor_hex": hex},
        "clock": 1_700_000_200u64,
        "revocations_known_at": 1_700_000_200u64,
        "no_require_status": true,
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
    assert_eq!(v["outcome"]["decision"], "pass");
    assert_eq!(v["currently_acceptable"], true);
    assert_eq!(v["currency_fail"], false);
    let (s, b) = route("POST", "/v1/explain", &body);
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["outcome"]["decision"], "pass");
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
        proof_api::server::handle(stream, &proof_api::server::Metrics::default());
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

/// Raw-socket helper: serve exactly one connection, return (status, body).
fn serve_once(raw_request: &[u8]) -> (u16, String) {
    use proof_api::server::{handle, Metrics};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = std::sync::Arc::new(Metrics::default());
    let m2 = metrics.clone();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle(stream, &m2)
    });
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(raw_request).unwrap();
    let mut raw = vec![];
    stream.read_to_end(&mut raw).unwrap();
    let status = server.join().unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[test]
fn hostile_http_never_crashes_and_never_leaks() {
    // Garbage request line.
    let (s, _) = serve_once(b"\x00\xff garbage\r\n\r\n");
    assert_eq!(s, 400);
    // Wrong HTTP version (HTTP/2 preface style).
    let (s, _) = serve_once(b"POST /v1/verify HTTP/2.0\r\nContent-Length: 2\r\n\r\n{}");
    assert_eq!(s, 400);
    // Missing version entirely.
    let (s, _) = serve_once(b"GET /v1/health\r\n\r\n");
    assert_eq!(s, 400);
    // Oversized headers.
    let big = format!(
        "GET /v1/health HTTP/1.1\r\nX-Pad: {}\r\n\r\n",
        "a".repeat(20000)
    );
    let (s, _) = serve_once(big.as_bytes());
    assert_eq!(s, 413);
    // POST without Content-Length.
    let (s, _) = serve_once(b"POST /v1/verify HTTP/1.1\r\n\r\n{}");
    assert_eq!(s, 413);
    // Content-Length over the cap (no 9 MiB allocation happens).
    let (s, _) = serve_once(b"POST /v1/verify HTTP/1.1\r\nContent-Length: 9000000\r\n\r\n");
    assert_eq!(s, 413);
}

#[test]
fn metrics_counts_without_payloads() {
    use proof_api::server::Metrics;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = std::sync::Arc::new(Metrics::default());
    let m2 = metrics.clone();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            proof_api::server::handle(stream, &m2);
        }
    });
    let get = |path: &str| {
        let mut stream = TcpStream::connect(addr).unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();
        let mut raw = vec![];
        stream.read_to_end(&mut raw).unwrap();
        String::from_utf8_lossy(&raw).into_owned()
    };
    let h = get("/v1/health");
    assert!(h.starts_with("HTTP/1.1 200 OK"));
    let n = get("/nope");
    assert!(n.starts_with("HTTP/1.1 404"));
    // Metrics sees exactly the two prior requests (not itself yet).
    let m = get("/v1/metrics");
    assert!(m.starts_with("HTTP/1.1 200 OK"));
    let body = m.split("\r\n\r\n").nth(1).unwrap();
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["requests_total"], 2);
    assert_eq!(v["responses_2xx"], 1);
    assert_eq!(v["responses_4xx"], 1);
    // No request bytes, paths, or ids leak into counters (shape only).
    assert!(body.contains("requests_total"));
    assert!(!body.contains("health"));
    server.join().unwrap();
}

#[test]
fn ingest_validates_records_with_line_numbers() {
    let ab = "ab".repeat(32);
    let body = serde_json::json!({
        "records": format!(
            "{{\"type\":\"test.event.occurred\",\"subject\":\"test:a\",\"effective_at\":1700000000,\"payload_hex\":\"{ab}\",\"meta\":\"k=v\"}}\n\
             {{\"type\":\"test.event.occurred\",\"subject\":\"test:b\",\"effective_at\":1700000001,\"payload_hex\":\"{ab}\"}}\n"
        ),
    })
    .to_string()
    .into_bytes();
    let (s, b) = route("POST", "/v1/ingest", &body);
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["ingested"], 2);
    assert_eq!(v["ids"].as_array().unwrap().len(), 2);
    assert!(v["ids"][0].as_str().unwrap().starts_with("evt:v1:"));
    assert!(v["skipped"].as_array().unwrap().is_empty());
    // Malformed line fails closed naming the line.
    let body = serde_json::json!({"records": "{\"type\":1}\n"})
        .to_string()
        .into_bytes();
    let (s, b) = route("POST", "/v1/ingest", &body);
    assert_eq!(s, 400, "{b}");
    assert!(b.contains("line 1"));
    // Unknown fields rejected, never swallowed.
    let body = serde_json::json!({"records": format!(
        "{{\"type\":\"t\",\"subject\":\"s\",\"effective_at\":1,\"payload_hex\":\"{ab}\",\"typo\":1}}\n"
    )})
    .to_string()
    .into_bytes();
    let (s, _) = route("POST", "/v1/ingest", &body);
    assert_eq!(s, 400);
    // skip_bad continues and lists the skip.
    let body = serde_json::json!({
        "records": "NOT-JSON\n",
        "skip_bad": true,
    })
    .to_string()
    .into_bytes();
    let (s, b) = route("POST", "/v1/ingest", &body);
    assert_eq!(s, 200, "{b}");
    let v: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["ingested"], 0);
    assert_eq!(v["skipped"].as_array().unwrap().len(), 1);
    // Missing records is a 400.
    let (s, _) = route("POST", "/v1/ingest", br#"{"dry_run": true}"#);
    assert_eq!(s, 400);
}
