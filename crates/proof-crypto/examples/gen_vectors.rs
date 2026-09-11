// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden-vector generator (vectors 01–10).
//! All randomness eliminated: fixed seeds, fixed timestamps, fixed payloads.
//! Run: `cargo run -p proof-crypto --example gen_vectors`
//! Writes `fixtures/golden-NN.json` (workspace root fixtures dir).

use proof_core::model::{
    AttestationContent, Claim, EventContent, EventType, EvidenceKind, MetaValue, RelType,
    Relationship,
};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures as build_fixtures, make_evidence, make_relationship,
};
use proof_crypto::cose::{sign_ed25519, sign_esp256};
use proof_crypto::id::{attestation_id, event_id};
use proof_crypto::keys::Ed25519Key;
use proof_crypto::keys::P256Key;
use proof_format::{attestation_to_cbor, encode_canonical, event_to_cbor};
use std::path::PathBuf;

const SEED: [u8; 32] = [9u8; 32];

fn fixtures_dir() -> PathBuf {
    // examples/ → crates/proof-crypto/examples → up 3 to workspace root → fixtures.
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
    println!("wrote {}", path.display());
}

fn main() {
    let limits = Limits::default();
    let _ = &limits;

    // ---- Vector 01: canonical EventContent + id ----
    let event = EventContent {
        v: 1,
        event_type: EventType::new(EventType::PAYMENT_CREATED),
        subject: "acct:merchant-01".into(),
        effective_at: 1_700_000_000,
        payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
    };
    let ev_canon = encode_canonical(&event_to_cbor(&event).unwrap());
    let ev_id = event_id(&ev_canon);
    write(
        "golden-01.json",
        serde_json::json!({
            "name": "01-event-canonical",
            "description": "Minimal payment.created event: canonical bytes + deterministic id.",
            "input": {
                "type": "payment.created",
                "subject": "acct:merchant-01",
                "effective_at": 1700000000,
                "payload_ref": {"v": 1, "alg": "sha-256", "digest_hex": "ab".repeat(32)},
                "metadata": {"order": "ord-1"}
            },
            "canonical_hex": hex::encode(&ev_canon),
            "object_id": ev_id,
            "expected": {"decode": "ok", "id_verify": "ok"}
        }),
    );

    // ---- Vector 02: duplicate map key ----
    write(
        "golden-02.json",
        serde_json::json!({
            "name": "02-duplicate-map-key",
            "description": "{\"a\":1,\"a\":2} must fail with DUPLICATE_MAP_KEY.",
            "input_hex": "a2616101616102",
            "expected": {"code": "DUPLICATE_MAP_KEY"}
        }),
    );

    // ---- Vector 03: non-canonical (non-shortest) int ----
    write(
        "golden-03.json",
        serde_json::json!({
            "name": "03-non-shortest-int",
            "description": "0 encoded as 0x1800 must fail with NON_CANONICAL.",
            "input_hex": "1800",
            "expected": {"code": "NON_CANONICAL"}
        }),
    );

    // ---- Vector 04: valid COSE_Sign1 (-19) over attestation ----
    let key = Ed25519Key::from_seed(&SEED);
    let issuer = key.key_ref();
    let att = AttestationContent {
        v: 1,
        issuer: issuer.clone(),
        subject: ev_id.clone(),
        claim: Claim {
            claim_type: "payment.created-observed".into(),
            fields: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        issued_at: 1_700_000_100,
        expires_at: Some(1_800_000_000),
        evidence_ref: None,
    };
    let att_canon = encode_canonical(&attestation_to_cbor(&att));
    let att_id = attestation_id(&att_canon);
    let sign1 = sign_ed25519(&att_canon, &key);
    write(
        "golden-04.json",
        serde_json::json!({
            "name": "04-valid-sign1-ed25519",
            "description": "COSE_Sign1 alg -19 over attestation content; verifies under strict policy.",
            "attestation_canonical_hex": hex::encode(&att_canon),
            "attestation_id": att_id,
            "cose_sign1_hex": hex::encode(&sign1),
            "verify_ctx": {"issuer": issuer, "allowed_algs": [-19]},
            "expected": {"verify": "ok", "alg": -19}
        }),
    );

    // ---- Vector 05: tampered payload (1-bit flip in signature) ----
    let mut bad = sign1.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    write(
        "golden-05.json",
        serde_json::json!({
            "name": "05-tampered-sign1",
            "description": "Vector 04 bytes with last byte flipped; must fail (SIGNATURE_INVALID).",
            "cose_sign1_hex": hex::encode(&bad),
            "verify_ctx": {"issuer": issuer, "allowed_algs": [-19]},
            "expected": {"verify": "fail", "code": "SIGNATURE_INVALID"}
        }),
    );

    // ---- Vectors 21/22/23: ESP256 (P-256, COSE -9) golden vectors (PE-CRYPTO-011) ----
    // Same discipline as 04/05/07 for the optional algorithm: fixed seed+payload,
    // canonical bytes pinned; tampered and wrong-issuer variants must fail. The
    // independent verifier (interop/pengine.py) re-verifies these with its own
    // pure-Python P-256 ECDSA implementation (no engine code).
    let esp_seed: [u8; 32] = [3u8; 32];
    let esp_sk = p256::ecdsa::SigningKey::from_bytes(esp_seed.as_slice().into()).unwrap();
    let esp_pk = P256Key::from_seed(&esp_seed).unwrap();
    let esp_issuer = esp_pk.key_ref().unwrap();
    let esp_payload = b"attestation-content-canonical-placeholder";
    let esp_sign1 = sign_esp256(esp_payload, &esp_pk, &esp_sk).unwrap();
    write(
        "golden-21.json",
        serde_json::json!({
            "name": "21-valid-sign1-esp256",
            "description": "COSE_Sign1 alg -9 over payload; token-verifiable only with esp256 policy.",
            "alg": -9,
            "cose_sign1_hex": hex::encode(&esp_sign1),
            "verify_ctx": {"issuer": esp_issuer, "allowed_algs": [-19, -9]},
            "expected": {"verify": "ok", "alg": -9}
        }),
    );
    let mut bad1 = esp_sign1.clone();
    let n = bad1.len();
    bad1[n - 1] ^= 0x01;
    write(
        "golden-22.json",
        serde_json::json!({
            "name": "22-tampered-sign1-esp256",
            "description": "Vector 21 bytes, last byte flipped; must fail SIGNATURE_INVALID.",
            "alg": -9,
            "cose_sign1_hex": hex::encode(&bad1),
            "verify_ctx": {"issuer": esp_issuer, "allowed_algs": [-19, -9]},
            "expected": {"verify": "fail", "code": "SIGNATURE_INVALID"}
        }),
    );
    let other_pk = P256Key::from_seed(&[7u8; 32]).unwrap();
    write(
        "golden-23.json",
        serde_json::json!({
            "name": "23-wrong-key-sign1-esp256",
            "description": "Vector 21 bytes, checked under a different issuer; key binding must fail.",
            "alg": -9,
            "cose_sign1_hex": hex::encode(&esp_sign1),
            "verify_ctx": {"issuer": other_pk.key_ref().unwrap(), "allowed_algs": [-19, -9]},
            "expected": {"verify": "fail", "code": "SIGNATURE_INVALID"}
        }),
    );
    println!("seed ed25519 pubkey: {}", hex::encode(key.pubkey_bytes()));
    println!("issuer: {issuer}");
    println!("event_id: {ev_id}");
    println!("attestation_id: {att_id}");

    // ---- Vectors 06–08: Phase 2 builder chain (event → attestation → evidence) ----
    let limits = Limits::default();
    let bkey = build_fixtures::test_key();
    let bevent = create_event(build_fixtures::fixed_event_content(), &limits).unwrap();
    let batt = attest(
        build_fixtures::fixed_attestation_content(&bkey.key_ref(), &bevent.id),
        &bkey,
        &limits,
    )
    .unwrap();
    let bevd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(batt.id.clone()),
        Some("invoice-I-9 settlement".into()),
        &limits,
    )
    .unwrap();
    write(
        "golden-06.json",
        serde_json::json!({
            "name": "06-builder-chain",
            "description": "Phase 2 builders: event + signed attestation (subject=event id) + evidence bound to attestation id. All must verify.",
            "event_canonical_hex": hex::encode(&bevent.canonical),
            "event_id": bevent.id,
            "attestation_canonical_hex": hex::encode(&batt.canonical),
            "attestation_id": batt.id,
            "cose_sign1_hex": hex::encode(&batt.sign1),
            "evidence_canonical_hex": hex::encode(&bevd.canonical),
            "evidence_id": bevd.id,
            "verify_ctx": {"issuer": bkey.key_ref(), "allowed_algs": [-19]},
            "expected": {"verify": "ok"}
        }),
    );

    // ---- Vector 07: valid artifact, wrong issuer ----
    let wrong = Ed25519Key::from_seed(&[7u8; 32]);
    write(
        "golden-07.json",
        serde_json::json!({
            "name": "07-wrong-issuer",
            "description": "Vector 06 sign1 verified under a different issuer; must fail (SIGNATURE_INVALID).",
            "cose_sign1_hex": hex::encode(&batt.sign1),
            "verify_ctx": {"issuer": wrong.key_ref(), "allowed_algs": [-19]},
            "expected": {"verify": "fail", "code": "SIGNATURE_INVALID"}
        }),
    );

    // ---- Vector 08: evidence tamper ----
    let mut tampered = bevd.content.clone();
    tampered.digest = HashRef::new(HashAlgorithm::Sha256, vec![0xEFu8; 32]).unwrap();
    let bad_ev = make_evidence(
        tampered.kind,
        tampered.digest,
        tampered.attestation_ref,
        tampered.hint,
        &limits,
    )
    .unwrap();
    write(
        "golden-08.json",
        serde_json::json!({
            "name": "08-evidence-tamper",
            "description": "Evidence bytes with substituted digest verified against the original id; must fail (ID_MISMATCH).",
            "evidence_canonical_hex": hex::encode(&bad_ev.canonical),
            "expected_id": bevd.id,
            "expected": {"verify": "fail", "code": "ID_MISMATCH"}
        }),
    );

    // ---- Vectors 09–10: graph topology over real builder ids ----
    let gkey = build_fixtures::test_key();
    let gev = |subject: &str| {
        create_event(
            EventContent {
                v: 1,
                event_type: EventType::new(EventType::PAYMENT_CREATED),
                subject: subject.into(),
                effective_at: 1_700_000_000,
                payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
                metadata: vec![],
            },
            &limits,
        )
        .unwrap()
    };
    let gco = gev("company:acme");
    let gacct = gev("account:a1");
    let gpay = gev("payment:p9");
    let ginv = gev("invoice:i9");
    let gatt = attest(
        build_fixtures::fixed_attestation_content(&gkey.key_ref(), &gpay.id),
        &gkey,
        &limits,
    )
    .unwrap();
    let gevd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(gatt.id.clone()),
        None,
        &limits,
    )
    .unwrap();
    let gedge = |from: &str, t: RelType, to: &str| {
        let r = make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: t,
                to: to.into(),
                evidence_ref: Some(gevd.id.clone()),
                attestation_ref: None,
            },
            &limits,
        )
        .unwrap();
        serde_json::json!({"canonical_hex": hex::encode(&r.canonical), "id": r.id})
    };
    write(
        "golden-09.json",
        serde_json::json!({
            "name": "09-valid-chain",
            "description": "Company OWNS Account CREATED Payment SETTLES Invoice, all grounded; graph must validate.",
            "nodes": [gco.id, gacct.id, gpay.id, ginv.id, gatt.id, gevd.id],
            "edges": [
                gedge(&gco.id, RelType::new(RelType::OWNS), &gacct.id),
                gedge(&gacct.id, RelType::new(RelType::CREATED), &gpay.id),
                gedge(&gpay.id, RelType::new(RelType::SETTLES), &ginv.id),
            ],
            "expected": {"verify": "ok", "edge_count": 3}
        }),
    );

    // ---- Vector 10: supersedes cycle ----
    let c1 = gev("doc:v1");
    let c2 = gev("doc:v2");
    let cedge = |from: &str, to: &str| {
        let r = make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: RelType::new(RelType::SUPERSEDES),
                to: to.into(),
                evidence_ref: None,
                attestation_ref: None,
            },
            &limits,
        )
        .unwrap();
        serde_json::json!({"canonical_hex": hex::encode(&r.canonical), "id": r.id})
    };
    write(
        "golden-10.json",
        serde_json::json!({
            "name": "10-supersedes-cycle",
            "description": "SUPERSEDES v1->v2->v1; graph must fail (CYCLE_DETECTED).",
            "nodes": [c1.id, c2.id],
            "edges": [cedge(&c1.id, &c2.id), cedge(&c2.id, &c1.id)],
            "expected": {"verify": "fail", "code": "CYCLE_DETECTED"}
        }),
    );
}
