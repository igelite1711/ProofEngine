// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 4 end-to-end: build → serialize → verify on a clean context.
//! Mutation tests simulate real tampering: content changed, ids/signatures stale.

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, LifecycleStatus, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_verify::{
    verify_proof, BuiltProof, PolicyDecision, ProofBuilder, Validity, VerifyCtx, VerifyReport,
};

fn ctx() -> VerifyCtx {
    // A live, fail-closed default: trustworthy clock inside the fixture
    // validity window and fresh revocation information all the way up to now.
    VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        ..VerifyCtx::default()
    }
}

fn event(t: EventType, subject: &str) -> proof_crypto::build::CreatedEvent {
    create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: t,
            subject: subject.into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        &Limits::default(),
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
        at_time: Some(1_700_000_100),
        context: vec![],
    }
}

struct Chain {
    built: BuiltProof,
    key_ref: String,
}

fn payment_chain() -> Chain {
    let lim = Limits::default();
    let key = fixtures::test_key();
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
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    Chain {
        built: b.build(&lim).unwrap(),
        key_ref: key.key_ref(),
    }
}

fn crypto_codes(r: &VerifyReport) -> Vec<ErrorCode> {
    r.checks
        .iter()
        .filter(|c| {
            !c.ok
                && matches!(
                    c.stage,
                    "PARSE" | "SCHEMA" | "CANONICAL" | "IDENTIFIERS" | "SIGNATURES" | "KEYS"
                )
        })
        .filter_map(|c| c.code)
        .collect()
}

/// Flip one byte inside a nested bstr/text without disturbing CBOR structure:
/// decode → mutate → re-encode (stays canonical; ids/sigs go stale).
fn mutate_proof<F>(bytes: &[u8], f: F) -> Vec<u8>
where
    F: FnOnce(&mut proof_format::CborValue),
{
    let lim = Limits::default();
    let mut v = proof_format::decode_strict(bytes, &lim).unwrap();
    f(&mut v);
    proof_format::encode_canonical(&v)
}

fn map_find<'a>(v: &'a mut proof_format::CborValue, key: &str) -> &'a mut proof_format::CborValue {
    match v {
        proof_format::CborValue::Map(pairs) => pairs
            .iter_mut()
            .find(|(k, _)| matches!(k, proof_format::CborValue::Text(s) if s == key))
            .map(|(_, v)| v)
            .expect("key must exist"),
        _ => panic!("expected map"),
    }
}

#[test]
fn valid_proof_verifies_portable() {
    let c = payment_chain();
    // Fresh context, no database: portability.
    let r = verify_proof(&c.built.canonical, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
    assert!(r.lifecycle_checked);
    assert_eq!(
        r.lifecycle
            .iter()
            .filter(|l| l.status == LifecycleStatus::Active)
            .count(),
        1
    );
    assert_eq!(r.proof_id.as_deref(), Some(c.built.id.as_str()));
    assert!(r.checks.iter().all(|c| c.ok));
    let _ = &c.key_ref;
}

#[test]
fn mutated_event_breaks_proof_id() {
    let c = payment_chain();
    let bad = mutate_proof(&c.built.canonical, |v| {
        let events = map_find(v, "events");
        let first = match events {
            proof_format::CborValue::Array(a) => &mut a[0],
            _ => panic!("events array"),
        };
        let meta = map_find(first, "metadata");
        let order = map_find(meta, "order");
        *order = proof_format::CborValue::Text("ord-2".into());
    });
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    let codes = crypto_codes(&r);
    assert!(
        codes.contains(&ErrorCode::IdMismatch),
        "expected ID_MISMATCH, got {codes:?}"
    );
    assert!(r
        .checks
        .iter()
        .any(|c| { !c.ok && c.stage == "IDENTIFIERS" && c.code == Some(ErrorCode::IdMismatch) }));
}

#[test]
fn mutated_signature_fails_signatures_stage() {
    let c = payment_chain();
    let bad = mutate_proof(&c.built.canonical, |v| {
        let atts = map_find(v, "attestations");
        let first = match atts {
            proof_format::CborValue::Array(a) => &mut a[0],
            _ => panic!("attestations array"),
        };
        let sign1 = map_find(first, "sign1");
        match sign1 {
            proof_format::CborValue::Bytes(b) => {
                let n = b.len();
                b[n - 1] ^= 0x01;
            }
            _ => panic!("sign1 bytes"),
        }
    });
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok && c.stage == "SIGNATURES" && c.code == Some(ErrorCode::SignatureInvalid)
    }));
}

#[test]
fn mutated_proof_id_fails_identifiers() {
    let c = payment_chain();
    let bad = mutate_proof(&c.built.canonical, |v| {
        let id = map_find(v, "proof_id");
        *id = proof_format::CborValue::Text(
            "prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        );
    });
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r
        .checks
        .iter()
        .any(|c| { !c.ok && c.stage == "IDENTIFIERS" && c.code == Some(ErrorCode::IdMismatch) }));
}

#[test]
fn wrong_version_fails_schema() {
    let c = payment_chain();
    let bad = mutate_proof(&c.built.canonical, |v| {
        let vv = map_find(v, "v");
        *vv = proof_format::CborValue::Uint(2);
    });
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok && c.stage == "SCHEMA" && c.code == Some(ErrorCode::UnsupportedVersion)
    }));
}

#[test]
fn ungrounded_proof_separates_crypto_from_evidence() {
    // Crypto VALID, evidence INVALID: the triple distinction under test.
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let bare = make_relationship(
        Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: RelType::new(RelType::SETTLES),
            to: inv.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_relationship(bare);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
    assert!(r.checks.iter().any(|c| {
        !c.ok && c.stage == "RELATIONSHIPS" && c.code == Some(ErrorCode::RelationshipUngrounded)
    }));
}

#[test]
fn dangling_endpoint_fails_relationships() {
    let lim = Limits::default();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let edge = make_relationship(
        Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: RelType::new(RelType::REFERENCES),
            to: "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok && c.stage == "RELATIONSHIPS" && c.code == Some(ErrorCode::DanglingReference)
    }));
}

#[test]
fn empty_proof_is_structurally_valid() {
    let lim = Limits::default();
    let built = ProofBuilder::new(proposition(), 1_700_000_200)
        .build(&lim)
        .unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    // Structure holds; whether emptiness suffices is the POLICY's call (Phase 5).
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
}

#[test]
fn builder_rejects_duplicate_members() {
    let lim = Limits::default();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay.clone());
    b.add_event(pay);
    let e = b.build(&lim).unwrap_err();
    assert_eq!(e.code, ErrorCode::SchemaViolation);
}

#[test]
fn dangling_evidence_ref_fails_evidence() {
    // PE-EVID-002: the attestation signature covers the dangling reference,
    // so crypto stays Valid while EVIDENCE fails DanglingReference.
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let mut content = fixtures::fixed_attestation_content(&key.key_ref(), &pay.id);
    content.evidence_ref = Some("evd:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    let att = attest(content, &key, &lim).unwrap();
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
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok && c.stage == "EVIDENCE" && c.code == Some(ErrorCode::DanglingReference)
    }));
}

#[test]
fn garbage_bytes_fail_parse_closed() {
    for bad in [
        vec![0xff],
        vec![0x01, 0x02],
        vec![],
        b"not a proof".to_vec(),
    ] {
        let r = verify_proof(&bad, &ctx()).unwrap();
        assert_eq!(r.cryptographic_validity, Validity::Invalid);
        // Early exit must never present a vacuous evidence Valid: no evidence
        // stage ran, so validity is unestablished (audit P1-1/P1-2).
        assert_eq!(r.evidence_validity, Validity::Invalid);
        assert!(!r.lifecycle_checked);
        assert!(r.proof_id.is_none());
        assert!(!r.checks.is_empty() && !r.checks[0].ok);
    }
}

#[test]
fn remote_fetch_request_is_caller_error() {
    let c = payment_chain();
    let mut bad_ctx = ctx();
    bad_ctx.allow_remote = true;
    let e = verify_proof(&c.built.canonical, &bad_ctx).unwrap_err();
    assert_eq!(e.code, ErrorCode::SchemaViolation);
}
