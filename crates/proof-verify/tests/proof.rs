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
    // Explicit caller-asserted absence (these tests pin non-feed stages;
    // the feed default is pinned by empty_feed_fails_closed_by_default).
    VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        require_status_feed: false,
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

#[test]
fn evidence_digest_binding_holds_when_matching() {
    // Fix 5: reserved claim field `evidence_digest` matching the bound
    // evidence digest passes with an explicit ok record; absent field = no
    // check (backward compatible).
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let digest_hex = hex::encode([0xEEu8; 32]);
    // Evidence first (no backing ref needed for AVAILABLE).
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        None,
        None,
        &lim,
    )
    .unwrap();
    // Attestation bound to that evidence + claim digest matching it.
    let mut content = fixtures::fixed_attestation_content(&key.key_ref(), &pay.id);
    content.evidence_ref = Some(evd.id.clone());
    content
        .claim
        .fields
        .push(("evidence_digest".into(), MetaValue::Text(digest_hex)));
    let att = attest(content, &key, &lim).unwrap();
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
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert!(r
        .checks
        .iter()
        .any(|c| c.ok && c.stage == "EVIDENCE" && c.message.contains("semantic binding holds")));
}

#[test]
fn evidence_digest_mismatch_fails_closed() {
    // Fix 5: attested digest that does not match the bound evidence digest
    // fails EVIDENCE with ID_MISMATCH (semantic forgery caught).
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
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
    content.claim.fields.push((
        "evidence_digest".into(),
        MetaValue::Text(hex::encode([0xFFu8; 32])),
    ));
    let att = attest(content, &key, &lim).unwrap();
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
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r
        .checks
        .iter()
        .any(|c| !c.ok && c.stage == "EVIDENCE" && c.code == Some(ErrorCode::IdMismatch)));
}

#[test]
fn evidence_digest_non_text_fails_closed() {
    // Non-text evidence_digest (uint/bool) cannot encode hex: fail closed,
    // never silently bypass binding.
    let lim = Limits::default();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
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
        .push(("evidence_digest".into(), MetaValue::Uint(123)));
    let att = attest(content, &key, &lim).unwrap();
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
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r
        .checks
        .iter()
        .any(|c| !c.ok && c.stage == "EVIDENCE" && c.code == Some(ErrorCode::SchemaViolation)));
}

#[test]
fn derivation_cycle_fails_by_default() {
    // Fix 2: PRODUCED A->B->A fails GRAPH closed even without opt-in;
    // REFERENCES A->B->A stays linkage-valid.
    let lim = Limits::default();
    let key = fixtures::test_key();
    let a = event(EventType::new("t.a"), "item:a");
    let b = event(EventType::new("t.b"), "item:b");
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &a.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new("production_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let mk = |from: &str, to: &str, t: &str| {
        make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: RelType::new(t),
                to: to.into(),
                evidence_ref: Some(evd.id.clone()),
                attestation_ref: Some(att.id.clone()),
            },
            &lim,
        )
        .unwrap()
    };
    // Derivation cycle.
    let mut bld = ProofBuilder::new(proposition(), 1_700_000_200);
    bld.add_event(a.clone());
    bld.add_event(b.clone());
    bld.add_attestation(att.clone());
    bld.add_evidence(evd.clone());
    bld.add_relationship(mk(&a.id, &b.id, RelType::PRODUCED));
    bld.add_relationship(mk(&b.id, &a.id, RelType::PRODUCED));
    let built = bld.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r
        .checks
        .iter()
        .any(|c| !c.ok && c.stage == "GRAPH" && c.code == Some(ErrorCode::CycleDetected)));
    // REFERENCES cycle on same nodes stays valid by default.
    let mk_ref = |from: &str, to: &str| {
        make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: RelType::new(RelType::REFERENCES),
                to: to.into(),
                evidence_ref: None,
                attestation_ref: None,
            },
            &lim,
        )
        .unwrap()
    };
    let mut bld2 = ProofBuilder::new(proposition(), 1_700_000_200);
    bld2.add_event(a);
    bld2.add_event(b);
    bld2.add_attestation(att);
    bld2.add_evidence(evd);
    // Need ids again for edges: read back from builder? Re-derive via fresh
    // events is simpler — rebuild ids from known members.
    // (a/b ids are still available via the built proof members below is
    // overkill; instead construct a second minimal REFERENCES-only proof.)
    let a2 = event(EventType::new("t.a2"), "item:a2");
    let b2 = event(EventType::new("t.b2"), "item:b2");
    let a2id = a2.id.clone();
    let b2id = b2.id.clone();
    let mut bld3 = ProofBuilder::new(proposition(), 1_700_000_200);
    // Reuse key/attestation pattern for a self-contained proof.
    let key2 = fixtures::test_key();
    let att2 = attest(
        fixtures::fixed_attestation_content(&key2.key_ref(), &a2id),
        &key2,
        &lim,
    )
    .unwrap();
    let evd2 = make_evidence(
        EvidenceKind::new("production_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att2.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    bld3.add_event(a2);
    bld3.add_event(b2);
    bld3.add_attestation(att2);
    bld3.add_evidence(evd2);
    bld3.add_relationship(mk_ref(&a2id, &b2id));
    bld3.add_relationship(mk_ref(&b2id, &a2id));
    let built_ref = bld3.build(&lim).unwrap();
    let r_ref = verify_proof(&built_ref.canonical, &ctx()).unwrap();
    assert_eq!(r_ref.evidence_validity, Validity::Valid);
    let _ = bld2;
}

#[test]
fn custom_edge_cycle_fails_as_derivation_by_default() {
    // Linkage rule pin: every edge type except REFERENCES/EQUIVALENT is
    // derivation. A custom-domain cycle (e.g. ACME_APPROVES A->B->A) fails
    // GRAPH closed; only REFERENCES/EQUIVALENT ride as linkage.
    let lim = Limits::default();
    let key = fixtures::test_key();
    let a = event(EventType::new("t.a"), "item:ca");
    let b = event(EventType::new("t.b"), "item:cb");
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &a.id),
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new("production_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let mk = |from: &str, to: &str| {
        make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: RelType::new("ACME_APPROVES"),
                to: to.into(),
                evidence_ref: None,
                attestation_ref: None,
            },
            &lim,
        )
        .unwrap()
    };
    let mut bld = ProofBuilder::new(proposition(), 1_700_000_200);
    bld.add_event(a.clone());
    bld.add_event(b.clone());
    bld.add_attestation(att);
    bld.add_evidence(evd);
    bld.add_relationship(mk(&a.id, &b.id));
    bld.add_relationship(mk(&b.id, &a.id));
    let built = bld.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r
        .checks
        .iter()
        .any(|c| !c.ok && c.stage == "GRAPH" && c.code == Some(ErrorCode::CycleDetected)));
}
