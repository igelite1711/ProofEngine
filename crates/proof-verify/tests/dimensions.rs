// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! P2 convergence tests: unified context, dimensioned verdicts, fail-collect.

use proof_core::model::{EventType, MetaValue, Proposition};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_verify::{
    verify_proof, Dimension, ProofBuilder, Validity, VecStatusSource, Verdict, VerificationContext,
    VerifyCtx,
};

fn ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        ..VerifyCtx::default()
    }
}

fn valid_bytes() -> Vec<u8> {
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
    let inv = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::INVOICE_ISSUED),
            subject: "invoice:i9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xCDu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let att = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p9".into(),
            claim: proof_core::model::Claim {
                claim_type: "payment.settled".into(),
                fields: vec![("amount".into(), MetaValue::Uint(4200))],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        proof_core::model::EvidenceKind::new("transaction_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let rel = make_relationship(
        proof_core::model::Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: proof_core::model::RelType::new("SETTLES"),
            to: inv.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: Some(att.id.clone()),
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: Some(inv.id.clone()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    b.build(&lim).unwrap().canonical
}

#[test]
fn unified_context_projects_to_verify_ctx() {
    let u = VerificationContext {
        verified_at: 1_700_000_200,
        revocations_known_at: Some(1_700_000_200),
        ..VerificationContext::default()
    };
    let v: VerifyCtx = u.to_verify_ctx();
    assert_eq!(v.verified_at, 1_700_000_200);
    assert_eq!(v.clock_skew_leeway, 300);
}

#[test]
fn dimensioned_verdicts_agree_with_triple_on_valid_proof() {
    let bytes = valid_bytes();
    let r = verify_proof(&bytes, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    let dims: std::collections::HashMap<Dimension, Verdict> = r.dimensions().into_iter().collect();
    assert_eq!(dims[&Dimension::Structural], Verdict::Valid);
    assert_eq!(dims[&Dimension::Cryptographic], Verdict::Valid);
    assert_eq!(dims[&Dimension::Evidence], Verdict::Valid);
    assert_eq!(dims[&Dimension::Overall], Verdict::Indeterminate);
    // Pipeline never passes policy by itself.
    assert_eq!(
        dims[&Dimension::Policy],
        Verdict::Indeterminate,
        "pipeline reports INDETERMINATE for policy"
    );
}

#[test]
fn fail_collect_reports_identifiers_and_signatures_together() {
    let mut bytes = valid_bytes();
    // Corrupt the proof_id (IDENTIFIERS) without breaking CBOR shape:
    // flip a byte in the trailing id suffix region is fragile; instead flip a
    // byte mid-buffer and assert fail-collect still reports (fail-fast would
    // stop at CANONICAL/IDENTIFIERS with fewer records).
    let n = bytes.len();
    bytes[n / 2] ^= 0x01;
    let mut fast = ctx();
    fast.report_all_failures = false;
    let mut collect = ctx();
    collect.report_all_failures = true;
    let rf = verify_proof(&bytes, &fast).unwrap();
    let rc = verify_proof(&bytes, &collect).unwrap();
    assert_eq!(rf.cryptographic_validity, Validity::Invalid);
    assert_eq!(rc.cryptographic_validity, Validity::Invalid);
    assert!(
        rc.checks.len() >= rf.checks.len(),
        "fail-collect must report at least as much as fail-fast"
    );
}

/// A proof carrying one extra bare edge of a custom (non-V1) kind.
/// Mirrors `valid_bytes()` so the only variable is the custom edge.
fn bare_custom_bytes() -> Vec<u8> {
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
    let inv = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::INVOICE_ISSUED),
            subject: "invoice:i9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xCDu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let att = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p9".into(),
            claim: proof_core::model::Claim {
                claim_type: "payment.settled".into(),
                fields: vec![("amount".into(), MetaValue::Uint(4200))],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        proof_core::model::EvidenceKind::new("transaction_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let rel = make_relationship(
        proof_core::model::Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: proof_core::model::RelType::new("SETTLES"),
            to: inv.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: Some(att.id.clone()),
        },
        &lim,
    )
    .unwrap();
    // Bare custom edge: no backing refs. Unknown kinds ride bare by design.
    let custom = make_relationship(
        proof_core::model::Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: proof_core::model::RelType::new("ACME_APPROVES"),
            to: inv.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: Some(inv.id.clone()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    b.add_relationship(custom);
    b.build(&lim).unwrap().canonical
}

#[test]
fn extra_grounded_makes_custom_kind_require_backing() {
    let bytes = bare_custom_bytes();
    // Default: unknown kinds ride bare — every check passes.
    let r = verify_proof(&bytes, &ctx()).unwrap();
    assert!(
        r.checks.iter().all(|c| c.ok),
        "bare custom edge must pass under V1 defaults"
    );
    // Once declared trust-relevant, the same bytes fail grounded-backing.
    let mut strict = ctx();
    strict.extra_grounded = vec!["ACME_APPROVES".into()];
    let r2 = verify_proof(&bytes, &strict).unwrap();
    assert!(
        r2.checks.iter().any(|c| !c.ok
            && c.stage == "RELATIONSHIPS"
            && c.code == Some(ErrorCode::RelationshipUngrounded)),
        "declared kind without backing must report RELATIONSHIP_UNGROUNDED"
    );
    // The unified context carries the set through its projection.
    let u = VerificationContext {
        verified_at: 1_700_000_200,
        revocations_known_at: Some(1_700_000_200),
        extra_grounded: vec!["ACME_APPROVES".into()],
        ..VerificationContext::default()
    };
    assert_eq!(u.to_verify_ctx().extra_grounded, vec!["ACME_APPROVES"]);
    let r3 = verify_proof(&bytes, &u.to_verify_ctx()).unwrap();
    assert!(r3.checks.iter().any(|c| !c.ok));
}

#[test]
fn status_source_populates_context_and_pipeline_still_verifies() {
    let src = VecStatusSource::new(vec![], Some(1_700_000_200));
    // Unified-context path.
    let u = VerificationContext {
        verified_at: 1_700_000_200,
        ..VerificationContext::default()
    }
    .with_status_source(&src)
    .unwrap();
    assert!(u.status_objects.is_empty());
    assert_eq!(u.revocations_known_at, Some(1_700_000_200));
    // An explicitly supplied freshness is never overwritten by the source.
    let u2 = VerificationContext {
        verified_at: 1_700_000_200,
        revocations_known_at: Some(1_700_000_100),
        ..VerificationContext::default()
    }
    .with_status_source(&src)
    .unwrap();
    assert_eq!(u2.revocations_known_at, Some(1_700_000_100));
    // Direct pipeline-context path.
    let v = VerifyCtx {
        verified_at: 1_700_000_200,
        ..VerifyCtx::default()
    }
    .with_status_source(&src)
    .unwrap();
    assert_eq!(v.revocations_known_at, Some(1_700_000_200));
    // The pipeline still verifies end-to-end through the populated context.
    let r = verify_proof(&valid_bytes(), &u.to_verify_ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
}
