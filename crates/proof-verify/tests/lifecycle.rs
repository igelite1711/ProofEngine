// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 6 lifecycle end-to-end: TIME + REVOCATION/SUPERSESSION state machine.
//! Acceptance: expired → FAIL(EXPIRED); revoked → FAIL(REVOKED); superseded →
//! SUPERSEDED with the historical note preserved; missing revocation info →
//! UNKNOWN → FAIL. Plus authority, freshness, and caller-supplied-status cases.

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, LifecycleStatus, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, revoke_attestation,
    supersede_attestation,
};
use proof_verify::{verify_proof, BuiltProof, ProofBuilder, Validity, VerifyCtx, VerifyReport};

const ISSUED: u64 = 1_700_000_100;
/// A clock inside the fixture validity window.
const NOW_OK: u64 = 1_700_000_200;
const SKEW: u64 = 300;

fn lim() -> Limits {
    Limits::default()
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
        &lim(),
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

/// Minimal payment chain: two events + one statement attestation (plus any
/// extra attestations supplied by the caller).
fn chain(atts: Vec<proof_crypto::build::CreatedAttestation>) -> BuiltProof {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(statement.id.clone()),
        None,
        &lim(),
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
        &lim(),
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(statement);
    for a in atts {
        b.add_attestation(a);
    }
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&lim()).unwrap()
}

fn live_ctx(verified_at: u64) -> VerifyCtx {
    VerifyCtx {
        verified_at,
        clock_skew_leeway: SKEW,
        revocations_known_at: Some(verified_at),
        ..VerifyCtx::default()
    }
}

fn codes(r: &VerifyReport) -> Vec<ErrorCode> {
    r.failure_codes()
}

fn status_of(r: &VerifyReport, id: &str) -> LifecycleStatus {
    r.lifecycle
        .iter()
        .find(|l| l.object == format!("att:{id}"))
        .map(|l| l.status)
        .unwrap_or(LifecycleStatus::Unknown)
}

#[test]
fn expired_attestation_fails_with_expired() {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let mut content = fixtures::fixed_attestation_content(&key.key_ref(), &pay.id);
    content.issued_at = ISSUED;
    content.expires_at = Some(ISSUED + 1); // dies essentially immediately
    let short = attest(content, &key, &lim()).unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(short.id.clone()),
        None,
        &lim(),
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
        &lim(),
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(short.clone());
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim()).unwrap();

    let report = verify_proof(&built.canonical, &live_ctx(ISSUED + 1_000)).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(report.lifecycle_checked);
    assert!(codes(&report).contains(&ErrorCode::Expired));
    assert_eq!(status_of(&report, &short.id), LifecycleStatus::Expired);
    // The expiry is reported by TIME, not by a REVOCATION failure.
    assert!(report
        .checks
        .iter()
        .any(|c| !c.ok && c.stage == "TIME" && c.code == Some(ErrorCode::Expired)));
}

#[test]
fn revoked_attestation_fails_with_revoked() {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    let revoke = revoke_attestation(&statement.id, Some("fraud"), &key, NOW_OK, &lim()).unwrap();
    let revoke_id = revoke.id.clone();
    let built = chain(vec![revoke]);
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::Revoked));
    assert_eq!(status_of(&report, &statement.id), LifecycleStatus::Revoked);
    assert!(report.status_objects.iter().any(|id| id == &revoke_id));
}

#[test]
fn expiry_within_skew_window_is_still_active() {
    // Regression (Phase 6 hostile review): skew is symmetric — the validity
    // window extends to `expires_at + skew`, so a clock just past expiry with
    // the window still open must stay ACTIVE (and the inverse case must flip
    // to EXPIRED one second beyond the extended window).
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let mut content = fixtures::fixed_attestation_content(&key.key_ref(), &pay.id);
    content.issued_at = ISSUED;
    content.expires_at = Some(NOW_OK); // hard expiry exactly at the live clock
    let short = attest(content, &key, &lim()).unwrap();
    let built = chain(vec![short.clone()]);
    // now == expires_at → inside the window; with skew 300 it stays ACTIVE.
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.evidence_validity, Validity::Valid);
    assert_eq!(status_of(&report, &short.id), LifecycleStatus::Active);
    // now == expires_at + skew + 1 → outside even the extended window.
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK + SKEW + 1)).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert_eq!(status_of(&report, &short.id), LifecycleStatus::Expired);
    assert!(codes(&report).contains(&ErrorCode::Expired));
}

#[test]
fn superseded_old_preserves_history() {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let old = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    // The replacement is a *statement* by the same issuer (new claim content).
    let new_content = proof_core::model::AttestationContent {
        issued_at: ISSUED + 1,
        claim: proof_core::model::Claim {
            claim_type: "payment.created-observed-v2".into(),
            fields: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        },
        ..fixtures::fixed_attestation_content(&key.key_ref(), &pay.id)
    };
    let new = attest(new_content, &key, &lim()).unwrap();
    let sup = supersede_attestation(&old.id, &new.id, &key, NOW_OK, &lim()).unwrap();
    let built = chain(vec![new.clone(), sup]);
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    // Historical note preserved: evidence stays valid.
    assert_eq!(report.evidence_validity, Validity::Valid);
    assert!(codes(&report).is_empty());
    assert_eq!(status_of(&report, &old.id), LifecycleStatus::Superseded);
    assert_eq!(status_of(&report, &new.id), LifecycleStatus::Active);
    assert!(report
        .checks
        .iter()
        .any(|c| { c.ok && c.stage == "REVOCATION" && c.message.contains("SUPERSEDED") }));
}
#[test]
fn missing_revocation_info_fails_closed() {
    let built = chain(vec![]);
    let mut ctx = live_ctx(NOW_OK);
    ctx.revocations_known_at = None;
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::RevocationUnknown));
    let statement = &built.proof.attestations[0];
    let id = {
        let canon =
            proof_format::encode_canonical(&proof_format::attestation_to_cbor(&statement.content));
        proof_crypto::id::attestation_id(&canon)
    };
    assert_eq!(status_of(&report, &id), LifecycleStatus::Unknown);
}

#[test]
fn stale_revocation_info_fails_closed() {
    let built = chain(vec![]);
    let mut ctx = live_ctx(NOW_OK + 400); // 700s after the status was obtained
    ctx.revocations_known_at = Some(NOW_OK);
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::RevocationUnknown));
}

#[test]
fn zero_clock_fails_closed() {
    let built = chain(vec![]);
    let mut ctx = live_ctx(NOW_OK);
    ctx.verified_at = 0;
    ctx.revocations_known_at = Some(0);
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    // No trustworthy clock: timeliness cannot be established → EXPIRED.
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::Expired));
    assert!(report
        .checks
        .iter()
        .any(|c| c.stage == "TIME" && !c.ok && c.message.contains("no trustworthy clock")));
}

#[test]
fn unauthorized_revocation_fails() {
    let key = fixtures::test_key();
    let other = proof_crypto::Ed25519Key::from_seed(&[7u8; 32]);
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    // `other` has no authority over an attestation issued by `key`.
    let forged = revoke_attestation(&statement.id, None, &other, NOW_OK, &lim()).unwrap();
    let built = chain(vec![forged]);
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::UnauthorizedStatus));
    // The effect never applied: target stays ACTIVE (the failure is the
    // unauthorized status object itself).
    assert_eq!(status_of(&report, &statement.id), LifecycleStatus::Active);
}

#[test]
fn revocation_authority_may_revoke() {
    let key = fixtures::test_key();
    let authority = proof_crypto::Ed25519Key::from_seed(&[11u8; 32]);
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    let revoke = revoke_attestation(&statement.id, None, &authority, NOW_OK, &lim()).unwrap();
    let built = chain(vec![revoke]);
    let mut ctx = live_ctx(NOW_OK);
    ctx.revocation_authorities = vec![authority.key_ref()];
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::Revoked));
    assert_eq!(status_of(&report, &statement.id), LifecycleStatus::Revoked);
}

#[test]
fn caller_supplied_revocation_applies() {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    let revoke = revoke_attestation(&statement.id, None, &key, NOW_OK, &lim()).unwrap();
    let built = chain(vec![]);
    let mut ctx = live_ctx(NOW_OK);
    ctx.status_objects = vec![proof_crypto::to_signed_status(&revoke).unwrap()];
    let report = verify_proof(&built.canonical, &ctx).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::Revoked));
    assert_eq!(status_of(&report, &statement.id), LifecycleStatus::Revoked);
}

#[test]
fn future_dated_status_object_ignored() {
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim(),
    )
    .unwrap();
    // signed an hour in the future: cannot be a present-day revocation
    let revoke = revoke_attestation(&statement.id, None, &key, NOW_OK + 3_600, &lim()).unwrap();
    let built = chain(vec![revoke]);
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(codes(&report).contains(&ErrorCode::Expired));
    // Not applied: still active under an otherwise valid context.
    assert_eq!(status_of(&report, &statement.id), LifecycleStatus::Active);
}

#[test]
fn active_proof_reports_active_lifecycle() {
    let built = chain(vec![]);
    let report = verify_proof(&built.canonical, &live_ctx(NOW_OK)).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Valid);
    assert!(report.lifecycle_checked);
    assert!(report.checks.iter().all(|c| c.ok));
    // Exactly one statement attestation → exactly one lifecycle record.
    assert_eq!(report.lifecycle.len(), 1);
    assert_eq!(report.lifecycle[0].status, LifecycleStatus::Active);
}
