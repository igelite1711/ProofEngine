// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 5 end-to-end: same evidence, different policies, different decisions.

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, Limits};
use proof_crypto::build::revoke_attestation;
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_policy::{
    evaluate_policy, explain_full, explain_outcome, parse_policy, state_from_report_and_proof,
    EvalInputs, Policy, RevocationSet,
};
use proof_verify::{verify_proof, BuiltProof, PolicyDecision, ProofBuilder, Validity, VerifyCtx};

const ISSUED: u64 = 1_700_000_100;
const EXPIRES: u64 = 1_800_000_000;
const CLOCK_OK: u64 = 1_700_000_200;

fn limits() -> Limits {
    Limits::default()
}

/// Standalone event builder for tests that assemble chains outside `setup()`
/// (whose local closure shadows this within its own scope).
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
        &limits(),
    )
    .unwrap()
}

/// Pipeline context consistent with the policy `EvalInputs` clock: the evid-
/// ence must be timely and revocation info fresh for policy to be evaluated.
fn ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: CLOCK_OK,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK_OK),
        ..VerifyCtx::default()
    }
}

fn setup() -> (BuiltProof, String, String) {
    let lim = limits();
    let key = fixtures::test_key();
    let event = |t: EventType, subject: &str| {
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
    };
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let att_id = att.id.clone();
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(ISSUED),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    (b.build(&lim).unwrap(), key.key_ref(), att_id)
}

fn merchant_policy(issuer: &str) -> Policy {
    parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "merchant_payment_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "relationship_exists", "relationship": "SETTLES"},
                {"type": "not_expired"},
                {"type": "not_revoked"},
            ]
        }),
        &limits(),
    )
    .unwrap()
}

fn strict_policy(issuer: &str) -> Policy {
    parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "strict_transparency_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "relationship_exists", "relationship": "SETTLES"},
                {"type": "not_expired"},
                {"type": "not_revoked"},
                {"type": "transparency_present"},
            ]
        }),
        &limits(),
    )
    .unwrap()
}

fn inputs(issuer: &str) -> EvalInputs {
    EvalInputs {
        trusted_issuers: vec![issuer.into()],
        revocations: RevocationSet::empty(),
        verified_at: CLOCK_OK,
        skew_leeway: 300,
    }
}

#[test]
fn same_evidence_passes_merchant_fails_strict() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();

    let pass = evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer));
    assert_eq!(pass.decision, PolicyDecision::Pass);
    assert!(pass.results.iter().all(|r| r.passed));

    // Identical evidence, stricter policy: FAIL. Evidence ≠ Policy.
    let fail = evaluate_policy(&state, &strict_policy(&issuer), &inputs(&issuer));
    assert_eq!(fail.decision, PolicyDecision::Fail);
    let t = fail
        .results
        .iter()
        .find(|r| r.requirement == "transparency_present")
        .unwrap();
    assert!(!t.passed);
}

#[test]
fn valid_signature_by_untrusted_issuer_fails() {
    let (built, _, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    // Attacker's key is valid crypto but nobody trusts it.
    let stranger = "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "stranger",
            "requirements": [{"type": "issuer_trusted", "issuer": stranger}]
        }),
        &limits(),
    )
    .unwrap();
    let out = evaluate_policy(
        &state,
        &policy,
        &EvalInputs {
            trusted_issuers: vec![stranger.into()],
            ..inputs(stranger)
        },
    );
    // Trusted-but-absent: the stranger trusts themselves, yet they signed nothing here.
    assert_eq!(out.decision, PolicyDecision::Fail);
}

#[test]
fn expired_attestation_fails_closed_at_pipeline() {
    // Phase 6: expiry is an evidence-validity property (pipeline TIME stage).
    // A verifier clock past expiry → evidence INVALID, code EXPIRED; the
    // policy layer can then only be INDETERMINATE — never PASS.
    let (built, issuer, _) = setup();
    let late_ctx = VerifyCtx {
        verified_at: EXPIRES + 10_000,
        revocations_known_at: Some(EXPIRES + 10_000),
        ..ctx()
    };
    let report = verify_proof(&built.canonical, &late_ctx).unwrap();
    assert_eq!(report.evidence_validity, Validity::Invalid);
    assert!(report.failure_codes().contains(&ErrorCode::Expired));
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let mut late = inputs(&issuer);
    late.verified_at = EXPIRES + 10_000;
    let out = evaluate_policy(&state, &merchant_policy(&issuer), &late);
    assert_eq!(out.decision, PolicyDecision::Indeterminate);
}

#[test]
fn inconsistent_policy_clock_cannot_turn_fail_into_pass() {
    // Defense in depth: the policy-layer not_expired check remains, so a
    // caller evaluating with a divergent (later) clock still FAILs instead of
    // ever upgrading to PASS.
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let mut late = inputs(&issuer);
    late.verified_at = EXPIRES + 10_000;
    let out = evaluate_policy(&state, &merchant_policy(&issuer), &late);
    assert_eq!(out.decision, PolicyDecision::Fail);
    assert!(out
        .results
        .iter()
        .any(|r| r.requirement == "not_expired" && !r.passed));
}

#[test]
fn revoked_attestation_fails_not_revoked() {
    // Signed revocations are enforced by the pipeline (stage REVOCATION). This
    // exercise covers the remaining policy-layer path: a caller-declared id
    // list (EvalInputs.revocations) still fails `not_revoked` — defense in
    // depth only when no signed status object is in the context.
    let (built, issuer, att_id) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let mut inp = inputs(&issuer);
    inp.revocations = RevocationSet::new([att_id]);
    let out = evaluate_policy(&state, &merchant_policy(&issuer), &inp);
    assert_eq!(out.decision, PolicyDecision::Fail);
    assert!(out
        .results
        .iter()
        .any(|r| r.requirement == "not_revoked" && !r.passed));
}

#[test]
fn superseded_attestation_fails_not_superseded() {
    // Pipeline preserves superseded history as evidence-Valid (Phase 6
    // semantics); policy decides currency. Without `not_superseded` the
    // merchant policy still passes (PASS means "valid", not "current");
    // with it, the stale attestation fails closed.
    use proof_crypto::build::supersede_attestation;
    let lim = limits();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let old = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let mut new_content = old.content.clone();
    new_content.issued_at = ISSUED + 10;
    new_content.claim.claim_type = "payment.created-observed-v2".into();
    let new = attest(new_content, &key, &lim).unwrap();
    let sup = supersede_attestation(&old.id, &new.id, &key, CLOCK_OK, &lim).unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(new.id.clone()),
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(ISSUED),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(old.clone());
    b.add_attestation(new);
    b.add_attestation(sup);
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();
    let issuer = key.key_ref();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Valid);
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    assert_eq!(state.superseded_ids, vec![old.id.clone()]);
    // Default merchant policy: still PASS (currency not requested).
    let out = evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer));
    assert_eq!(out.decision, PolicyDecision::Pass);
    // Currency-sensitive policy: FAIL on the superseded attestation.
    let current = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "current_only",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "not_superseded"},
            ]
        }),
        &limits(),
    )
    .unwrap();
    let out = evaluate_policy(&state, &current, &inputs(&issuer));
    assert_eq!(out.decision, PolicyDecision::Fail);
    assert!(out
        .results
        .iter()
        .any(|r| r.requirement == "not_superseded" && !r.passed));
}

#[test]
fn credential_lifecycle_expiry_renewal_and_currency() {
    // Domain journey #2 (identity): a credential is granted with a bounded
    // validity window, lapses, then is renewed by supersession. PASS means
    // "valid", and only `not_superseded` answers "current".
    use proof_crypto::build::supersede_attestation;
    const EXP: u64 = ISSUED + 1000;
    const MID: u64 = ISSUED + 500;
    const LATE: u64 = EXP + 301;
    let lim = limits();
    let key = fixtures::test_key();
    let issuer = key.key_ref();
    let cred = event(
        EventType::new(EventType::DOCUMENT_SIGNED),
        "credential:alice-42",
    );
    let mut grant_v1 = fixtures::fixed_attestation_content(&issuer, &cred.id);
    grant_v1.claim.claim_type = "credential.granted".into();
    grant_v1.claim.fields = vec![("role".into(), MetaValue::Text("member".into()))];
    grant_v1.issued_at = ISSUED;
    grant_v1.expires_at = Some(EXP);
    let a1 = attest(grant_v1, &key, &lim).unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::CREDENTIAL),
        HashRef::new(HashAlgorithm::Sha256, vec![0xCCu8; 32]).unwrap(),
        Some(a1.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let edge = make_relationship(
        Relationship {
            v: 1,
            from: cred.id.clone(),
            rel_type: RelType::new(RelType::REFERENCES),
            to: evd.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let build_cred = |atts: Vec<proof_crypto::build::CreatedAttestation>| {
        let mut b = ProofBuilder::new(
            Proposition {
                v: 1,
                kind: "credential.membership".into(),
                subject: "credential:alice-42".into(),
                predicate: "grants".into(),
                object: None,
                at_time: Some(ISSUED),
                context: vec![],
            },
            1_700_000_200,
        );
        b.add_event(cred.clone());
        for a in atts {
            b.add_attestation(a);
        }
        b.add_evidence(evd.clone());
        b.add_relationship(edge.clone());
        b.build(&lim).unwrap()
    };
    let credential_policy = |with_currency: bool| {
        let mut reqs = vec![
            serde_json::json!({"type": "signature_valid"}),
            serde_json::json!({"type": "issuer_trusted", "issuer": issuer}),
            serde_json::json!({"type": "not_expired"}),
            serde_json::json!({"type": "not_revoked"}),
        ];
        if with_currency {
            reqs.push(serde_json::json!({"type": "not_superseded"}));
        }
        parse_policy(
            &serde_json::json!({
                "policy_version": 1,
                "policy_id": "credential_current",
                "requirements": reqs,
            }),
            &limits(),
        )
        .unwrap()
    };
    let late_ctx = || VerifyCtx {
        verified_at: LATE,
        clock_skew_leeway: 300,
        revocations_known_at: Some(LATE),
        ..VerifyCtx::default()
    };
    let late_inputs = || EvalInputs {
        trusted_issuers: vec![issuer.clone()],
        revocations: RevocationSet::empty(),
        verified_at: LATE,
        skew_leeway: 300,
    };
    let mid_ctx = || VerifyCtx {
        verified_at: MID,
        clock_skew_leeway: 300,
        revocations_known_at: Some(MID),
        ..VerifyCtx::default()
    };
    let mid_inputs = || EvalInputs {
        trusted_issuers: vec![issuer.clone()],
        revocations: RevocationSet::empty(),
        verified_at: MID,
        skew_leeway: 300,
    };

    // Phase 1: fresh grant verifies and passes.
    let p1 = build_cred(vec![a1.clone()]);
    let r1 = verify_proof(&p1.canonical, &ctx()).unwrap();
    assert_eq!(r1.evidence_validity, Validity::Valid);
    let s1 = state_from_report_and_proof(&r1, &p1.proof).unwrap();
    assert_eq!(
        evaluate_policy(&s1, &credential_policy(true), &inputs(&issuer)).decision,
        PolicyDecision::Pass
    );

    // Phase 2: past expiry the same bytes fail closed (EXPIRED, INDETERMINATE).
    let r2 = verify_proof(&p1.canonical, &late_ctx()).unwrap();
    assert_eq!(r2.evidence_validity, Validity::Invalid);
    assert!(r2.failure_codes().contains(&ErrorCode::Expired));
    let s2 = state_from_report_and_proof(&r2, &p1.proof).unwrap();
    assert_eq!(
        evaluate_policy(&s2, &credential_policy(true), &late_inputs()).decision,
        PolicyDecision::Indeterminate
    );

    // Phase 3: renewal before lapse. The old grant reads SUPERSEDED
    // (history preserved, evidence still valid); the new grant is ACTIVE.
    // NOTE: renewal must precede expiry — a proof containing an *expired*
    // attestation is evidence-invalid even if superseded (TIME poisons
    // evidence by design; an expired record reads EXPIRED, truthfully).
    let mut grant_v2 = a1.content.clone();
    grant_v2.issued_at = ISSUED + 400;
    grant_v2.expires_at = Some(LATE + 100_000);
    grant_v2.claim.claim_type = "credential.granted-v2".into();
    let a2 = attest(grant_v2, &key, &lim).unwrap();
    let sup = supersede_attestation(&a1.id, &a2.id, &key, MID, &lim).unwrap();
    let p3 = build_cred(vec![a1.clone(), a2.clone(), sup]);
    let r3 = verify_proof(&p3.canonical, &mid_ctx()).unwrap();
    assert_eq!(r3.cryptographic_validity, Validity::Valid);
    assert_eq!(r3.evidence_validity, Validity::Valid);
    let s3 = state_from_report_and_proof(&r3, &p3.proof).unwrap();
    assert_eq!(s3.superseded_ids, vec![a1.id.clone()]);
    // Validity without currency still passes on history ...
    assert_eq!(
        evaluate_policy(&s3, &credential_policy(false), &mid_inputs()).decision,
        PolicyDecision::Pass
    );
    // ... while currency fails closed on the stale grant ...
    assert_eq!(
        evaluate_policy(&s3, &credential_policy(true), &mid_inputs()).decision,
        PolicyDecision::Fail
    );
    // ... and a proof carrying only the renewal is fully current, even late.
    let p4 = build_cred(vec![a2]);
    let r4 = verify_proof(&p4.canonical, &late_ctx()).unwrap();
    let s4 = state_from_report_and_proof(&r4, &p4.proof).unwrap();
    assert!(s4.superseded_ids.is_empty());
    assert_eq!(
        evaluate_policy(&s4, &credential_policy(true), &late_inputs()).decision,
        PolicyDecision::Pass
    );
}

#[test]
fn blocklisted_issuer_fails_others_pass() {
    // Sanctions/blocklist screening: a listed issuer touching the chain
    // fails closed; an unlisted one changes nothing.
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let screen = |excluded: &str| {
        parse_policy(
            &serde_json::json!({
                "policy_version": 1,
                "policy_id": "screen",
                "requirements": [
                    {"type": "signature_valid"},
                    {"type": "issuer_excluded", "issuer": excluded},
                ]
            }),
            &limits(),
        )
        .unwrap()
    };
    let hit = evaluate_policy(&state, &screen(&issuer), &inputs(&issuer));
    assert_eq!(hit.decision, PolicyDecision::Fail);
    assert!(hit
        .results
        .iter()
        .any(|r| r.requirement.starts_with("issuer_excluded(") && !r.passed));
    let stranger = proof_crypto::Ed25519Key::from_seed(&[7u8; 32]).key_ref();
    let miss = evaluate_policy(&state, &screen(&stranger), &inputs(&issuer));
    assert_eq!(miss.decision, PolicyDecision::Pass);
}

#[test]
fn broken_proof_yields_indeterminate_not_fail() {
    let (built, issuer, _) = setup();
    // Tamper: flip a signature byte, keep everything else.
    let mut v: proof_format::CborValue =
        proof_format::decode_strict(&built.canonical, &limits()).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        let atts = pairs
            .iter_mut()
            .find(|(k, _)| matches!(k, proof_format::CborValue::Text(s) if s == "attestations"))
            .map(|(_, v)| v)
            .unwrap();
        if let proof_format::CborValue::Array(items) = atts {
            if let proof_format::CborValue::Map(ep) = &mut items[0] {
                let s = ep
                    .iter_mut()
                    .find(|(k, _)| matches!(k, proof_format::CborValue::Text(s) if s == "sign1"))
                    .map(|(_, v)| v)
                    .unwrap();
                if let proof_format::CborValue::Bytes(b) = s {
                    let n = b.len();
                    b[n - 1] ^= 0x01;
                }
            }
        }
    }
    let bad = proof_format::encode_canonical(&v);
    let report = verify_proof(&bad, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let out = evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer));
    assert_eq!(out.decision, PolicyDecision::Indeterminate);
    assert!(out.note.is_some());
}

#[test]
fn status_attestations_never_satisfy_issuer_trusted() {
    // A signed status object (revoke) by an issuer must never LEAK into the
    // verified-issuer set: it is not a statement. The state projection must
    // skip report.status_objects.
    let lim = limits();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let statement = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    let revoke = revoke_attestation(&statement.id, None, &key, CLOCK_OK, &lim).unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(statement.id.clone()),
        None,
        &lim,
    )
    .unwrap();
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(ISSUED),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(statement);
    b.add_attestation(revoke);
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();

    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.status_objects.len(), 1);
    // Revoked → evidence invalid, but the state projection must still be
    // faithful: only the statement issuer is verified.
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    assert_eq!(state.verified_issuers, vec![key.key_ref()]);
    assert_eq!(state.attestation_ids.len(), 1);
    let out = evaluate_policy(
        &state,
        &merchant_policy(&key.key_ref()),
        &inputs(&key.key_ref()),
    );
    assert_eq!(out.decision, PolicyDecision::Indeterminate);
}

#[test]
fn mismatched_report_and_proof_is_caller_error() {
    let (built, _, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let diff = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "other".into(),
            subject: "x".into(),
            predicate: "y".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        1,
    )
    .build(&limits())
    .unwrap();
    let e = state_from_report_and_proof(&report, &diff.proof).unwrap_err();
    assert_eq!(e.code, proof_core::ErrorCode::SchemaViolation);
}

#[test]
fn explanations_never_contradict_verdicts() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    for policy in [merchant_policy(&issuer), strict_policy(&issuer)] {
        let out = evaluate_policy(&state, &policy, &inputs(&issuer));
        let text = explain_outcome(&out);
        let word = match out.decision {
            PolicyDecision::Pass => "PASS",
            PolicyDecision::Fail => "FAIL",
            PolicyDecision::Indeterminate => "INDETERMINATE",
        };
        assert!(text.contains(&format!("Decision: {word}")), "{text}");
        assert!(text.contains(&format!("POLICY: {}", policy.id)));
    }
    let full = explain_full(
        &report,
        &evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer)),
    );
    assert!(full.contains("cryptographic_validity: valid"));
}

#[test]
fn explanations_carry_no_secret_or_signature_payload() {
    // PE-SEC: human/machine explanations echo ids, verdicts, and requirement
    // outcomes only — never key material, never raw signature blobs. The
    // fixed test seed is the canary: its hex/b64 must not appear in text.
    use proof_policy::explain_report;
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let outcome = evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer));
    let texts = [
        explain_report(&report),
        explain_outcome(&outcome),
        explain_full(&report, &outcome),
    ];
    let seed_hex = "09".repeat(32);
    let sign1_hex = hex::encode(&built.proof.attestations[0].sign1);
    for text in &texts {
        assert!(
            !text.contains(&seed_hex),
            "seed hex leaked into explanation"
        );
        assert!(
            !text.contains(&sign1_hex),
            "raw signature blob leaked into explanation"
        );
    }
}

/// PE-CLI-007: the machine-readable policy contract (`evaluate --json`,
/// POLICY.md "Machine-readable output") mirrors the evaluator exactly —
/// decision vocabulary and per-requirement results — and can never upgrade
/// an untrusted-issuer outcome into something stronger than the evaluator
/// produced.
#[test]
fn policy_outcome_json_matches_evaluator() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    // Same proof, empty trust list: NOT acceptable (Fail or Indeterminate —
    // never Pass, PE-NEUT-002).
    let untrusted = evaluate_policy(
        &state,
        &merchant_policy(&issuer),
        &EvalInputs {
            trusted_issuers: vec![],
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK,
            skew_leeway: 300,
        },
    );
    assert_ne!(untrusted.decision, PolicyDecision::Pass);
    // Same proof, issuer explicitly trusted: PASS.
    let trusted = evaluate_policy(&state, &merchant_policy(&issuer), &inputs(&issuer));
    assert_eq!(trusted.decision, PolicyDecision::Pass);
    // The CLI JSON projection (proof-cli/src/check.rs outcome_json) is a
    // lossless view of exactly these fields — pin the shape and values here.
    for out in [&untrusted, &trusted] {
        let v = serde_json::json!({
            "policy_id": out.policy_id,
            "decision": out.decision.as_str(),
            "note": out.note,
            "results": out
                .results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "requirement": r.requirement,
                        "passed": r.passed,
                        "message": r.message,
                    })
                })
                .collect::<Vec<_>>(),
        });
        assert_eq!(v["decision"].as_str().unwrap(), out.decision.as_str());
        let results = v["results"].as_array().unwrap();
        assert_eq!(results.len(), out.results.len());
        for (j, r) in results.iter().zip(&out.results) {
            assert_eq!(j["requirement"].as_str().unwrap(), r.requirement);
            assert_eq!(j["passed"].as_bool().unwrap(), r.passed);
            assert_eq!(j["message"].as_str().unwrap(), r.message);
        }
    }
}

#[test]
fn proof_fresh_requirement_passes_within_window() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    // Proof created_at is at CLOCK_OK (during build), verifier at CLOCK_OK + 50
    let fresh_policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "fresh_proof_v1",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 300}]
        }),
        &limits(),
    )
    .unwrap();
    let mut fresh_inputs = inputs(&issuer);
    fresh_inputs.verified_at = CLOCK_OK + 50; // 50 seconds after proof creation
    let out = evaluate_policy(&state, &fresh_policy, &fresh_inputs);
    assert_eq!(out.decision, PolicyDecision::Pass);
    let fresh_result = out
        .results
        .iter()
        .find(|r| r.requirement.contains("proof_fresh"))
        .unwrap();
    assert!(fresh_result.passed);
}

#[test]
fn proof_fresh_requirement_fails_when_stale() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    // Proof created_at is at CLOCK_OK, verifier at CLOCK_OK + 100000 (stale)
    let fresh_policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "stale_proof_v1",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 300}]
        }),
        &limits(),
    )
    .unwrap();
    let mut stale_inputs = inputs(&issuer);
    stale_inputs.verified_at = CLOCK_OK + 100_000; // Way past the freshness window
    let out = evaluate_policy(&state, &fresh_policy, &stale_inputs);
    assert_eq!(out.decision, PolicyDecision::Fail);
    let fresh_result = out
        .results
        .iter()
        .find(|r| r.requirement.contains("proof_fresh"))
        .unwrap();
    assert!(!fresh_result.passed);
}

#[test]
fn proof_fresh_zero_max_age_fails_immediately() {
    let (built, issuer, _) = setup();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    // max_age_seconds = 0 means the proof must be created at the exact same second
    let zero_fresh = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "zero_fresh_v1",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 0}]
        }),
        &limits(),
    )
    .unwrap();
    let mut inputs2 = inputs(&issuer);
    inputs2.verified_at = CLOCK_OK + 1; // Even 1 second later fails
    let out = evaluate_policy(&state, &zero_fresh, &inputs2);
    assert_eq!(out.decision, PolicyDecision::Fail);
}

#[test]
fn verify_and_evaluate_pairs_one_context() {
    use proof_policy::{verify_and_evaluate, RevocationSet as RS};
    use proof_verify::VerificationContext;
    let lim = limits();
    let key = fixtures::test_key();
    let pay = event(EventType::new(EventType::PAYMENT_CREATED), "payment:p9");
    let inv = event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i9");
    let att = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p9".into(),
            claim: proof_core::model::Claim {
                claim_type: "payment.settled".into(),
                fields: vec![("amount".into(), MetaValue::Uint(1))],
            },
            issued_at: ISSUED,
            expires_at: Some(EXPIRES),
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .unwrap();
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let rel = make_relationship(
        Relationship {
            v: 1,
            from: pay.id.clone(),
            rel_type: RelType::new("SETTLES"),
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
            at_time: Some(ISSUED),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let u = VerificationContext {
        verified_at: CLOCK_OK,
        revocations_known_at: Some(CLOCK_OK),
        trusted_issuers: vec![key.key_ref()],
        ..VerificationContext::default()
    };
    let issuer = key.key_ref();
    let policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "t",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
            ],
        }),
        &lim,
    )
    .unwrap();
    let d = verify_and_evaluate(&built.canonical, &u, &policy, RS::empty()).unwrap();
    assert_eq!(d.outcome.decision, PolicyDecision::Pass);
}

#[test]
fn created_at_restamp_moves_freshness_without_breaking_binding() {
    // ATTACKER MODEL for `proof_fresh` (see `Requirement::ProofFresh`): the
    // holder of a stale proof rewrites the unauthenticated `created_at` to
    // look fresh. The binding and all signatures survive (by design), so the
    // rewritten proof verifies — and `proof_fresh` flips to PASS. This test
    // pins that behavior so nobody mistakes the check for a security
    // boundary: strong freshness must come from signed attestation windows.
    let (built, issuer, _) = setup();
    let lim = limits();
    let stale_clock = CLOCK_OK + 100_000;
    let fresh_policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "fresh_v1",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 300}]
        }),
        &lim,
    )
    .unwrap();
    let eval_at = |proof: &proof_core::model::Proof, bytes: &[u8], clock: u64| {
        let mut c = ctx();
        c.verified_at = clock;
        c.revocations_known_at = Some(clock);
        let report = verify_proof(bytes, &c).unwrap();
        let state = state_from_report_and_proof(&report, proof).unwrap();
        let mut inp = inputs(&issuer);
        inp.verified_at = clock;
        (report, evaluate_policy(&state, &fresh_policy, &inp))
    };
    let (_, stale_out) = eval_at(&built.proof, &built.canonical, stale_clock);
    assert_eq!(stale_out.decision, PolicyDecision::Fail);

    // Re-stamp `created_at` in the envelope. No signature covers it.
    let mut v = proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        for (k, val) in pairs.iter_mut() {
            if matches!(k, proof_format::CborValue::Text(s) if s == "created_at") {
                *val = proof_format::CborValue::Uint(stale_clock);
            }
        }
    }
    let restamped = proof_format::encode_canonical(&v);
    let restamped_proof = proof_format::cbor_to_proof(
        &proof_format::decode_strict(&restamped, &lim).unwrap(),
        &lim,
    )
    .unwrap();
    let (report, fresh_out) = eval_at(&restamped_proof, &restamped, stale_clock);
    // Binding untouched: same proof_id, IDENTIFIERS clean.
    assert_eq!(restamped_proof.proof_id, built.proof.proof_id);
    assert!(!report
        .failure_codes()
        .contains(&proof_core::ErrorCode::IdMismatch));
    // ...but freshness now passes on holder-rewritten bytes. Advisory only.
    assert_eq!(fresh_out.decision, PolicyDecision::Pass);
}
