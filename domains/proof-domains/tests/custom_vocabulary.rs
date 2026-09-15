// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Extension-seam proof: a brand-new `acme` vocabulary — custom event types,
//! evidence kinds, and a custom trust-relevant relationship kind — verifies
//! end-to-end with ZERO core changes (no new crate code, no new requirement
//! types, no registry entry). Open labels transport verbatim; caller-declared
//! `extra_grounded` promotes a custom kind to trust-relevant; policy judges
//! custom vocabulary like any other. If a future change makes the core care
//! about a specific industry's words, this test (plus `check_neutrality.py`)
//! fails.

use proof_core::model::{EventType, EvidenceKind, MetaValue, Proposition, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_policy::{evaluate_policy, parse_policy, state_from_report_and_proof};
use proof_verify::{verify_proof, PolicyDecision, ProofBuilder, Validity, VerifyCtx};

const CLOCK: u64 = 1_700_000_200;

fn lim() -> Limits {
    Limits::default()
}

fn ctx_extra(grounded: &[&str]) -> VerifyCtx {
    VerifyCtx {
        verified_at: CLOCK,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK),
        extra_grounded: grounded.iter().map(|s| s.to_string()).collect(),
        // Vocabulary tests, not feed tests: explicit caller-asserted absence.
        require_status_feed: false,
        ..VerifyCtx::default()
    }
}

/// Build the acme journey. `grounded=false` leaves the custom edge bare
/// (valid open vocabulary); `true` backs it with evidence + attestation.
fn acme_proof(grounded: bool) -> proof_verify::BuiltProof {
    let lim = lim();
    let key = fixtures::test_key();
    let minted = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("acme:widget.minted"),
            subject: "acme:widget:W-1".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let shipped = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("acme:widget.shipped"),
            subject: "acme:widget:W-1".into(),
            effective_at: 1_700_000_050,
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
            subject: "acme:widget:W-1".into(),
            claim: proof_core::model::Claim {
                claim_type: "acme:quality.passed".into(),
                fields: vec![("grade".into(), MetaValue::Text("A".into()))],
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
        EvidenceKind::new("acme:quality_report"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let (evidence_ref, attestation_ref) = if grounded {
        (Some(evd.id.clone()), Some(att.id.clone()))
    } else {
        (None, None)
    };
    let edge = make_relationship(
        Relationship {
            v: 1,
            from: minted.id.clone(),
            rel_type: RelType::new("ACME_APPROVES"),
            to: shipped.id.clone(),
            evidence_ref,
            attestation_ref,
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "acme:widget.lifecycle".into(),
            subject: minted.id.clone(),
            predicate: "approved".into(),
            object: Some(shipped.id.clone()),
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK,
    );
    b.add_event(minted);
    b.add_event(shipped);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(edge);
    b.build(&lim).unwrap()
}

#[test]
fn novel_vocabulary_verifies_with_zero_core_changes() {
    // Namespaces partition labels: acme words can never collide with another
    // industry's identical suffix by construction.
    assert_eq!(proof_core::model::vocabulary_ns("acme:widget.minted"), "acme");
    assert_eq!(
        proof_core::model::vocabulary_ns("acme:quality.passed"),
        "acme"
    );
    // Grounded custom journey: valid under V1 defaults AND under the
    // caller-declared trust-relevant promotion.
    for extra in [vec![], vec!["ACME_APPROVES"]] {
        let built = acme_proof(true);
        let report = verify_proof(&built.canonical, &ctx_extra(&extra)).unwrap();
        assert_eq!(report.cryptographic_validity, Validity::Valid);
        assert_eq!(report.evidence_validity, Validity::Valid);
    }
    // Bare custom edge: open vocabulary, valid by default — but once the
    // caller promotes the kind via extra_grounded, the SAME bytes fail
    // closed with RELATIONSHIP_UNGROUNDED. No core change in either branch.
    let bare = acme_proof(false);
    let r = verify_proof(&bare.canonical, &ctx_extra(&[])).unwrap();
    assert_eq!(r.evidence_validity, Validity::Valid);
    let r = verify_proof(&bare.canonical, &ctx_extra(&["ACME_APPROVES"])).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| !c.ok
        && c.stage == "RELATIONSHIPS"
        && c.code == Some(proof_core::ErrorCode::RelationshipUngrounded)));
}

#[test]
fn novel_vocabulary_policy_judges_custom_kinds() {
    // Policy over custom vocabulary needs no new requirement types:
    // relationship_exists / evidence_present match open strings.
    let built = acme_proof(true);
    let report = verify_proof(&built.canonical, &ctx_extra(&[])).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let issuer = fixtures::test_key().key_ref();
    let policy = parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "acme_quality_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "relationship_exists", "relationship": "ACME_APPROVES"},
                {"type": "evidence_present", "kind": "acme:quality_report"},
            ],
        }),
        &lim(),
    )
    .unwrap();
    let outcome = evaluate_policy(
        &state,
        &policy,
        &proof_policy::EvalInputs {
            trusted_issuers: vec![issuer],
            revocations: proof_policy::RevocationSet::empty(),
            verified_at: CLOCK,
            skew_leeway: 300,
        },
    );
    assert_eq!(outcome.decision, PolicyDecision::Pass);
}
