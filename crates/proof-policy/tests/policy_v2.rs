// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy v2: boolean connectives + thresholds over leaves, and the ten
//! adjudication leaves (delegation, identity, transparency, conflict,
//! vocabulary, usability, binding). V1 frozen behavior is asserted alongside:
//! v2 leaf names never parse under v1, and v1 verdicts are byte-identical.

use proof_core::model::{Claim, EventType, EvidenceKind, MetaValue, Proposition, RelType};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, CreatedAttestation,
};
use proof_policy::{
    canonical_policy_hash, evaluate_policy, parse_policy, policy_to_canonical_cbor,
    state_from_report_and_proof, EvalInputs, Policy, RevocationSet,
};
use proof_verify::{verify_proof, PolicyDecision, ProofBuilder, Validity, VerifyCtx};

const CLOCK_OK: u64 = 1_700_000_200;

fn limits() -> Limits {
    Limits::default()
}

fn ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: CLOCK_OK,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK_OK),
        // Feed-behavior-independent tests: explicit caller-asserted absence
        // (default fails closed; see proof-verify lifecycle tests).
        require_status_feed: false,
        ..VerifyCtx::default()
    }
}

fn v2(id: &str, expression: serde_json::Value) -> Policy {
    parse_policy(
        &serde_json::json!({
            "policy_version": 2,
            "policy_id": id,
            "expression": expression,
        }),
        &limits(),
    )
    .unwrap()
}

fn statement(
    key: &proof_crypto::Ed25519Key,
    subject: &str,
    claim_type: &str,
    fields: Vec<(String, MetaValue)>,
) -> CreatedAttestation {
    attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: subject.into(),
            claim: Claim {
                claim_type: claim_type.into(),
                fields,
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        key,
        &limits(),
    )
    .unwrap()
}

// ---------- parsing ----------

#[test]
fn v2_connectives_parse_and_describe() {
    let p = v2(
        "demo",
        serde_json::json!({
            "any": [
                {"type": "signature_valid"},
                {"all": [
                    {"type": "issuer_trusted", "issuer": "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                    {"not": {"type": "not_expired"}}
                ]},
                {"threshold": {"k": 1, "of": [{"type": "not_revoked"}]}}
            ]
        }),
    );
    assert_eq!(p.version, 2);
    assert!(p.requirements.is_empty());
    let d = match &p.expression {
        Some(e) => e.describe(),
        None => panic!("v2 must carry an expression"),
    };
    assert!(d.starts_with("any["));
    assert!(d.contains("threshold(1/1)"));
}

#[test]
fn v2_rejects_vacuous_and_impossible_shapes() {
    for expr in [
        serde_json::json!({"all": []}),
        serde_json::json!({"any": []}),
        serde_json::json!({"threshold": {"k": 0, "of": [{"type": "signature_valid"}]}}),
        serde_json::json!({"threshold": {"k": 2, "of": [{"type": "signature_valid"}]}}),
        serde_json::json!({"not": [{"type": "signature_valid"}]}),
        serde_json::json!({"all": [{"type": "signature_valid"}], "any": []}),
        serde_json::json!({"type": "signature_valid", "all": []}),
        serde_json::json!({"all": [{"type": "vibes_good"}]}),
        serde_json::json!({"threshold": {"k": "two", "of": []}}),
    ] {
        let v = serde_json::json!({
            "policy_version": 2, "policy_id": "bad", "expression": expr,
        });
        assert!(parse_policy(&v, &limits()).is_err(), "must reject {expr}");
    }
    // v2 rejects the v1 requirements key (strict separation, no ambiguity).
    let v = serde_json::json!({
        "policy_version": 2, "policy_id": "bad",
        "requirements": [{"type": "signature_valid"}],
    });
    assert!(parse_policy(&v, &limits()).is_err());
}

#[test]
fn v1_rejects_v2_leaf_names_and_stays_frozen() {
    for t in [
        "delegated_authority",
        "identity_bound",
        "transparency_inclusion",
        "no_conflicting_evidence",
        "vocabulary_accepted",
        "evidence_usable",
        "evidence_bound",
        "requires_reference",
        "forbids_reference",
        "claim_field",
    ] {
        let v = serde_json::json!({
            "policy_version": 1, "policy_id": "frozen",
            "requirements": [{"type": t}],
        });
        assert!(parse_policy(&v, &limits()).is_err(), "v1 must reject {t}");
    }
    // V1 canonical bytes are unaffected by v2's existence.
    let v1 = parse_policy(
        &serde_json::json!({
            "policy_version": 1, "policy_id": "stable",
            "requirements": [{"type": "signature_valid"}],
        }),
        &limits(),
    )
    .unwrap();
    assert_eq!(v1.expression, None);
    assert_eq!(v1.requirements.len(), 1);
}

#[test]
fn v2_node_budget_enforced() {
    // 33 nested `not`s exceed the 32-node default budget.
    let mut expr = serde_json::json!({"type": "signature_valid"});
    for _ in 0..33 {
        expr = serde_json::json!({"not": expr});
    }
    let v = serde_json::json!({
        "policy_version": 2, "policy_id": "deep", "expression": expr,
    });
    assert_eq!(
        parse_policy(&v, &limits()).unwrap_err().code,
        proof_core::ErrorCode::LimitExceeded
    );
}

#[test]
fn v2_canonical_cbor_deterministic_and_versioned() {
    let a = v2(
        "h",
        serde_json::json!({"threshold": {"k": 1, "of": [{"type": "not_revoked"}]}}),
    );
    let b = v2(
        "h",
        serde_json::json!({"threshold": {"k": 1, "of": [{"type": "not_revoked"}]}}),
    );
    assert_eq!(policy_to_canonical_cbor(&a), policy_to_canonical_cbor(&b));
    let h = canonical_policy_hash(&a);
    assert!(h.starts_with("policy:v2:"));
    // v1 hash shape unchanged.
    let v1 = parse_policy(
        &serde_json::json!({
            "policy_version": 1, "policy_id": "h",
            "requirements": [{"type": "signature_valid"}],
        }),
        &limits(),
    )
    .unwrap();
    assert!(canonical_policy_hash(&v1).starts_with("policy:v1:"));
}

// ---------- evaluation helpers ----------

fn base_proof(extra_atts: Vec<CreatedAttestation>) -> proof_verify::BuiltProof {
    let lim = limits();
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
    let att = statement(
        &key,
        "payment:p9",
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(4200))],
    );
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
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
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    for a in extra_atts {
        b.add_attestation(a);
    }
    b.add_evidence(evd);
    b.add_relationship(rel);
    b.build(&lim).unwrap()
}

fn eval_built(
    built: &proof_verify::BuiltProof,
    policy: &Policy,
    trusted: Vec<String>,
) -> proof_policy::PolicyOutcome {
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Valid);
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    evaluate_policy(
        &state,
        policy,
        &EvalInputs {
            trusted_issuers: trusted,
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK,
            skew_leeway: 300,
        },
    )
}

// ---------- connectives ----------

#[test]
fn v2_or_and_not_and_threshold_decide() {
    let built = base_proof(vec![]);
    let issuer = fixtures::test_key().key_ref();
    let other = "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let trusted = vec![issuer.clone()];

    // any() passes when either side passes.
    let p = v2(
        "either",
        serde_json::json!({"any": [
            {"type": "issuer_trusted", "issuer": other},
            {"type": "issuer_trusted", "issuer": issuer},
        ]}),
    );
    assert_eq!(
        eval_built(&built, &p, trusted.clone()).decision,
        PolicyDecision::Pass
    );
    // all() fails when one side fails.
    let p = v2(
        "both",
        serde_json::json!({"all": [
            {"type": "issuer_trusted", "issuer": issuer},
            {"type": "relationship_exists", "relationship": "NEVER_HAPPENS"},
        ]}),
    );
    assert_eq!(
        eval_built(&built, &p, trusted.clone()).decision,
        PolicyDecision::Fail
    );
    // not() inverts; double negation restores.
    let p = v2(
        "neg",
        serde_json::json!({"not": {"type": "relationship_exists", "relationship": "NEVER_HAPPENS"}}),
    );
    assert_eq!(
        eval_built(&built, &p, trusted.clone()).decision,
        PolicyDecision::Pass
    );
    // threshold 2-of-3 (corroboration quorum shape).
    let p = v2(
        "quorum",
        serde_json::json!({"threshold": {"k": 2, "of": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer},
            {"type": "relationship_exists", "relationship": "NEVER_HAPPENS"},
        ]}}),
    );
    assert_eq!(
        eval_built(&built, &p, trusted.clone()).decision,
        PolicyDecision::Pass
    );
    let p = v2(
        "quorum-missed",
        serde_json::json!({"threshold": {"k": 3, "of": [
            {"type": "signature_valid"},
            {"type": "issuer_trusted", "issuer": issuer},
            {"type": "relationship_exists", "relationship": "NEVER_HAPPENS"},
        ]}}),
    );
    // k=3 of 3 with one failing leaf: parses (k ≤ n) but FAILs.
    assert_eq!(
        eval_built(&built, &p, trusted).decision,
        PolicyDecision::Fail
    );
}

#[test]
fn v2_broken_proof_stays_indeterminate() {
    let built = base_proof(vec![]);
    let mut bad = built.canonical.clone();
    let n = bad.len();
    bad[n / 2] ^= 0x01;
    let report = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Invalid);
    let state = state_from_report_and_proof(&report, &built.proof);
    // Mismatched pair is a caller error; verify the guard via matching bytes.
    assert!(state.is_err());
    let p = v2(
        "any",
        serde_json::json!({"any": [{"type": "signature_valid"}]}),
    );
    let report = verify_proof(&bad, &ctx()).unwrap();
    // Re-parse the mutated bytes for a matching (invalid) pair.
    let value = proof_format::decode_strict(&bad, &limits());
    if let Ok(v) = value {
        if let Ok(proof) = proof_format::cbor_to_proof(&v, &limits()) {
            let state = state_from_report_and_proof(&report, &proof).unwrap();
            let out = evaluate_policy(
                &state,
                &p,
                &EvalInputs {
                    trusted_issuers: vec![],
                    ..EvalInputs::default()
                },
            );
            assert_eq!(out.decision, PolicyDecision::Indeterminate);
            assert!(out.results.is_empty());
        }
    }
}

// ---------- delegation ----------

#[test]
fn v2_delegated_authority_chains() {
    // Org root → regional signer → device operator: two delegate links.
    let lim = limits();
    let root = proof_crypto::Ed25519Key::from_seed(&[21u8; 32]);
    let mid = proof_crypto::Ed25519Key::from_seed(&[22u8; 32]);
    let leaf = proof_crypto::Ed25519Key::from_seed(&[23u8; 32]);
    let delegate = |by: &proof_crypto::Ed25519Key, to: &str| {
        attest(
            proof_core::model::AttestationContent {
                v: 1,
                issuer: by.key_ref(),
                subject: to.into(),
                claim: Claim {
                    claim_type: "delegate".into(),
                    fields: vec![],
                },
                issued_at: 1_700_000_100,
                expires_at: None,
                evidence_ref: None,
            },
            by,
            &lim,
        )
        .unwrap()
    };
    // Leaf's payment statement, signed by the leaf operator.
    let pay_statement = statement(
        &leaf,
        "payment:p9",
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(1))],
    );
    let built = base_proof(vec![
        delegate(&root, &mid.key_ref()),
        delegate(&mid, &leaf.key_ref()),
        pay_statement,
    ]);
    let target = leaf.key_ref();
    let p = v2(
        "chain",
        serde_json::json!({"type": "delegated_authority",
            "root": root.key_ref(), "issuer": target}),
    );
    let out = eval_built(&built, &p, vec![root.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Trusting mid does not satisfy a root-pinned requirement: the named
    // root itself must be listed (delegation without a trusted root is nothing).
    let out = eval_built(&built, &p, vec![mid.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // A mid-rooted requirement passes over the mid→leaf link.
    let p_mid = v2(
        "chain-mid",
        serde_json::json!({"type": "delegated_authority",
            "root": mid.key_ref(), "issuer": target}),
    );
    let out = eval_built(&built, &p_mid, vec![mid.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    let stranger = "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let out = eval_built(&built, &p, vec![stranger.clone()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // Unknown issuer has no verified attestation: fails even under root.
    let p2 = v2(
        "chain-unknown",
        serde_json::json!({"type": "delegated_authority",
            "root": root.key_ref(), "issuer": stranger}),
    );
    let out = eval_built(&built, &p2, vec![root.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
}

// ---------- identity ----------

#[test]
fn v2_identity_bound_paths() {
    let authority = fixtures::test_key();
    // authority binds did:acme:42 ≡ account:acme-42.
    let bind = statement(
        &authority,
        "did:acme:42",
        "identity.bind",
        vec![(
            "equivalent".into(),
            MetaValue::Text("account:acme-42".into()),
        )],
    );
    let built = base_proof(vec![bind]);
    let p = v2(
        "bound",
        serde_json::json!({"type": "identity_bound",
            "a": "did:acme:42", "b": "account:acme-42"}),
    );
    let out = eval_built(&built, &p, vec![authority.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Untrusted asserter: the binding exists but nobody trusted said so.
    let out = eval_built(&built, &p, vec![]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // Reflexivity holds without any binding.
    let p = v2(
        "self",
        serde_json::json!({"type": "identity_bound", "a": "x", "b": "x"}),
    );
    let out = eval_built(&built, &p, vec![]);
    assert_eq!(out.decision, PolicyDecision::Pass);
}

// ---------- transparency ----------

#[test]
fn v2_transparency_inclusion() {
    let lim = limits();
    let log = proof_crypto::Ed25519Key::from_seed(&[31u8; 32]);
    // Log checkpoint (currently valid) + receipt bound to it.
    let checkpoint = statement(
        &log,
        "scitt:example-log",
        "transparency.checkpoint",
        vec![("sequence".into(), MetaValue::Uint(987))],
    );
    let receipt = make_evidence(
        EvidenceKind::new("transparency_receipt"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(checkpoint.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    // Build a proof carrying both (reuse base members + extras).
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(checkpoint.clone());
    b.add_evidence(receipt);
    let built = b.build(&lim).unwrap();
    let p = v2(
        "inclusion",
        serde_json::json!({"type": "transparency_inclusion", "log": log.key_ref()}),
    );
    let out = eval_built(&built, &p, vec![log.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Wrong log: no checkpoint by that identity.
    let p = v2(
        "inclusion-wrong",
        serde_json::json!({"type": "transparency_inclusion", "log": key.key_ref()}),
    );
    let out = eval_built(&built, &p, vec![key.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
}

// ---------- conflicts ----------

#[test]
fn v2_conflict_adjudication_with_threshold() {
    // Two authorities assert different amounts: recorded conflict, then a
    // 1-of-2 issuer quorum adjudicates (corroboration pattern in reverse:
    // either authority suffices this verifier).
    let key_a = fixtures::test_key();
    let key_b = proof_crypto::Ed25519Key::from_seed(&[41u8; 32]);
    // Base proof already asserts amount=4200 by key_a; `b` disagrees (4300).
    let b = statement(
        &key_b,
        "payment:p9",
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(4300))],
    );
    let built = base_proof(vec![b]);
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    // Strict: any conflict fails.
    let p = v2(
        "strict",
        serde_json::json!({"type": "no_conflicting_evidence"}),
    );
    let out = eval_built(&built, &p, vec![key_a.key_ref(), key_b.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // Adjudicated: either trusted issuer suffices.
    let p = v2(
        "either",
        serde_json::json!({"any": [
            {"type": "issuer_trusted", "issuer": key_a.key_ref()},
            {"type": "issuer_trusted", "issuer": key_b.key_ref()},
        ]}),
    );
    let out = eval_built(&built, &p, vec![key_a.key_ref(), key_b.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass);
    // Clean proof has no conflicts.
    let clean = base_proof(vec![]);
    let p = v2(
        "strict",
        serde_json::json!({"type": "no_conflicting_evidence"}),
    );
    let out = eval_built(&clean, &p, vec![key_a.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass);
}

// ---------- vocabulary + usability ----------

#[test]
fn v2_vocabulary_and_usability() {
    let lim = limits();
    let key = fixtures::test_key();
    let pay = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("acme:invoice.issued"),
            subject: "invoice:i9".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "acme:settles".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_vocabulary("acme".into(), 2).unwrap();
    let built = b.build(&lim).unwrap();
    // Declared ns within max: passes.
    let p = v2(
        "vocab",
        serde_json::json!({"type": "vocabulary_accepted", "ns": "acme", "max_version": 2}),
    );
    let out = eval_built(&built, &p, vec![key.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Stricter max: fails.
    let p = v2(
        "vocab-strict",
        serde_json::json!({"type": "vocabulary_accepted", "ns": "acme", "max_version": 1}),
    );
    let out = eval_built(&built, &p, vec![key.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // Unused namespace passes vacuously.
    let p = v2(
        "vocab-absent",
        serde_json::json!({"type": "vocabulary_accepted", "ns": "other", "max_version": 1}),
    );
    let out = eval_built(&built, &p, vec![key.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass);
}

#[test]
fn v2_delegation_cycles_terminate_and_scopes_bind() {
    let lim = limits();
    let a = proof_crypto::Ed25519Key::from_seed(&[51u8; 32]);
    let b = proof_crypto::Ed25519Key::from_seed(&[52u8; 32]);
    let delegate = |by: &proof_crypto::Ed25519Key, to: &str, scope: Option<&str>| {
        let mut fields = vec![];
        if let Some(sc) = scope {
            fields.push(("scope".into(), MetaValue::Text(sc.into())));
        }
        attest(
            proof_core::model::AttestationContent {
                v: 1,
                issuer: by.key_ref(),
                subject: to.into(),
                claim: Claim {
                    claim_type: "delegate".into(),
                    fields,
                },
                issued_at: 1_700_000_100,
                expires_at: None,
                evidence_ref: None,
            },
            by,
            &lim,
        )
        .unwrap()
    };
    // Cycle A→B→A plus a scoped A→B grant; leaf statement by B.
    let pay_statement = statement(
        &b,
        "payment:p9",
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(1))],
    );
    let built = base_proof(vec![
        delegate(&a, &b.key_ref(), None),
        delegate(&b, &a.key_ref(), None),
        delegate(&a, &b.key_ref(), Some("payments")),
        pay_statement,
    ]);
    // Cycle terminates: unreachable target fails, it does not hang.
    let p = v2(
        "cycle",
        serde_json::json!({"type": "delegated_authority",
            "root": a.key_ref(), "issuer": "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
    );
    let out = eval_built(&built, &p, vec![a.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
    // Reachable through the cycle without looping.
    let p = v2(
        "through-cycle",
        serde_json::json!({"type": "delegated_authority",
            "root": a.key_ref(), "issuer": b.key_ref()}),
    );
    let out = eval_built(&built, &p, vec![a.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Scope binds: matching scope passes, mismatched scope fails.
    let p = v2(
        "scoped",
        serde_json::json!({"type": "delegated_authority",
            "root": a.key_ref(), "issuer": b.key_ref(), "scope": "payments"}),
    );
    let out = eval_built(&built, &p, vec![a.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    let p = v2(
        "scoped-wrong",
        serde_json::json!({"type": "delegated_authority",
            "root": a.key_ref(), "issuer": b.key_ref(), "scope": "refunds"}),
    );
    let out = eval_built(&built, &p, vec![a.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail);
}

#[test]
fn v2_contradiction_edge_over_non_statements_notes_without_conflict() {
    // A grounded CONTRADICTS edge pointing at an event is graph-valid but
    // records no conflict (opposition needs two verified claims); a note
    // says so, validity unchanged.
    let lim = limits();
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
    let att = statement(
        &key,
        "payment:p9",
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(1))],
    );
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    let contra = make_relationship(
        proof_core::model::Relationship {
            v: 1,
            from: att.id.clone(),
            rel_type: RelType::new("CONTRADICTS"),
            to: pay.id.clone(),
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
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(contra);
    let built = b.build(&lim).unwrap();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Valid);
    assert!(report.conflicts.is_empty());
    assert!(report.checks.iter().any(|c| c.ok
        && c.message
            .contains("does not connect two verified statements")));
}

#[test]
fn v2_identity_bound_via_equivalent_edge() {
    // Identity through a grounded EQUIVALENT relationship edge (not a claim):
    // asserter key attests, edge links did:x ≡ acct:x with attestation_ref.
    let lim = limits();
    let asserter = fixtures::test_key();
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
    let anchor = statement(&asserter, "payment:p9", "identity.witnessed", vec![]);
    let edge = make_relationship(
        proof_core::model::Relationship {
            v: 1,
            from: "did:example:alice".into(),
            rel_type: RelType::new("EQUIVALENT"),
            to: "account:alice-1".into(),
            evidence_ref: None,
            attestation_ref: Some(anchor.id.clone()),
        },
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "identity.link".into(),
            subject: "did:example:alice".into(),
            predicate: "equivalent".into(),
            object: Some("account:alice-1".into()),
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(anchor);
    b.add_relationship(edge);
    let built = b.build(&lim).unwrap();
    let p = v2(
        "edge-bound",
        serde_json::json!({"type": "identity_bound",
            "a": "did:example:alice", "b": "account:alice-1"}),
    );
    let out = eval_built(&built, &p, vec![asserter.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // Same edge, untrusted asserter: no merge.
    let out = eval_built(&built, &p, vec![]);
    assert_eq!(out.decision, PolicyDecision::Fail);
}

#[test]
fn v2_transparency_checkpoint_expiry_has_teeth() {
    // An EXPIRED checkpoint poisons evidence validity first (TIME fails), so
    // policy short-circuits to INDETERMINATE — freshness has teeth before
    // the leaf is even reached.
    let lim = limits();
    let log = proof_crypto::Ed25519Key::from_seed(&[33u8; 32]);
    let checkpoint = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: log.key_ref(),
            subject: "scitt:example-log".into(),
            claim: Claim {
                claim_type: "transparency.checkpoint".into(),
                fields: vec![("sequence".into(), MetaValue::Uint(7))],
            },
            issued_at: 1_700_000_100,
            expires_at: Some(1_700_000_150),
            evidence_ref: None,
        },
        &log,
        &lim,
    )
    .unwrap();
    let receipt = make_evidence(
        EvidenceKind::new("transparency_receipt"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(checkpoint.id.clone()),
        None,
        &lim,
    )
    .unwrap();
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "inclusion.proved".into(),
            subject: pay.id.clone(),
            predicate: "logged".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(checkpoint);
    b.add_evidence(receipt);
    let built = b.build(&lim).unwrap();
    // After checkpoint expiry (clock past window + skew): inclusion fails.
    let late = VerifyCtx {
        verified_at: CLOCK_OK + 100_000,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK_OK + 100_000),
        require_status_feed: false,
        ..VerifyCtx::default()
    };
    let report = verify_proof(&built.canonical, &late).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let p = v2(
        "inclusion",
        serde_json::json!({"type": "transparency_inclusion", "log": log.key_ref()}),
    );
    let out = evaluate_policy(
        &state,
        &p,
        &EvalInputs {
            trusted_issuers: vec![log.key_ref()],
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK + 100_000,
            skew_leeway: 300,
        },
    );
    // Broken preconditions short-circuit to INDETERMINATE (never Fail, never
    // Pass): the expired checkpoint poisons evidence validity first, so the
    // inclusion leaf is never even reached. Freshness has teeth either way.
    assert_eq!(out.decision, PolicyDecision::Indeterminate, "{out:?}");
    assert!(out.results.is_empty());
}

#[test]
fn v2_transparency_rotation_without_reanchor_fails_leaf() {
    // Log rotates its checkpoint (supersede old→new) but the receipt still
    // binds the OLD checkpoint: history stays valid (evidence Valid), yet
    // inclusion FAILS at the leaf — a rotated-away anchor is not current.
    let lim = limits();
    let log = proof_crypto::Ed25519Key::from_seed(&[34u8; 32]);
    let mk_checkpoint = |sequence: u64| {
        attest(
            proof_core::model::AttestationContent {
                v: 1,
                issuer: log.key_ref(),
                subject: "scitt:example-log".into(),
                claim: Claim {
                    claim_type: "transparency.checkpoint".into(),
                    fields: vec![("sequence".into(), MetaValue::Uint(sequence))],
                },
                issued_at: 1_700_000_100,
                expires_at: None,
                evidence_ref: None,
            },
            &log,
            &lim,
        )
        .unwrap()
    };
    let old = mk_checkpoint(7);
    let new = mk_checkpoint(8);
    let rot =
        proof_crypto::build::supersede_attestation(&old.id, &new.id, &log, 1_700_000_150, &lim)
            .unwrap();
    let receipt = make_evidence(
        EvidenceKind::new("transparency_receipt"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(old.id.clone()),
        None,
        &lim,
    )
    .unwrap();
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "inclusion.proved".into(),
            subject: pay.id.clone(),
            predicate: "logged".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(old);
    b.add_attestation(new);
    b.add_attestation(rot);
    b.add_evidence(receipt);
    let built = b.build(&lim).unwrap();
    let report = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(report.cryptographic_validity, Validity::Valid);
    assert_eq!(report.evidence_validity, Validity::Valid);
    let p = v2(
        "inclusion",
        serde_json::json!({"type": "transparency_inclusion", "log": log.key_ref()}),
    );
    let out = eval_built(&built, &p, vec![log.key_ref()]);
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
}

#[test]
fn v2_stale_identity_never_merges() {
    // An EXPIRED identity.bind attestation merges nothing, even from a
    // trusted asserter: identity authority is current-only, fail closed.
    let lim = limits();
    let authority = fixtures::test_key();
    let mut content = proof_core::model::AttestationContent {
        v: 1,
        issuer: authority.key_ref(),
        subject: "did:acme:42".into(),
        claim: Claim {
            claim_type: "identity.bind".into(),
            fields: vec![(
                "equivalent".into(),
                MetaValue::Text("account:acme-42".into()),
            )],
        },
        issued_at: 1_700_000_100,
        expires_at: Some(1_700_000_150),
        evidence_ref: None,
    };
    let _ = &mut content;
    let bind = attest(content, &authority, &lim).unwrap();
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
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "identity.link".into(),
            subject: "did:acme:42".into(),
            predicate: "equivalent".into(),
            object: Some("account:acme-42".into()),
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(bind);
    let built = b.build(&lim).unwrap();
    // Past expiry, the binding is recorded but merges nothing.
    let late = VerifyCtx {
        verified_at: CLOCK_OK + 100_000,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK_OK + 100_000),
        require_status_feed: false,
        ..VerifyCtx::default()
    };
    let report = verify_proof(&built.canonical, &late).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    assert!(!state.identity_bindings.is_empty(), "binding projected");
    let p = v2(
        "bound",
        serde_json::json!({"type": "identity_bound",
            "a": "did:acme:42", "b": "account:acme-42"}),
    );
    let out = evaluate_policy(
        &state,
        &p,
        &EvalInputs {
            trusted_issuers: vec![authority.key_ref()],
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK + 100_000,
            skew_leeway: 300,
        },
    );
    // Guard fires first (expired attestation poisons evidence): neither Pass
    // nor Fail — and crucially the merge never happens.
    assert_eq!(out.decision, PolicyDecision::Indeterminate, "{out:?}");

    // Sharper: a SUPERSEDED binding keeps evidence valid (history preserved),
    // so the leaf itself evaluates — and must refuse the stale merge.
    let old_live = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: authority.key_ref(),
            subject: "did:acme:42".into(),
            claim: Claim {
                claim_type: "identity.bind".into(),
                fields: vec![(
                    "equivalent".into(),
                    MetaValue::Text("account:acme-42".into()),
                )],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &authority,
        &lim,
    )
    .unwrap();
    let fresh = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: authority.key_ref(),
            subject: "did:acme:42".into(),
            claim: Claim {
                claim_type: "identity.bind".into(),
                fields: vec![(
                    "equivalent".into(),
                    MetaValue::Text("account:acme-43".into()),
                )],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &authority,
        &lim,
    )
    .unwrap();
    let rot = proof_crypto::build::supersede_attestation(
        &old_live.id,
        &fresh.id,
        &authority,
        1_700_000_150,
        &lim,
    )
    .unwrap();
    let pay2 = create_event(
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
    let mut b2 = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "identity.link".into(),
            subject: "did:acme:42".into(),
            predicate: "equivalent".into(),
            object: Some("account:acme-42".into()),
            at_time: None,
            context: vec![],
        },
        CLOCK_OK,
    );
    b2.add_event(pay2);
    b2.add_attestation(old_live);
    b2.add_attestation(fresh);
    b2.add_attestation(rot);
    let built2 = b2.build(&lim).unwrap();
    let report2 = verify_proof(&built2.canonical, &ctx()).unwrap();
    assert_eq!(report2.evidence_validity, Validity::Valid);
    let state2 = state_from_report_and_proof(&report2, &built2.proof).unwrap();
    let out2 = evaluate_policy(
        &state2,
        &v2(
            "bound",
            serde_json::json!({"type": "identity_bound",
                "a": "did:acme:42", "b": "account:acme-42"}),
        ),
        &EvalInputs {
            trusted_issuers: vec![authority.key_ref()],
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK,
            skew_leeway: 300,
        },
    );
    assert_eq!(out2.decision, PolicyDecision::Fail, "{out2:?}");
    // ...while the fresh binding (account:acme-43) still resolves.
    let out3 = evaluate_policy(
        &state2,
        &v2(
            "bound-fresh",
            serde_json::json!({"type": "identity_bound",
                "a": "did:acme:42", "b": "account:acme-43"}),
        ),
        &EvalInputs {
            trusted_issuers: vec![authority.key_ref()],
            revocations: RevocationSet::empty(),
            verified_at: CLOCK_OK,
            skew_leeway: 300,
        },
    );
    assert_eq!(out3.decision, PolicyDecision::Pass, "{out3:?}");
}

// ---------- reference hooks (requires/forbids_reference) ----------

/// Fully valid attested proof with composition linkage, for hook tests.
fn linked_proof(tag: &str, refs: &[String]) -> proof_verify::BuiltProof {
    let lim = limits();
    let key = fixtures::test_key();
    let pay = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: format!("payment:{tag}"),
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
            subject: format!("invoice:{tag}"),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xCDu8; 32]).unwrap(),
            metadata: vec![],
        },
        &lim,
    )
    .unwrap();
    let att = statement(
        &key,
        &format!("payment:{tag}"),
        "payment.settled",
        vec![("amount".into(), MetaValue::Uint(4200))],
    );
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
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
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let mut sorted = refs.to_vec();
    sorted.sort();
    for r in sorted {
        b.add_referenced_proof(r).unwrap();
    }
    b.build(&lim).unwrap()
}

#[test]
fn v2_reference_hooks_parse() {
    let leaf = linked_proof("leaf", &[]);
    // Both leaves parse under v2 with shape-checked ids.
    let p = v2(
        "hooks",
        serde_json::json!({"all": [
            {"type": "requires_reference", "id": leaf.id},
            {"type": "forbids_reference", "id": leaf.id},
        ]}),
    );
    assert_eq!(p.version, 2);
    // Malformed ids fail closed at parse (typos never silently miss).
    for bad in [
        serde_json::json!({"type": "requires_reference", "id": "prf:v1:!!!"}),
        serde_json::json!({"type": "requires_reference", "id": "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"type": "requires_reference"}),
        serde_json::json!({"type": "forbids_reference", "id": leaf.id, "extra": 1}),
    ] {
        let v = serde_json::json!({
            "policy_version": 2, "policy_id": "bad", "expression": bad,
        });
        assert!(parse_policy(&v, &limits()).is_err(), "must reject {bad}");
    }
    // v1 rejects both names (frozen v1 cannot drift as v2 grows).
    for name in ["requires_reference", "forbids_reference"] {
        let v = serde_json::json!({
            "policy_version": 1, "policy_id": "h",
            "requirements": [{"type": name, "id": leaf.id}],
        });
        assert!(parse_policy(&v, &limits()).is_err(), "{name} is v2-only");
    }
}

#[test]
fn v2_reference_hooks_decide_on_direct_linkage() {
    let leaf = linked_proof("leaf", &[]);
    let other = linked_proof("other", &[]);
    let parent = linked_proof("parent", std::slice::from_ref(&leaf.id));
    let issuer = fixtures::test_key().key_ref();
    let trusted = vec![issuer];
    // Present source required: PASS; absent source required: FAIL.
    let out = eval_built(
        &parent,
        &v2(
            "req-present",
            serde_json::json!({"type": "requires_reference", "id": leaf.id}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    let out = eval_built(
        &parent,
        &v2(
            "req-absent",
            serde_json::json!({"type": "requires_reference", "id": other.id}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
    // Forbidden source absent: PASS; forbidden source present: FAIL.
    let out = eval_built(
        &parent,
        &v2(
            "forbid-absent",
            serde_json::json!({"type": "forbids_reference", "id": other.id}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    let out = eval_built(
        &parent,
        &v2(
            "forbid-present",
            serde_json::json!({"type": "forbids_reference", "id": leaf.id}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
    // Hooks compose inside connectives: quorum over linkage + validity.
    let out = eval_built(
        &parent,
        &v2(
            "quorum",
            serde_json::json!({"threshold": {"k": 2, "of": [
                {"type": "signature_valid"},
                {"type": "requires_reference", "id": leaf.id},
                {"type": "forbids_reference", "id": other.id},
            ]}}),
        ),
        trusted,
    );
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
}

#[test]
fn v2_claim_field_uint_predicates() {
    // base_proof carries payment.settled {amount: 4200 uint} ACTIVE.
    let built = base_proof(vec![]);
    let trusted = vec![fixtures::test_key().key_ref()];
    // eq / gte pass; gt on boundary fails; lt fails.
    for (op, value, expect) in [
        ("eq", 4200u64, PolicyDecision::Pass),
        ("gte", 100u64, PolicyDecision::Pass),
        ("gte", 4200u64, PolicyDecision::Pass),
        ("gt", 4200u64, PolicyDecision::Fail),
        ("lt", 5000u64, PolicyDecision::Pass),
        ("lt", 100u64, PolicyDecision::Fail),
        ("ne", 1u64, PolicyDecision::Pass),
        ("lte", 4200u64, PolicyDecision::Pass),
    ] {
        let out = eval_built(
            &built,
            &v2(
                "cf",
                serde_json::json!({"type": "claim_field", "claim_type": "payment.settled", "field": "amount", "op": op, "value": value}),
            ),
            trusted.clone(),
        );
        assert_eq!(out.decision, expect, "op={op} value={value}: {out:?}");
    }
    // Wrong type scope matches nothing → FAIL (never vacuous pass).
    let out = eval_built(
        &built,
        &v2(
            "cf-scope",
            serde_json::json!({"type": "claim_field", "claim_type": "payment.other", "field": "amount", "op": "eq", "value": 4200}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
    // Missing field → FAIL.
    let out = eval_built(
        &built,
        &v2(
            "cf-missing",
            serde_json::json!({"type": "claim_field", "claim_type": "payment.settled", "field": "nope", "op": "eq", "value": 1}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
    // Type mismatch (text value vs uint field) → FAIL, not panic.
    let out = eval_built(
        &built,
        &v2(
            "cf-mismatch",
            serde_json::json!({"type": "claim_field", "claim_type": "payment.settled", "field": "amount", "op": "eq", "value": "4200"}),
        ),
        trusted,
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
}

#[test]
fn v2_commitment_pattern_hides_value_but_binds_policy() {
    // CONFIDENTIALITY.md pattern, pinned executable: the claim carries only
    // a salted SHA-256 commitment (`commit`), never the sensitive value.
    // commit = hex(sha256("pe-commit-demo-salt|income:84000")) =
    //   5752cca34a0199e42de6869abe609f93ed9e189c5877739c9282bfff9ec73819
    // (recompute: printf 'pe-commit-demo-salt|income:84000' | sha256sum).
    // Policy checks equality on the commitment; the preimage lives off-proof.
    // Limits, stated in the test name: equality-only, no range proofs, no
    // redaction — ZK predicates belong in adapters, never the core.
    let key = fixtures::test_key();
    let commit_att = statement(
        &key,
        "employee:e7",
        "income.committed",
        vec![(
            "commit".into(),
            MetaValue::Text(
                "5752cca34a0199e42de6869abe609f93ed9e189c5877739c9282bfff9ec73819".into(),
            ),
        )],
    );
    let built = base_proof(vec![commit_att]);
    let trusted = vec![fixtures::test_key().key_ref()];
    // Exact commitment passes.
    let out = eval_built(
        &built,
        &v2(
            "commit-eq",
            serde_json::json!({"type": "claim_field", "claim_type": "income.committed", "field": "commit", "op": "eq", "value": "5752cca34a0199e42de6869abe609f93ed9e189c5877739c9282bfff9ec73819"}),
        ),
        trusted.clone(),
    );
    assert_eq!(out.decision, PolicyDecision::Pass, "{out:?}");
    // A commitment to a different value (income:84001 →
    // 3da31f71fcde005ff652aee4c7f0788595d7ffea4fea79d86ca5067df461af47)
    // does not match: FAIL, never vacuous pass.
    let out = eval_built(
        &built,
        &v2(
            "commit-ne",
            serde_json::json!({"type": "claim_field", "claim_type": "income.committed", "field": "commit", "op": "eq", "value": "3da31f71fcde005ff652aee4c7f0788595d7ffea4fea79d86ca5067df461af47"}),
        ),
        trusted,
    );
    assert_eq!(out.decision, PolicyDecision::Fail, "{out:?}");
}

#[test]
fn v2_claim_field_parse_rejects_bad_shapes() {
    // v1 rejects claim_field (frozen).
    let v1 = serde_json::json!({
        "policy_version": 1, "policy_id": "f",
        "requirements": [{"type": "claim_field", "field": "amount", "op": "eq", "value": 1}],
    });
    assert!(parse_policy(&v1, &limits()).is_err());
    // Ordering op on text rejected at parse (not at eval).
    let raw = serde_json::json!({
        "policy_version": 2, "policy_id": "bad",
        "expression": {"type": "claim_field", "field": "status", "op": "gt", "value": "paid"},
    });
    assert_eq!(
        parse_policy(&raw, &limits()).unwrap_err().code,
        proof_core::ErrorCode::PolicyInvalid
    );
    // field "type" reserved.
    let raw2 = serde_json::json!({
        "policy_version": 2, "policy_id": "bad2",
        "expression": {"type": "claim_field", "field": "type", "op": "eq", "value": "x"},
    });
    assert!(parse_policy(&raw2, &limits()).is_err());
}

#[test]
fn v2_evidence_bound_requires_cryptographic_binding() {
    // Bound proof: statement attestation names the evidence AND its claim
    // digest equals the evidence digest. Unbound base proof (same shapes,
    // no digest field) must FAIL the leaf while passing usability.
    let lim = limits();
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
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
        HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        None,
        None,
        &lim,
    )
    .unwrap();
    let mut content = proof_core::model::AttestationContent {
        v: 1,
        issuer: key.key_ref(),
        subject: "payment:p9".into(),
        claim: Claim {
            claim_type: "payment.settled".into(),
            fields: vec![("amount".into(), MetaValue::Uint(4200))],
        },
        issued_at: 1_700_000_100,
        expires_at: None,
        evidence_ref: Some(evd.id.clone()),
    };
    content
        .claim
        .fields
        .push(("evidence_digest".into(), MetaValue::Text("ab".repeat(32))));
    let att = attest(content, &key, &lim).unwrap();
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: pay.id.clone(),
            predicate: "settles".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK_OK,
    );
    b.add_event(pay);
    b.add_attestation(att);
    b.add_evidence(evd);
    let bound = b.build(&lim).unwrap();
    let leaf = v2(
        "bound",
        serde_json::json!({"type": "evidence_bound", "kind": "transaction_record"}),
    );
    assert_eq!(
        leaf.requirements.len(),
        0,
        "v2 leaves live in the expression tree, not requirements"
    );
    let trusted = vec![fixtures::test_key().key_ref()];
    assert_eq!(
        eval_built(&bound, &leaf, trusted.clone()).decision,
        PolicyDecision::Pass
    );
    // Wrong kind fails; unbound base proof fails while usable passes.
    let wrong = v2(
        "wrong-kind",
        serde_json::json!({"type": "evidence_bound", "kind": "receipt"}),
    );
    assert_eq!(
        eval_built(&bound, &wrong, trusted.clone()).decision,
        PolicyDecision::Fail
    );
    let plain = base_proof(vec![]);
    let usable = v2(
        "usable",
        serde_json::json!({"type": "evidence_usable", "kind": "transaction_record"}),
    );
    assert_eq!(
        eval_built(&plain, &usable, trusted.clone()).decision,
        PolicyDecision::Pass
    );
    assert_eq!(
        eval_built(&plain, &leaf, trusted).decision,
        PolicyDecision::Fail
    );
}

#[test]
fn v2_evidence_bound_parse_and_describe() {
    // v1 rejects the name (frozen); describe + canonical round-trip hold.
    let v1 = serde_json::json!({
        "policy_version": 1, "policy_id": "frozen",
        "requirements": [{"type": "evidence_bound", "kind": "receipt"}],
    });
    assert!(parse_policy(&v1, &limits()).is_err());
    let p = v2(
        "h",
        serde_json::json!({"type": "evidence_bound", "kind": "receipt"}),
    );
    let d = match &p.expression {
        Some(e) => e.describe(),
        None => panic!("v2 must carry an expression"),
    };
    assert!(d.contains("evidence_bound(receipt)"), "{d}");
    assert_eq!(
        policy_to_canonical_cbor(&p),
        policy_to_canonical_cbor(&v2(
            "h",
            serde_json::json!({"type": "evidence_bound", "kind": "receipt"}),
        ))
    );
    assert!(canonical_policy_hash(&p).starts_with("policy:v2:"));
}
