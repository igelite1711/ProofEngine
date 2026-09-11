// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Composition linkage (SPEC §7) + divergence representation (SPEC §17).
//! Additive proofs: empty linkage is byte-identical V1; references bind when
//! present; conflicts are recorded, never arbitrated.

use proof_core::model::{EventType, MetaValue, Proposition};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_crypto::id::proof_id;
use proof_verify::{verify_proof, ProofBuilder, Validity, VerifyCtx};

fn ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1_700_000_200),
        ..VerifyCtx::default()
    }
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

fn members() -> (
    proof_crypto::build::CreatedEvent,
    proof_crypto::build::CreatedEvent,
    proof_crypto::build::CreatedAttestation,
    proof_crypto::build::CreatedEvidence,
    proof_crypto::build::CreatedRelationship,
) {
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
    (pay, inv, att, evd, rel)
}

fn ref_id(seed: &[u8]) -> String {
    use proof_crypto::hash::sha256;
    format!("prf:v1:{}", proof_crypto::id::b64u_nopad(&sha256(seed)))
}

#[test]
fn empty_linkage_is_byte_identical_v1() {
    // The additive guarantee: no refs → identical binding to `proof_id`.
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let prop_cbor = proof_format::proposition_to_cbor(&proposition());
    let classic = proof_id(
        &prop_cbor,
        &[pay.id.clone(), inv.id.clone()],
        std::slice::from_ref(&att.id),
        std::slice::from_ref(&evd.id),
        std::slice::from_ref(&rel.id),
    );
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    assert_eq!(built.id, classic);
    assert!(built.proof.referenced_proofs.is_empty());
}

#[test]
fn references_bind_and_verify() {
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let r1 = ref_id(b"composition-ref-one");
    let r2 = ref_id(b"composition-ref-two");
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    // Unsorted input is normalized by the builder.
    b.add_referenced_proof(r2.clone()).unwrap();
    b.add_referenced_proof(r1.clone()).unwrap();
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let mut expect_refs = vec![r1.clone(), r2.clone()];
    expect_refs.sort();
    assert_eq!(built.proof.referenced_proofs, expect_refs);
    // Binding covers the set: a ref-free proof over identical members binds
    // a different id.
    let mut b0 = ProofBuilder::new(proposition(), 1_700_000_200);
    let (p0, i0, a0, e0, r0) = members();
    b0.add_event(p0);
    b0.add_event(i0);
    b0.add_attestation(a0);
    b0.add_evidence(e0);
    b0.add_relationship(r0);
    let bare = b0.build(&lim).unwrap();
    assert_ne!(built.id, bare.id, "linkage changes the id");
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.referenced_proofs, expect_refs);
    assert!(r
        .checks
        .iter()
        .any(|c| c.stage == "GRAPH" && c.ok && c.message.contains("REFERENCED")));
}

#[test]
fn self_reference_rejected_with_explicit_code() {
    // A self-link with a matching id is a hash preimage (infeasible), so the
    // feasible attack is a stale envelope: copy proof P, set
    // referenced_proofs=[P.id] without rebinding. The pipeline must refuse
    // with an explicit CYCLE_DETECTED alongside the binding mismatch — never
    // silently accept the linkage.
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let own = built.id.clone();
    let mut v = proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        pairs.push((
            proof_format::CborValue::Text("referenced_proofs".into()),
            proof_format::CborValue::Array(vec![proof_format::CborValue::Text(own)]),
        ));
    }
    let bad = proof_format::encode_canonical(&v);
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.failure_codes().contains(&ErrorCode::IdMismatch));
    assert!(r.failure_codes().contains(&ErrorCode::CycleDetected));
}

#[test]
fn malformed_reference_rejected_at_schema() {
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    // Inject a malformed reference at the CBOR layer.
    let mut v = proof_format::decode_strict(&built.canonical, &lim).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        pairs.push((
            proof_format::CborValue::Text("referenced_proofs".into()),
            proof_format::CborValue::Array(vec![proof_format::CborValue::Text(
                "not-a-proof-id".into(),
            )]),
        ));
    }
    let bad = proof_format::encode_canonical(&v);
    let r = verify_proof(&bad, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.failure_codes().contains(&ErrorCode::SchemaViolation));
}

#[test]
fn divergent_attestations_recorded_not_arbitrated() {
    let lim = Limits::default();
    let key = fixtures::test_key();
    let (pay, inv, _, evd, rel) = members();
    // Two issuers assert different amounts for the same claim+subject.
    let mk_att = |amount: u64, seed_byte: u8| {
        let k = if seed_byte == 0 {
            key.clone()
        } else {
            proof_crypto::Ed25519Key::from_seed(&[seed_byte; 32])
        };
        attest(
            proof_core::model::AttestationContent {
                v: 1,
                issuer: k.key_ref(),
                subject: "payment:p9".into(),
                claim: proof_core::model::Claim {
                    claim_type: "payment.settled".into(),
                    fields: vec![("amount".into(), MetaValue::Uint(amount))],
                },
                issued_at: 1_700_000_100,
                expires_at: None,
                evidence_ref: None,
            },
            &k,
            &lim,
        )
        .unwrap()
    };
    let a1 = mk_att(4200, 0);
    let a2 = mk_att(4300, 7);
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(a1.clone());
    b.add_attestation(a2.clone());
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    // Both signatures valid; the core records the divergence and changes no
    // validity by itself.
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!(r.conflicts[0].claim_type, "payment.settled");
    assert_eq!(r.conflicts[0].subject, "payment:p9");
    assert_eq!(r.conflicts[0].attestation_ids.len(), 2);
    assert!(r
        .checks
        .iter()
        .any(|c| c.ok && c.message.contains("conflicting evidence")));
}

#[test]
fn corroborating_attestations_are_not_conflicts() {
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    // A second issuer asserts the byte-identical claim (corroboration):
    // same type/subject/fields, distinct attestation id.
    let key2 = proof_crypto::Ed25519Key::from_seed(&[11u8; 32]);
    let mut content2 = att.content.clone();
    content2.issuer = key2.key_ref();
    let att2 = attest(content2, &key2, &lim).unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_attestation(att2);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    assert!(r.conflicts.is_empty());
}

#[test]
fn denies_field_records_opposition_without_failing() {
    use proof_core::model::{Claim, MetaValue};
    use proof_crypto::build::attest;
    let lim = Limits::default();
    let key = fixtures::test_key();
    let (pay, inv, att, evd, rel) = members();
    // A second issuer denies the first attestation's claim.
    let denial = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: proof_crypto::Ed25519Key::from_seed(&[13u8; 32]).key_ref(),
            subject: "payment:p9".into(),
            claim: Claim {
                claim_type: "payment.review".into(),
                fields: vec![
                    ("denies".into(), MetaValue::Text(att.id.clone())),
                    ("verdict".into(), MetaValue::Text("reject".into())),
                ],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &proof_crypto::Ed25519Key::from_seed(&[13u8; 32]),
        &lim,
    )
    .unwrap();
    // An external denial (target outside the proof) records the asserter.
    let ext_denial = attest(
        proof_core::model::AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p9".into(),
            claim: Claim {
                claim_type: "payment.review".into(),
                fields: vec![(
                    "denies".into(),
                    MetaValue::Text("att:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
                )],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_attestation(denial);
    b.add_attestation(ext_denial);
    b.add_evidence(evd);
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let r = verify_proof(&built.canonical, &ctx()).unwrap();
    // Validity unchanged by opposition; all three records present: the two
    // reviews structurally diverge (different denies targets) plus the two
    // denial records (one anchored, one external).
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.conflicts.len(), 3);
    assert!(r.conflicts.iter().all(|c| {
        !c.attestation_ids.is_empty()
            && r.checks
                .iter()
                .any(|ch| ch.ok && ch.message.contains("representation only"))
    }));
}

#[test]
fn redacted_subset_with_back_reference_verifies() {
    // Selective-disclosure shape (privacy-extension path, no core change):
    // disclose a member SUBSET under a new id, link back to the source proof.
    // Member signatures still verify (they cover content, not the envelope),
    // the new binding covers exactly what is disclosed, and the reference
    // names what was withheld. A verifier learns nothing beyond the subset
    // plus the source id.
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let mut full = ProofBuilder::new(proposition(), 1_700_000_200);
    full.add_event(pay.clone());
    full.add_event(inv.clone());
    full.add_attestation(att.clone());
    full.add_evidence(evd.clone());
    full.add_relationship(rel.clone());
    let full = full.build(&lim).unwrap();

    // Redact the invoice event and the relationship: disclose payment,
    // attestation, and evidence only.
    let mut red = ProofBuilder::new(
        proof_core::model::Proposition {
            v: 1,
            kind: "payment.proved".into(),
            subject: pay.id.clone(),
            predicate: "occurred".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        1_700_000_200,
    );
    red.add_event(pay);
    red.add_attestation(att);
    red.add_evidence(evd);
    red.add_referenced_proof(full.id.clone()).unwrap();
    let red = red.build(&lim).unwrap();
    assert_ne!(red.id, full.id);
    let r = verify_proof(&red.canonical, &ctx()).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.referenced_proofs, vec![full.id]);
    // Withheld members are absent from the disclosed bytes.
    assert!(!red.proof.events.iter().any(|e| e.subject == "invoice:i9"));
}

#[test]
fn authority_signed_withdrawal_applies_without_being_issuer() {
    // A revocation authority (third party, not the evidence's issuer) can
    // withdraw evidence: authority rule, not issuer identity, governs.
    let lim = Limits::default();
    let authority = proof_crypto::Ed25519Key::from_seed(&[55u8; 32]);
    let (pay, inv, att, evd, rel) = members();
    let wd = proof_crypto::build::withdraw_attestation(
        &evd.id,
        Some("takedown order"),
        &authority,
        1_700_000_150,
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_attestation(wd);
    b.add_evidence(evd.clone());
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let mut c = ctx();
    c.revocation_authorities = vec![authority.key_ref()];
    let r = verify_proof(&built.canonical, &c).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r.failure_codes().contains(&ErrorCode::Withdrawn));
    assert_eq!(r.withdrawn_ids, vec![evd.id]);
}

#[test]
fn direct_evidence_compromise_marking_taints() {
    // A compromise marking can target an evidence id directly (not only an
    // issuer): the item taints even with a healthy backing attestation.
    let lim = Limits::default();
    let authority = proof_crypto::Ed25519Key::from_seed(&[56u8; 32]);
    let (pay, inv, att, evd, rel) = members();
    let mark = proof_crypto::build::compromise_attestation(
        &evd.id,
        1_700_000_000,
        Some("media provenance forged"),
        &authority,
        1_700_000_150,
        &lim,
    )
    .unwrap();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_attestation(mark);
    b.add_evidence(evd.clone());
    b.add_relationship(rel);
    let built = b.build(&lim).unwrap();
    let mut c = ctx();
    c.revocation_authorities = vec![authority.key_ref()];
    let r = verify_proof(&built.canonical, &c).unwrap();
    assert_eq!(r.evidence_validity, Validity::Invalid);
    assert!(r.failure_codes().contains(&ErrorCode::Compromised));
}

#[test]
fn vocabulary_restriction_notes_without_failing() {
    // A context that accepts only `legacy` notes the acme declaration and
    // use, plus the version over-max — informational only, validity holds.
    use proof_core::model::VocabularyAccept;
    let lim = Limits::default();
    let (pay, inv, att, evd, rel) = members();
    let mut b = ProofBuilder::new(proposition(), 1_700_000_200);
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att);
    b.add_evidence(evd);
    b.add_relationship(rel);
    b.add_vocabulary("acme".into(), 2).unwrap();
    let built = b.build(&lim).unwrap();
    let mut c = ctx();
    c.accepted_vocabularies = vec![VocabularyAccept {
        ns: "legacy".into(),
        max_version: 1,
    }];
    let r = verify_proof(&built.canonical, &c).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert!(r.checks.iter().any(|ch| ch.ok
        && ch
            .message
            .contains("`acme` declared but not in accepted vocabularies")));
    // Over-max declarations are noted too.
    let mut c_max = ctx();
    c_max.accepted_vocabularies = vec![
        VocabularyAccept {
            ns: "legacy".into(),
            max_version: 1,
        },
        VocabularyAccept {
            ns: "acme".into(),
            max_version: 1,
        },
    ];
    let r_max = verify_proof(&built.canonical, &c_max).unwrap();
    assert_eq!(r_max.evidence_validity, Validity::Valid);
    assert!(r_max
        .checks
        .iter()
        .any(|ch| ch.ok && ch.message.contains("exceeds accepted max 1")));
    // And a fully-accepting context emits no *acceptance* notes (the
    // undeclared-use note for legacy labels still fires: the declaration
    // doesn't cover what's used — provenance, not permission).
    let mut c2 = ctx();
    c2.accepted_vocabularies = vec![
        VocabularyAccept {
            ns: "legacy".into(),
            max_version: 1,
        },
        VocabularyAccept {
            ns: "acme".into(),
            max_version: 2,
        },
    ];
    let r2 = verify_proof(&built.canonical, &c2).unwrap();
    assert!(!r2
        .checks
        .iter()
        .any(|ch| ch.message.contains("accepted vocabularies")
            || ch.message.contains("exceeds accepted max")));
    assert!(r2
        .checks
        .iter()
        .any(|ch| ch.message.contains("used but not declared")));
}

#[test]
fn builder_rejects_bad_linkage_and_vocabularies() {
    use proof_core::model::Proposition;
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "k".into(),
            subject: "s".into(),
            predicate: "p".into(),
            object: None,
            at_time: None,
            context: vec![],
        },
        1_700_000_200,
    );
    assert!(b.add_referenced_proof("not-a-proof-id".into()).is_err());
    assert!(b
        .add_referenced_proof("evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())
        .is_err());
    assert!(b.add_vocabulary("".into(), 1).is_err());
    assert!(b.add_vocabulary("has space".into(), 1).is_err());
    assert!(b.add_vocabulary("has:colon".into(), 1).is_err());
    assert!(b.add_vocabulary("ok-ns_2".into(), 99).is_ok());
}
