// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Batch verification: shared context, independent members, no weakening.

use proof_core::model::{EventType, Proposition};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::create_event;
use proof_verify::{verify_batch, verify_proof, ProofBuilder, Validity, VerifyCtx};

fn ctx() -> VerifyCtx {
    VerifyCtx::default()
}

fn tiny_proof(tag: &str) -> Vec<u8> {
    let lim = Limits::default();
    let ev = create_event(
        proof_core::model::EventContent {
            v: 1,
            event_type: EventType::new("test.event.occurred"),
            subject: format!("test:{tag}"),
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
            kind: "test.proposition".into(),
            subject: format!("test:{tag}"),
            predicate: "occurred".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(ev);
    b.build(&lim).unwrap().canonical
}

#[test]
fn matches_sequential_verification() {
    let inputs = vec![tiny_proof("a"), tiny_proof("b"), tiny_proof("c")];
    let batch = verify_batch(&inputs, &ctx(), 256).unwrap();
    assert!(batch.complete(inputs.len()));
    assert!(batch.all_valid());
    assert_eq!(batch.members.len(), 3);
    for (i, bytes) in inputs.iter().enumerate() {
        let direct = verify_proof(bytes, &ctx()).unwrap();
        assert_eq!(batch.members[i].index, i);
        assert_eq!(batch.members[i].report.proof_id, direct.proof_id);
        assert_eq!(
            batch.members[i].report.cryptographic_validity,
            direct.cryptographic_validity
        );
        assert_eq!(
            batch.members[i].report.evidence_validity,
            direct.evidence_validity
        );
        assert_eq!(
            batch.members[i].report.failure_codes(),
            direct.failure_codes()
        );
    }
}

#[test]
fn independence_holds_with_invalid_members() {
    let mut bad = tiny_proof("bad");
    bad[12] ^= 0x01;
    let inputs = vec![tiny_proof("good"), bad];
    let batch = verify_batch(&inputs, &ctx(), 256).unwrap();
    // No short-circuit: both members fully verified despite the failure.
    assert_eq!(batch.members.len(), 2);
    assert!(!batch.all_valid());
    assert_eq!(batch.crypto_valid_count, 1);
    assert_eq!(
        batch.members[0].report.cryptographic_validity,
        Validity::Valid
    );
    assert_eq!(
        batch.members[1].report.cryptographic_validity,
        Validity::Invalid
    );
    assert!(!batch.members[1].report.failure_codes().is_empty());
}

#[test]
fn empty_batch_is_vacuously_complete_but_not_all_valid() {
    let batch = verify_batch(&[], &ctx(), 256).unwrap();
    assert!(batch.complete(0));
    assert!(!batch.all_valid());
}

#[test]
fn over_cap_batch_fails_closed() {
    let inputs = vec![tiny_proof("a"), tiny_proof("b")];
    let err = verify_batch(&inputs, &ctx(), 1).unwrap_err();
    assert_eq!(err.code, proof_core::ErrorCode::LimitExceeded);
}
