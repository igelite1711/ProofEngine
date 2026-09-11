// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bundle + store fit: external bytes authenticate against evidence digests
//! through the SAME digest rule the pipeline enforces — inline carriage
//! without touching core canonical bytes.

use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{fixtures, make_evidence};
use proof_format::{check_blob_against_digest, ArtifactStore, Bundle, MemoryStore};

fn lim() -> Limits {
    Limits::default()
}

#[test]
fn bundle_blob_satisfies_evidence_digest() {
    // External content whose digest is bound in an evidence item.
    let content = b"quarterly-invoice-pdf-content".to_vec();
    let digest = HashRef::new(
        HashAlgorithm::Sha256,
        proof_crypto::hash::sha256(&content).to_vec(),
    )
    .unwrap();
    let key = fixtures::test_key();
    let att = proof_crypto::build::attest(
        fixtures::fixed_attestation_content(&key.key_ref(), "invoice:i9"),
        &key,
        &lim(),
    )
    .unwrap();
    let evd = make_evidence(
        proof_core::model::EvidenceKind::new("signed_document"),
        digest.clone(),
        Some(att.id.clone()),
        None,
        &lim(),
    )
    .unwrap();

    // The bundle carries the bytes alongside; both resolve and authenticate.
    let bundle = Bundle::new().with_blob(digest.clone(), content.clone());
    let found = bundle.find_blob(&evd.content.digest).expect("blob present");
    assert_eq!(found, content.as_slice());
    check_blob_against_digest(found, &evd.content.digest).unwrap();

    // A store carries the envelope bytes; the pipeline verifies them
    // identically whether they came from disk or memory.
    let mut store = MemoryStore::new();
    let canon = proof_format::encode_canonical(&proof_format::evidence_to_cbor(&evd.content));
    let id = proof_crypto::id::evidence_id(&canon);
    store.put(&id, canon.clone()).unwrap();
    assert_eq!(store.get(&id).unwrap(), Some(canon));
}
