// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! P4: transitive linkage resolution. The core stays linkage-only (frozen);
//! this layer fetches + re-verifies and names everything it cannot produce.

use proof_core::model::{EventType, Proposition};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{create_event, fixtures};
use proof_format::{ArtifactStore, MemoryStore};
use proof_verify::{
    descendants_of, resolve_proof_chain, verify_proof, BuiltProof, ProofBuilder, UnresolvedReason,
    Validity, VerifyCtx,
};

fn ctx() -> VerifyCtx {
    VerifyCtx::default()
}

/// Minimal single-event proof; `tag` keeps ids distinct. `refs` are recorded
/// as composition linkage (bound by proof_id, validated at build).
fn tiny_proof(tag: &str, refs: &[String]) -> BuiltProof {
    let lim = Limits::default();
    let _ = fixtures::test_key();
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
            at_time: Some(1_700_000_000),
            context: vec![],
        },
        1_700_000_200,
    );
    b.add_event(ev);
    let mut sorted = refs.to_vec();
    sorted.sort();
    for r in sorted {
        b.add_referenced_proof(r).unwrap();
    }
    b.build(&lim).unwrap()
}

fn stored(proofs: &[&BuiltProof]) -> MemoryStore {
    let mut s = MemoryStore::new();
    for p in proofs {
        s.put(&p.id, p.canonical.clone()).unwrap();
    }
    s
}

#[test]
fn chain_resolves_transitively_with_depth_accounting() {
    let c = tiny_proof("c", &[]);
    let b = tiny_proof("b", std::slice::from_ref(&c.id));
    let a = tiny_proof("a", std::slice::from_ref(&b.id));
    let store = stored(&[&a, &b, &c]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    assert!(rep.complete());
    assert_eq!(rep.resolved.len(), 2);
    let depths: std::collections::HashMap<&str, usize> = rep
        .resolved
        .iter()
        .map(|r| (r.id.as_str(), r.depth))
        .collect();
    assert_eq!(depths[b.id.as_str()], 1);
    assert_eq!(depths[c.id.as_str()], 2);
    assert!(rep.unresolved.is_empty());
}

#[test]
fn root_verdict_is_reproduced_verbatim() {
    // Resolution never changes verdicts: the root report equals a direct
    // verify_proof call byte-for-byte in the fields that matter.
    let c = tiny_proof("c", &[]);
    let a = tiny_proof("a", std::slice::from_ref(&c.id));
    let store = stored(&[&a, &c]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    let direct = verify_proof(&a.canonical, &ctx()).unwrap();
    assert_eq!(rep.root.proof_id, direct.proof_id);
    assert_eq!(
        rep.root.cryptographic_validity,
        direct.cryptographic_validity
    );
    assert_eq!(rep.root.evidence_validity, direct.evidence_validity);
    assert_eq!(rep.root.cryptographic_validity, Validity::Valid);
}

#[test]
fn missing_reference_is_unavailable_fail_closed() {
    let ghost = tiny_proof("ghost", &[]); // well-formed id, never stored
    let a = tiny_proof("a", std::slice::from_ref(&ghost.id));
    let store = stored(&[&a]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    assert!(!rep.complete());
    assert_eq!(rep.unresolved.len(), 1);
    assert_eq!(rep.unresolved[0].id, ghost.id);
    assert_eq!(rep.unresolved[0].depth, 1);
    assert_eq!(rep.unresolved[0].reason, UnresolvedReason::Unavailable);
}

#[test]
fn depth_bound_names_frontier_without_fetching() {
    let c = tiny_proof("c", &[]);
    let b = tiny_proof("b", std::slice::from_ref(&c.id));
    let a = tiny_proof("a", std::slice::from_ref(&b.id));
    let store = stored(&[&a, &b, &c]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 1).unwrap();
    assert!(!rep.complete());
    assert_eq!(rep.resolved.len(), 1);
    assert_eq!(rep.resolved[0].id, b.id);
    assert_eq!(rep.unresolved.len(), 1);
    assert_eq!(rep.unresolved[0].id, c.id);
    assert_eq!(rep.unresolved[0].depth, 2);
    assert_eq!(rep.unresolved[0].reason, UnresolvedReason::DepthExceeded);
    // Depth zero: root only, direct references named but unfetched.
    let rep0 = resolve_proof_chain(&a.canonical, &store, &ctx(), 0).unwrap();
    assert!(!rep0.complete());
    assert!(rep0.resolved.is_empty());
    assert_eq!(rep0.unresolved[0].reason, UnresolvedReason::DepthExceeded);
}

/// A store that equivocates: returns tampered bytes under the requested id.
/// MemoryStore refuses this (conflict); the resolver must still catch it via
/// id re-verification, never by trusting the key.
struct EquivocatingStore {
    id: String,
    bytes: Vec<u8>,
}

impl ArtifactStore for EquivocatingStore {
    fn put(&mut self, _id: &str, _cbor: Vec<u8>) -> Result<(), String> {
        Err("read-only".into())
    }
    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(if id == self.id {
            Some(self.bytes.clone())
        } else {
            None
        })
    }
}

#[test]
fn equivocating_bytes_are_id_mismatch_never_trusted() {
    let b = tiny_proof("b", &[]);
    let a = tiny_proof("a", std::slice::from_ref(&b.id));
    let mut tampered = b.canonical.clone();
    tampered[8] ^= 0x01;
    let store = EquivocatingStore {
        id: b.id.clone(),
        bytes: tampered,
    };
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    assert!(!rep.complete());
    assert!(rep.resolved.is_empty());
    assert_eq!(rep.unresolved.len(), 1);
    assert!(matches!(
        rep.unresolved[0].reason,
        UnresolvedReason::IdMismatch { .. }
    ));
}

#[test]
fn diamond_references_resolve_once() {
    let d = tiny_proof("d", &[]);
    let b = tiny_proof("b", std::slice::from_ref(&d.id));
    let c = tiny_proof("c", std::slice::from_ref(&d.id));
    let a = tiny_proof("a", &[b.id.clone(), c.id.clone()]);
    let store = stored(&[&a, &b, &c, &d]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    assert!(rep.complete());
    assert_eq!(rep.resolved.len(), 3);
    let d_entries: Vec<_> = rep.resolved.iter().filter(|r| r.id == d.id).collect();
    assert_eq!(d_entries.len(), 1);
    assert_eq!(d_entries[0].depth, 2);
}

#[test]
fn ancestors_list_shallowest_depths_in_order() {
    let d = tiny_proof("d", &[]);
    let b = tiny_proof("b", std::slice::from_ref(&d.id));
    let c = tiny_proof("c", std::slice::from_ref(&d.id));
    let a = tiny_proof("a", &[b.id.clone(), c.id.clone()]);
    let store = stored(&[&a, &b, &c, &d]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    let anc = rep.ancestors();
    assert_eq!(anc.len(), 3);
    // Ordered by (depth, id): b and c at depth 1, d at depth 2 exactly once.
    assert_eq!(anc[0].depth, 1);
    assert_eq!(anc[1].depth, 1);
    assert_eq!(anc[2].depth, 2);
    assert_eq!(anc[2].id, d.id);
    assert!(anc.iter().all(|x| x.resolved));
    let ids: Vec<&str> = anc.iter().map(|x| x.id.as_str()).collect();
    assert!(ids.contains(&b.id.as_str()));
    assert!(ids.contains(&c.id.as_str()));
}

#[test]
fn ancestors_name_unavailable_references_as_unresolved() {
    let ghost = tiny_proof("ghost", &[]);
    let a = tiny_proof("a", std::slice::from_ref(&ghost.id));
    let store = stored(&[&a]);
    let rep = resolve_proof_chain(&a.canonical, &store, &ctx(), 8).unwrap();
    let anc = rep.ancestors();
    assert_eq!(anc.len(), 1);
    assert_eq!(anc[0].id, ghost.id);
    assert_eq!(anc[0].depth, 1);
    assert!(!anc[0].resolved);
}

#[test]
fn descendants_of_finds_proper_descendants_only() {
    let d = tiny_proof("d", &[]);
    let b = tiny_proof("b", std::slice::from_ref(&d.id));
    let c = tiny_proof("c", std::slice::from_ref(&d.id));
    let a = tiny_proof("a", &[b.id.clone(), c.id.clone()]);
    let all = vec![
        a.canonical.clone(),
        b.canonical.clone(),
        c.canonical.clone(),
        d.canonical.clone(),
    ];
    let store = stored(&[&a, &b, &c, &d]);
    // d is referenced (transitively) by b, c, and a — but never itself.
    let mut found = descendants_of(&d.id, &all, &store, &ctx(), 8).unwrap();
    found.sort();
    let mut want = vec![a.id.clone(), b.id.clone(), c.id.clone()];
    want.sort();
    assert_eq!(found, want);
    // a references nothing further down: no descendants.
    let none: Vec<String> = descendants_of(&a.id, &all, &store, &ctx(), 8).unwrap();
    assert!(none.is_empty());
    // Unknown target: nobody descends from it.
    let ghost = tiny_proof("ghost", &[]);
    let noone = descendants_of(&ghost.id, &all, &store, &ctx(), 8).unwrap();
    assert!(noone.is_empty());
}
