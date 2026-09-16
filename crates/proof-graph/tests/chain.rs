// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end graph test with REAL builder ids (no synthetic strings).
//! Company → Account → Payment → Invoice, grounded by a payment attestation.

use proof_core::model::EvidenceKind;
use proof_core::model::{EventType, MetaValue, RelType, Relationship};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, verify_relationship};
use proof_crypto::build::{make_relationship, verify_attestation, verify_event, verify_evidence};
use proof_graph::{validate_graph, EdgeRecord, NodeSet};

fn event_content(t: EventType, subject: &str, order: &str) -> proof_core::model::EventContent {
    proof_core::model::EventContent {
        v: 1,
        event_type: t,
        subject: subject.into(),
        effective_at: 1_700_000_000,
        payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
        metadata: vec![("order".into(), MetaValue::Text(order.into()))],
    }
}

#[test]
fn payment_settles_invoice_chain() {
    let lim = Limits::default();
    let key = fixtures::test_key();

    // Four events: company owns account, account created payment, payment settles invoice.
    let co = create_event(
        event_content(
            EventType::new(EventType::DOCUMENT_SIGNED),
            "company:acme",
            "o",
        ),
        &lim,
    )
    .unwrap();
    let acct = create_event(
        event_content(
            EventType::new(EventType::DOCUMENT_SIGNED),
            "account:a1",
            "o",
        ),
        &lim,
    )
    .unwrap();
    let pay = create_event(
        event_content(
            EventType::new(EventType::PAYMENT_CREATED),
            "payment:p9",
            "ord-1",
        ),
        &lim,
    )
    .unwrap();
    let inv = create_event(
        event_content(
            EventType::new(EventType::INVOICE_ISSUED),
            "invoice:i9",
            "ord-1",
        ),
        &lim,
    )
    .unwrap();
    for (ev, bytes) in [
        (&co, &co.canonical),
        (&acct, &acct.canonical),
        (&pay, &pay.canonical),
        (&inv, &inv.canonical),
    ] {
        let (_, id) = verify_event(bytes, Some(&ev.id), &lim).unwrap();
        assert_eq!(id, ev.id);
    }

    // One attestation grounding the settlement.
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
        &key,
        &lim,
    )
    .unwrap();
    verify_attestation(
        &att.sign1,
        &key.key_ref(),
        &proof_crypto::alg::AllowedAlgs::strict(),
        &lim,
    )
    .unwrap();

    // Evidence bound to the attestation.
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        Some(att.id.clone()),
        None,
        &lim,
    )
    .unwrap();
    verify_evidence(&evd.canonical, Some(&evd.id), &lim).unwrap();

    // Edges (all trust-relevant → grounded by attestation/evidence ids).
    let mk = |from: &str, t: RelType, to: &str| {
        let r = make_relationship(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: t,
                to: to.into(),
                evidence_ref: Some(evd.id.clone()),
                attestation_ref: Some(att.id.clone()),
            },
            &lim,
        )
        .unwrap();
        let (back, id) = verify_relationship(&r.canonical, Some(&r.id), &lim).unwrap();
        assert_eq!(back, r.content);
        EdgeRecord {
            content: r.content,
            id,
        }
    };
    let edges = vec![
        mk(&co.id, RelType::new(RelType::OWNS), &acct.id),
        mk(&acct.id, RelType::new(RelType::CREATED), &pay.id),
        mk(&pay.id, RelType::new(RelType::SETTLES), &inv.id),
    ];

    let nodes = NodeSet::new(
        [&co.id, &acct.id, &pay.id, &inv.id, &att.id, &evd.id]
            .into_iter()
            .map(|s| s.to_string()),
    );
    let g = validate_graph(&edges, &nodes, &lim).unwrap();
    assert_eq!(g.edge_count, 3);
    assert_eq!(g.node_count, 4);
}

#[test]
fn huge_node_set_with_few_edges_fails_closed() {
    // Total member ids are bounded by max_nodes even when edge endpoints are
    // few: a 10k NodeSet with 0 edges must not pass.
    use proof_core::ErrorCode;
    let lim = Limits::default();
    let huge: Vec<String> = (0..(lim.max_nodes + 100))
        .map(|i| format!("evt:v1:node{i:05}"))
        .collect();
    let nodes = NodeSet::new(huge);
    let err = validate_graph(&[], &nodes, &lim).unwrap_err();
    assert_eq!(err.code, ErrorCode::LimitExceeded);
}

#[test]
fn duplicate_edge_ids_rejected() {
    use proof_core::ErrorCode;
    let lim = Limits::default();
    let key = fixtures::test_key();
    let ev = create_event(event_content(EventType::new("t"), "s", "1"), &lim).unwrap();
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
        None,
        None,
        &lim,
    )
    .unwrap();
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &ev.id),
        &key,
        &lim,
    )
    .unwrap();
    // REFERENCES is ungrounded: needs no backing, endpoints must resolve.
    // Use two distinct events (self-edges forbidden).
    let ev2 = create_event(event_content(EventType::new("t"), "s2", "2"), &lim).unwrap();
    let nodes = NodeSet::new(
        [&ev.id, &ev2.id, &att.id, &evd.id]
            .into_iter()
            .map(|s| s.to_string()),
    );
    let rel = make_relationship(
        Relationship {
            v: 1,
            from: ev.id.clone(),
            rel_type: RelType::new(RelType::REFERENCES),
            to: ev2.id.clone(),
            evidence_ref: None,
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap();
    let (back, id) = verify_relationship(&rel.canonical, Some(&rel.id), &lim).unwrap();
    assert_eq!(back, rel.content);
    let edge = EdgeRecord {
        content: rel.content.clone(),
        id: id.clone(),
    };
    let dup = edge.clone();
    let err = validate_graph(&[edge, dup], &nodes, &lim).unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
}

#[test]
fn mistyped_backing_ref_rejected() {
    use proof_core::ErrorCode;
    let lim = Limits::default();
    let key = fixtures::test_key();
    let ev = create_event(event_content(EventType::new("t"), "s", "1"), &lim).unwrap();
    let ev2 = create_event(event_content(EventType::new("t"), "s2", "2"), &lim).unwrap();
    let att = attest(
        fixtures::fixed_attestation_content(&key.key_ref(), &ev.id),
        &key,
        &lim,
    )
    .unwrap();
    let nodes = NodeSet::new(
        [&ev.id, &ev2.id, &att.id]
            .into_iter()
            .map(|s| s.to_string()),
    );
    // SETTLES is trust-relevant: evidence_ref must be evd:v1:…, not att:.
    // Typed backing refs are enforced eagerly at construction —
    // make_relationship canonicalizes through cbor_to_relationship, whose
    // opt_ref_or_nil enforces the "evd:v1:" / "att:v1:" prefixes before any
    // id is ever computed (fail at creation, not at graph validation).
    let err = make_relationship(
        Relationship {
            v: 1,
            from: ev.id.clone(),
            rel_type: RelType::new(RelType::SETTLES),
            to: ev2.id.clone(),
            evidence_ref: Some(att.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
    // A hand-forged canonical edge bypassing construction is still rejected
    // lazily by validate_graph (defense in depth for direct EdgeRecord use).
    let content = Relationship {
        v: 1,
        from: ev.id.clone(),
        rel_type: RelType::new(RelType::SETTLES),
        to: ev2.id.clone(),
        evidence_ref: Some(att.id.clone()),
        attestation_ref: None,
    };
    let canonical =
        proof_format::cbor::encode_canonical(&proof_format::schema::relationship_to_cbor(&content));
    let bytes = canonical;
    let forged = proof_crypto::id::relationship_id(&bytes);
    let edge = EdgeRecord {
        content,
        id: forged,
    };
    let err = validate_graph(&[edge], &nodes, &lim).unwrap_err();
    assert_eq!(err.code, ErrorCode::SchemaViolation);
}
