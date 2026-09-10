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
