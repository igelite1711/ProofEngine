// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy golden-vector generator (vectors 13–14).
//! Reuses the vector-11 proof bytes (single source of truth for the proof).
//! Run: `cargo run -p proof-policy --example gen_policy_vectors`

use proof_policy::{
    evaluate_policy, parse_policy, state_from_report_and_proof, EvalInputs, RevocationSet,
};
use proof_verify::{VerifyCtx, VerifyReport};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn main() {
    let dir = fixtures_dir();
    let v11: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("golden-11.json")).unwrap())
            .unwrap();
    let bytes = hex::decode(v11["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let limits = proof_core::Limits::default();
    // The pipeline context embedded in vector 11: live clock + fresh revocations.
    let vctx = v11["verify_ctx"].clone();
    let ctx: VerifyCtx = VerifyCtx {
        verified_at: vctx["verified_at"].as_u64().unwrap(),
        clock_skew_leeway: vctx["skew_leeway"].as_u64().unwrap(),
        revocations_known_at: vctx["revocations_known_at"].as_u64(),
        ..VerifyCtx::default()
    };
    let report: VerifyReport = proof_verify::verify_proof(&bytes, &ctx).unwrap();
    assert!(report.checks.iter().all(|c| c.ok));

    // Recover the parsed proof the same way the pipeline did.
    let value = proof_format::decode_strict(&bytes, &limits).unwrap();
    let proof = proof_format::cbor_to_proof(&value, &limits).unwrap();
    let state = state_from_report_and_proof(&report, &proof).unwrap();
    let issuer = state.verified_issuers[0].clone();
    let inputs = EvalInputs {
        trusted_issuers: vec![issuer.clone()],
        revocations: RevocationSet::empty(),
        verified_at: 1_700_000_200,
        skew_leeway: 300,
    };

    for (name, id, reqs) in [
        (
            "golden-13.json",
            "merchant_payment_v1",
            serde_json::json!([
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "relationship_exists", "relationship": "SETTLES"},
                {"type": "not_expired"},
                {"type": "not_revoked"},
            ]),
        ),
        (
            "golden-14.json",
            "strict_transparency_v1",
            serde_json::json!([
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "relationship_exists", "relationship": "SETTLES"},
                {"type": "not_expired"},
                {"type": "not_revoked"},
                {"type": "transparency_present"},
            ]),
        ),
        (
            "golden-20.json",
            "sanctions_screen_v1",
            serde_json::json!([
                {"type": "signature_valid"},
                {"type": "issuer_excluded", "issuer": issuer},
            ]),
        ),
    ] {
        let policy_doc =
            serde_json::json!({"policy_version": 1, "policy_id": id, "requirements": reqs});
        let policy = parse_policy(&policy_doc, &limits).unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs);
        let results: Vec<_> = outcome
            .results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "requirement": r.requirement,
                    "passed": r.passed,
                    "message": r.message,
                })
            })
            .collect();
        std::fs::write(
            dir.join(name),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": name.strip_suffix(".json").unwrap(),
                "description": format!("Vector-11 proof under {id}."),
                "proof_canonical_hex": v11["proof_canonical_hex"],
                "verify_ctx": v11["verify_ctx"],
                "policy": policy_doc,
                "eval_inputs": {
                    "trusted_issuers": inputs.trusted_issuers,
                    "revoked": [],
                    "verified_at": inputs.verified_at,
                    "skew_leeway": inputs.skew_leeway,
                },
                "expected": {
                    "decision": match outcome.decision {
                        proof_verify::PolicyDecision::Pass => "pass",
                        proof_verify::PolicyDecision::Fail => "fail",
                        proof_verify::PolicyDecision::Indeterminate => "indeterminate",
                    },
                    "results": results,
                }
            }))
            .unwrap(),
        )
        .unwrap();
        println!("wrote {name} decision={:?}", outcome.decision);
    }

    // Vector 19: superseded proof under a currency-sensitive policy.
    // PE-POLICY-006 golden: merchant requirements pass on history, but
    // `not_superseded` fails closed (decision fail, never indeterminate:
    // crypto and evidence are both valid).
    {
        use proof_core::model::{
            Claim, EventContent, EventType, EvidenceKind, Proposition, RelType, Relationship,
        };
        use proof_core::{HashAlgorithm, HashRef};
        use proof_crypto::build::{
            attest, create_event, fixtures, make_evidence, make_relationship, supersede_attestation,
        };
        use proof_verify::ProofBuilder;
        let key = fixtures::test_key();
        let mk_event = |t: EventType, subject: &str| {
            create_event(
                EventContent {
                    v: 1,
                    event_type: t,
                    subject: subject.into(),
                    effective_at: 1_700_000_000,
                    payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
                    metadata: vec![],
                },
                &limits,
            )
            .unwrap()
        };
        let pay = mk_event(EventType::new(EventType::PAYMENT_CREATED), "payment:p19");
        let inv = mk_event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i19");
        let old = attest(
            fixtures::fixed_attestation_content(&key.key_ref(), &pay.id),
            &key,
            &limits,
        )
        .unwrap();
        let mut new_content = old.content.clone();
        new_content.issued_at = 1_700_000_150;
        new_content.claim = Claim {
            claim_type: "payment.created-observed-v2".into(),
            fields: vec![],
        };
        let new = attest(new_content, &key, &limits).unwrap();
        let sup = supersede_attestation(&old.id, &new.id, &key, 1_700_000_200, &limits).unwrap();
        let evd = make_evidence(
            EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
            HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
            Some(new.id.clone()),
            None,
            &limits,
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
            &limits,
        )
        .unwrap();
        let mut b = ProofBuilder::new(
            Proposition {
                v: 1,
                kind: "payment.settles-invoice".into(),
                subject: "payment:p19".into(),
                predicate: "settles".into(),
                object: Some("invoice:i19".into()),
                at_time: Some(1_700_000_100),
                context: vec![],
            },
            1_700_000_200,
        );
        b.add_event(pay);
        b.add_event(inv);
        b.add_attestation(old);
        b.add_attestation(new);
        b.add_attestation(sup);
        b.add_evidence(evd);
        b.add_relationship(edge);
        let built = b.build(&limits).unwrap();
        let bytes = built.canonical.clone();
        let report = proof_verify::verify_proof(&bytes, &ctx).unwrap();
        assert!(report.checks.iter().all(|c| c.ok));
        let value = proof_format::decode_strict(&bytes, &limits).unwrap();
        let proof = proof_format::cbor_to_proof(&value, &limits).unwrap();
        let state = state_from_report_and_proof(&report, &proof).unwrap();
        assert!(!state.superseded_ids.is_empty());
        let policy_doc = serde_json::json!({
            "policy_version": 1,
            "policy_id": "current_only_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": issuer},
                {"type": "not_superseded"},
            ]
        });
        let policy = parse_policy(&policy_doc, &limits).unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs);
        assert!(matches!(
            outcome.decision,
            proof_verify::PolicyDecision::Fail
        ));
        assert!(outcome
            .results
            .iter()
            .any(|r| r.requirement == "not_superseded" && !r.passed));
        let results: Vec<_> = outcome
            .results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "requirement": r.requirement,
                    "passed": r.passed,
                    "message": r.message,
                })
            })
            .collect();
        std::fs::write(
            dir.join("golden-19.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "golden-19",
                "description": "Superseded proof under current_only_v1 (not_superseded fails).",
                "proof_canonical_hex": hex::encode(&bytes),
                "verify_ctx": vctx,
                "policy": policy_doc,
                "eval_inputs": {
                    "trusted_issuers": inputs.trusted_issuers,
                    "revoked": [],
                    "verified_at": inputs.verified_at,
                    "skew_leeway": inputs.skew_leeway,
                },
                "expected": {
                    "decision": "fail",
                    "results": results,
                }
            }))
            .unwrap(),
        )
        .unwrap();
        println!("wrote golden-19.json decision={:?}", outcome.decision);
    }
}
