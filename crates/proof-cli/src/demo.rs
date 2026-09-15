// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `demo`: the killer use-case (ARCHITECTURE §8), end to end and
//! deterministically: build a payment-settles-invoice proof, verify it fresh
//! (PASS), have the merchant revoke their own attestation, re-verify
//! (REVOKED), and prove byte-identical determinism by rebuilding everything.
//! Every timestamp is a constant; the same seed yields the same bytes.

use proof_core::model::{
    AttestationContent, Claim, EventContent, EventType, EvidenceKind, MetaValue, Proposition,
    RelType, Relationship,
};
use proof_core::{HashAlgorithm, HashRef, LifecycleStatus, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, revoke_attestation,
};
use proof_crypto::SignedStatus;
use proof_policy::explain_report;
use proof_verify::{verify_proof, BuiltProof, ProofBuilder, Validity, VerifyCtx};

const T_EVENT: u64 = 1_700_000_000;
const T_ATTEST: u64 = 1_700_000_150;
const T_BUILT: u64 = 1_700_000_200;
const T_FRESH: u64 = 1_700_000_300;
const T_REVOKED: u64 = 1_700_000_400;
const T_AFTER: u64 = 1_700_000_500;

fn write_json(path: &str, v: serde_json::Value) -> Result<(), String> {
    std::fs::write(
        path,
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
            + "
",
    )
    .map_err(|e| format!("write {path}: {e}"))
}

// PE-CLI-005: deterministic demo (fixed key + timestamps; CI pins bytes).
pub fn run(out_dir: &str) -> Result<i32, String> {
    let lim = Limits::default();
    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {out_dir}: {e}"))?;
    let key = fixtures::test_key();

    println!("== Proof Engine demo: a proof that dies (ARCHITECTURE §8) ==");
    println!("[1] creating payment + invoice events (t={T_EVENT})");
    let event = |t: EventType, subject: &str| -> Result<EventContent, String> {
        Ok(EventContent {
            v: 1,
            event_type: t,
            subject: subject.into(),
            effective_at: T_EVENT,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0x5Eu8; 32])
                .map_err(|e| e.to_string())?,
            metadata: vec![("order".into(), MetaValue::Text("ord-demo-1".into()))],
        })
    };
    let pay = create_event(
        event(EventType::new(EventType::PAYMENT_CREATED), "payment:p-demo")?,
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let inv = create_event(
        event(EventType::new(EventType::INVOICE_ISSUED), "invoice:i-demo")?,
        &lim,
    )
    .map_err(|e| e.to_string())?;

    println!(
        "[2] merchant attests `payment.settled` over {} (t={T_ATTEST})",
        pay.id
    );
    let att = attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p-demo".into(),
            claim: Claim {
                claim_type: "payment.settled".into(),
                fields: vec![
                    ("amount".into(), MetaValue::Uint(4200)),
                    ("currency".into(), MetaValue::Text("EUR".into())),
                ],
            },
            issued_at: T_ATTEST,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .map_err(|e| e.to_string())?;

    println!("[3] grounding evidence + SETTLES edge");
    let evd = make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
        HashRef::new(HashAlgorithm::Sha256, vec![0xE1u8; 32]).map_err(|e| e.to_string())?,
        Some(att.id.clone()),
        Some("acquirer:receipt:demo".into()),
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let edge = make_relationship(
        Relationship {
            v: 1,
            rel_type: RelType::new(RelType::SETTLES),
            from: pay.id.clone(),
            to: inv.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;

    let build_once = || -> Result<BuiltProof, String> {
        let mut b = ProofBuilder::new(
            Proposition {
                v: 1,
                kind: "payment.settles-invoice".into(),
                subject: "payment:p-demo".into(),
                predicate: "settles".into(),
                object: Some("invoice:i-demo".into()),
                at_time: Some(T_ATTEST),
                context: vec![],
            },
            T_BUILT,
        );
        b.add_event(pay.clone());
        b.add_event(inv.clone());
        b.add_attestation(att.clone());
        b.add_evidence(evd.clone());
        b.add_relationship(edge.clone());
        b.build(&lim).map_err(|e| e.to_string())
    };
    let built = build_once()?;

    println!("[4] determinism: rebuilding from scratch must reproduce identical bytes");
    let rebuilt = build_once()?;
    assert_eq!(built.id, rebuilt.id, "proof id must be deterministic");
    assert_eq!(
        built.canonical, rebuilt.canonical,
        "proof bytes must be deterministic"
    );
    println!("    proof {} — identical on rebuild ✓", built.id);

    let proof_path = format!("{out_dir}/proof.cbor.json");
    crate::artifact::write_proof_file(&proof_path, &built.id, &built.canonical)?;
    println!("    wrote {proof_path}");

    println!("[5] fresh verification (clock={T_FRESH}, revocations known to {T_FRESH})");
    let fresh = verify_proof(
        &built.canonical,
        &VerifyCtx {
            verified_at: T_FRESH,
            clock_skew_leeway: 300,
            revocations_known_at: Some(T_FRESH),
            // Demo genesis step: no revocations exist yet; assert absence
            // explicitly (default fails closed; production uses a feed).
            require_status_feed: false,
            ..VerifyCtx::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if fresh.cryptographic_validity != Validity::Valid
        || fresh.evidence_validity != Validity::Valid
        || !fresh
            .lifecycle
            .iter()
            .all(|l| l.status == LifecycleStatus::Active)
    {
        return Err("demo invariant broken: fresh proof should verify PASS/ACTIVE".to_string());
    }
    println!("    verdict: PASS (exit 0) — crypto valid, evidence valid, attestation ACTIVE");
    write_json(
        &format!("{out_dir}/report-fresh.json"),
        serde_json::json!({
            "when": T_FRESH,
            "cryptographic_validity": "valid",
            "evidence_validity": "valid",
            "policy_decision": fresh.policy_decision.as_str(),
            "lifecycle": fresh.lifecycle.iter().map(|l| l.status.as_str()).collect::<Vec<_>>(),
        }),
    )?;

    println!("[6] tamper: flip one byte of the attested subject, re-verify the same way");
    let needle = b"invoice:i-demo";
    let pos = built
        .canonical
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| {
            "demo invariant violated: subject bytes missing from canonical proof".to_string()
        })?;
    let mut tampered = built.canonical.clone();
    tampered[pos] ^= 0x01;
    let bad = verify_proof(
        &tampered,
        &VerifyCtx {
            verified_at: T_FRESH,
            clock_skew_leeway: 300,
            revocations_known_at: Some(T_FRESH),
            ..VerifyCtx::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if bad.cryptographic_validity != Validity::Invalid
        || !bad
            .failure_codes()
            .contains(&proof_core::ErrorCode::IdMismatch)
    {
        return Err(
            "demo invariant broken: tampered proof should fail with IdMismatch".to_string(),
        );
    }
    println!(
        "    verdict: FAIL (exit 1) — proof id no longer binds the bytes: {:?}",
        bad.failure_codes()
    );

    println!("[7] merchant revokes their own attestation (t={T_REVOKED})");
    let rev = revoke_attestation(
        &att.id,
        Some("chargeback: order cancelled"),
        &key,
        T_REVOKED,
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let status_path = format!("{out_dir}/status-revoke.json");
    write_json(
        &status_path,
        serde_json::json!({
            "kind": "status",
            "id": rev.id,
            "issuer": rev.content.issuer,
            "claim_type": rev.content.claim.claim_type,
            "cbor": hex::encode(&rev.canonical),
            "sign1_b64": proof_crypto::id::b64u_nopad(&rev.sign1),
        }),
    )?;
    println!("    wrote {status_path}");

    println!("[8] re-verification after revocation (clock={T_AFTER}, status object supplied)");
    let dead = verify_proof(
        &built.canonical,
        &VerifyCtx {
            verified_at: T_AFTER,
            clock_skew_leeway: 300,
            status_objects: vec![SignedStatus {
                content: rev.content.clone(),
                sign1: rev.sign1.clone(),
            }],
            revocations_known_at: Some(T_AFTER),
            ..VerifyCtx::default()
        },
    )
    .map_err(|e| e.to_string())?;
    if dead.cryptographic_validity != Validity::Valid
        || dead.evidence_validity != Validity::Invalid
        || !dead
            .failure_codes()
            .contains(&proof_core::ErrorCode::Revoked)
    {
        return Err(
            "demo invariant broken: revoked proof should stay crypto-valid but evidence-invalid/Revoked"
                .to_string(),
        );
    }
    println!(
        "    verdict: FAIL (exit 1) — same bytes, crypto still valid, attestation REVOKED: {:?}",
        dead.failure_codes()
    );
    write_json(
        &format!("{out_dir}/report.json"),
        serde_json::json!({
            "when": T_AFTER,
            "cryptographic_validity": "valid",
            "evidence_validity": "invalid",
            "policy_decision": dead.policy_decision.as_str(),
            "lifecycle": dead.lifecycle.iter().map(|l| l.status.as_str()).collect::<Vec<_>>(),
            "failure_codes": dead.failure_codes().iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        }),
    )?;

    let explanation = format!(
        "== fresh (t={T_FRESH}) ==
{}
== after revocation (t={T_AFTER}) ==
{}
",
        explain_report(&fresh),
        explain_report(&dead),
    );
    std::fs::write(format!("{out_dir}/explanation.txt"), explanation)
        .map_err(|e| format!("write explanation: {e}"))?;
    // A2 artifacts: raw canonical CBOR (the artifact of record), the final
    // report, and the human explanation. Extra JSON wrappers make the files
    // directly consumable by the CLI itself.
    std::fs::write(format!("{out_dir}/proof.cbor"), &built.canonical)
        .map_err(|e| format!("write proof.cbor: {e}"))?;
    println!(
        "[9] artifacts in {out_dir}: proof.cbor, report.json, explanation.txt (+ CLI wrappers)"
    );
    println!("demo complete: one signing event turned PASS into REVOKED. Deterministic: rerun reproduces every byte.");
    Ok(crate::EXIT_OK)
}
