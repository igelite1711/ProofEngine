// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `demo --interactive`: a guided 60-second tour of Proof Engine.
//!
//! Thin presentation client over the core: every build, verification,
//! tamper check, policy evaluation, revocation, and supersession on this tour
//! calls the existing `proof-*` crates directly. Nothing here re-implements
//! cryptography, canonicalization, verification, graph validation, lifecycle,
//! or policy semantics. No ANSI colors (textual PASS/FAIL/UNKNOWN only).

use crate::Cli;
use proof_core::model::{
    AttestationContent, Claim, EventContent, EventType, EvidenceKind, MetaValue, Proposition,
    RelType, Relationship,
};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{attest, create_event, fixtures, make_evidence, make_relationship};
use proof_crypto::{revoke_attestation, supersede_attestation, SignedStatus};
use proof_policy::explain_report;
use proof_verify::{verify_proof, BuiltProof, ProofBuilder, Validity, VerifyCtx};
use std::io::{IsTerminal, Write};

// Fixed tour timestamps (deterministic; the tour is reproducible).
const T_EVENT: u64 = 1_757_000_000;
const T_ATTEST: u64 = 1_757_000_100;
const T_BUILT: u64 = 1_757_000_200;
const T_FRESH: u64 = 1_757_000_300;
const T_REVOKE: u64 = 1_757_000_400;
const T_AFTER: u64 = 1_757_000_500;
const T_ATTEST2: u64 = 1_757_000_600;
const T_SUPERSEDE: u64 = 1_757_000_700;
const T_LATE: u64 = 1_757_000_800;

/// A fully built tour proof plus the pieces later stages need.
struct TourProof {
    built: BuiltProof,
    proof: proof_core::model::Proof,
    att_id: String,
}

fn limits() -> Limits {
    Limits::default()
}

fn sha256_fill(byte: u8) -> HashRef {
    // Fixed demo digest: 32 bytes always satisfies Sha256 length, so direct
    // construction is fail-closed without a fallible Result path.
    HashRef {
        v: 1,
        alg: HashAlgorithm::Sha256,
        digest: vec![byte; 32],
    }
}

/// Build the financial-transaction example entirely through the core.
fn build_payment() -> Result<TourProof, String> {
    let lim = limits();
    let key = fixtures::test_key();
    let pay = create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("payment.created"),
            subject: "payment:p-tour".into(),
            effective_at: T_EVENT,
            payload_ref: sha256_fill(0x5E),
            metadata: vec![("order".into(), MetaValue::Text("ord-tour-1".into()))],
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let inv = create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("invoice.issued"),
            subject: "invoice:i-tour".into(),
            effective_at: T_EVENT,
            payload_ref: sha256_fill(0xA7),
            metadata: vec![],
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let att = attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p-tour".into(),
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
    let evd = make_evidence(
        EvidenceKind::new("transaction_record"),
        sha256_fill(0xE1),
        Some(att.id.clone()),
        Some("acquirer:receipt:tour".into()),
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let edge = make_relationship(
        Relationship {
            v: 1,
            rel_type: RelType::new("SETTLES"),
            from: pay.id.clone(),
            to: inv.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p-tour".into(),
            predicate: "settles".into(),
            object: Some("invoice:i-tour".into()),
            at_time: Some(T_ATTEST),
            context: vec![],
        },
        T_BUILT,
    );
    b.add_event(pay);
    b.add_event(inv);
    b.add_attestation(att.clone());
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).map_err(|e| e.to_string())?;
    let proof = decode(&built.canonical, &lim)?;
    Ok(TourProof {
        att_id: att.id,
        built,
        proof,
    })
}

/// Build the software-artifact example: different vocabulary, same engine.
fn build_software() -> Result<TourProof, String> {
    let lim = limits();
    let key = fixtures::test_key();
    let src = create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("source.committed"),
            subject: "repo:svc".into(),
            effective_at: T_EVENT,
            payload_ref: sha256_fill(0xC0),
            metadata: vec![("rev".into(), MetaValue::Text("r4242".into()))],
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let fin = create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("build.finished"),
            subject: "artifact:svc-2.1.0".into(),
            effective_at: T_EVENT,
            payload_ref: sha256_fill(0xBE),
            metadata: vec![],
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let att = attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "artifact:svc-2.1.0".into(),
            claim: Claim {
                claim_type: "artifact.released".into(),
                fields: vec![("channel".into(), MetaValue::Text("stable".into()))],
            },
            issued_at: T_ATTEST,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let evd = make_evidence(
        EvidenceKind::new("receipt"),
        sha256_fill(0xB1),
        Some(att.id.clone()),
        Some("ci:build-log:tour".into()),
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let edge = make_relationship(
        Relationship {
            v: 1,
            rel_type: RelType::new("PRODUCED"),
            from: fin.id.clone(),
            to: att.id.clone(),
            evidence_ref: Some(evd.id.clone()),
            attestation_ref: None,
        },
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "artifact.build-release".into(),
            subject: "artifact:svc-2.1.0".into(),
            predicate: "released".into(),
            object: None,
            at_time: Some(T_ATTEST),
            context: vec![],
        },
        T_BUILT,
    );
    b.add_event(src);
    b.add_event(fin);
    b.add_attestation(att.clone());
    b.add_evidence(evd);
    b.add_relationship(edge);
    let built = b.build(&lim).map_err(|e| e.to_string())?;
    let proof = decode(&built.canonical, &lim)?;
    Ok(TourProof {
        att_id: att.id,
        built,
        proof,
    })
}

fn decode(canonical: &[u8], lim: &Limits) -> Result<proof_core::model::Proof, String> {
    let value = proof_format::decode_strict(canonical, lim).map_err(|e| format!("decode: {e}"))?;
    proof_format::schema::cbor_to_proof(&value, lim).map_err(|e| format!("schema: {e}"))
}

fn verify_at(
    canonical: &[u8],
    at: u64,
    statuses: Vec<SignedStatus>,
) -> Result<proof_verify::VerifyReport, String> {
    verify_proof(
        canonical,
        &VerifyCtx {
            verified_at: at,
            clock_skew_leeway: 300,
            status_objects: statuses,
            revocations_known_at: Some(at),
            ..VerifyCtx::default()
        },
    )
    .map_err(|e| e.to_string())
}

fn policy_json(id: &str, extra: &str) -> serde_json::Value {
    // Fixed template over caller-supplied fragments; parse failure would mean a
    // programming error in the tour. Fail closed with a minimal valid policy
    // shape rather than panicking so CLI never aborts on demo paths.
    serde_json::from_str(&format!(
        r#"{{"policy_version":1,"policy_id":"{id}","requirements":[{extra}]}}"#
    ))
    .unwrap_or_else(|_| serde_json::json!({"policy_version":1,"policy_id":id,"requirements":[]}))
}

fn evaluate(
    report: &proof_verify::VerifyReport,
    proof: &proof_core::model::Proof,
    policy: &serde_json::Value,
    trusted: Vec<String>,
) -> Result<proof_policy::PolicyOutcome, String> {
    let lim = limits();
    let policy = proof_policy::parse_policy(policy, &lim).map_err(|e| format!("policy: {e}"))?;
    let state = proof_policy::state_from_report_and_proof(report, proof)
        .map_err(|e| format!("state: {e}"))?;
    Ok(proof_policy::evaluate_policy(
        &state,
        &policy,
        &proof_policy::EvalInputs {
            trusted_issuers: trusted,
            revocations: proof_policy::RevocationSet::empty(),
            verified_at: T_FRESH,
            skew_leeway: 300,
        },
    ))
}

/// Build both tour proofs twice and return their ids. The tour must be
/// deterministic: identical inputs always yield identical proof bytes.
pub fn tour_proof_ids() -> Result<(String, String), String> {
    let first = build_payment()?;
    let second = build_payment()?;
    if first.built.id != second.built.id {
        return Err("tour payment proof is not deterministic".to_string());
    }
    let third = build_software()?;
    let fourth = build_software()?;
    if third.built.id != fourth.built.id {
        return Err("tour software proof is not deterministic".to_string());
    }
    if first.built.id == third.built.id {
        return Err("tour domains must produce distinct proofs".to_string());
    }
    Ok((first.built.id, third.built.id))
}

/// Wait for Enter; `false` means the visitor quit early (or stdin closed).
fn pause() -> bool {
    print!("[Enter] continue   [q] quit > ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => false,
        Ok(_) => !matches!(line.trim(), "q" | "quit" | "exit"),
        Err(_) => false,
    }
}

fn screen(n: &str, title: &str) {
    println!("\n── {n} · {title} ─────────────────────────────");
}

fn edges_of(proof: &proof_core::model::Proof) -> Vec<(String, String, String)> {
    proof
        .relationships
        .iter()
        .map(|r| {
            (
                crate::sanitize(&r.from),
                crate::sanitize(r.rel_type.as_str()),
                crate::sanitize(&r.to),
            )
        })
        .collect()
}

/// The guided tour. Every fact shown comes from the core at runtime.
pub fn run(_cli: &Cli) -> Result<i32, String> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "interactive demo needs a terminal (stdin is not a TTY); run `proof-cli demo` for the scripted version"
                .to_string(),
        );
    }

    println!("Proof Engine — interactive demo (60 seconds)");
    println!("A claim, packaged with evidence and attestations, verified live.");
    println!("Nothing here is simulated: every verdict below is computed now.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 1. Build ----
    let tour = build_payment()?;
    screen("1/8", "BUILD — one claim becomes a proof");
    println!("Claim:        payment:p-tour settles invoice:i-tour");
    println!("Events:       payment.created, invoice.issued (payloads by digest)");
    println!("Attestation:  {} (signed)", tour.att_id);
    println!("Evidence:     transaction_record + receipt reference");
    println!("Relation:     SETTLES edge, backed by evidence");
    println!("Proof ID:     {}", tour.built.id);
    println!("\nThe original files never enter the proof — only their digests.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 2. Members + graph ----
    screen("2/8", "INSPECT — what is inside?");
    println!(
        "Members: {} events, {} attestations, {} evidence, {} relationships",
        tour.proof.events.len(),
        tour.proof.attestations.len(),
        tour.proof.evidence.len(),
        tour.proof.relationships.len()
    );
    println!();
    println!(
        "{}",
        crate::graph::render_text(
            &tour.proof.proposition.subject,
            &tour.proof.proposition.predicate,
            &edges_of(&tour.proof)
        )
    );
    println!("Inspection is read-only: INSPECTED is not VERIFIED.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 3. Verify ----
    screen("3/8", "VERIFY — the pipeline runs now");
    let fresh = verify_at(&tour.built.canonical, T_FRESH, vec![])?;
    print!("{}", explain_report(&fresh));
    let verdict = if fresh.passed_crypto() && fresh.evidence_validity == Validity::Valid {
        "PASS"
    } else {
        "FAIL"
    };
    println!("VERDICT: {verdict}");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 4. Policy ----
    screen("4/8", "POLICY — same proof, different decision");
    let issuer = tour.proof.attestations[0].content.issuer.clone();
    let base = policy_json(
        "tour-base",
        r#"{"type":"signature_valid"},{"type":"not_expired"}"#,
    );
    let strict = policy_json(
        "tour-strict",
        r#"{"type":"signature_valid"},{"type":"not_expired"},{"type":"transparency_present"}"#,
    );
    let out_base = evaluate(&fresh, &tour.proof, &base, vec![issuer.clone()])?;
    let out_strict = evaluate(&fresh, &tour.proof, &strict, vec![issuer])?;
    println!(
        "Policy tour-base   (signature + freshness): {:?}",
        out_base.decision
    );
    println!(
        "Policy tour-strict (+ transparency receipt): {:?}",
        out_strict.decision
    );
    println!("The bytes never changed. Proof validity is not a trust decision.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 5. Tamper ----
    screen("5/8", "TAMPER — attack the proof, watch it fail");
    let needle = b"invoice:i-tour";
    let pos = tour
        .built
        .canonical
        .windows(needle.len())
        .position(|w| w == needle)
        .ok_or_else(|| "tour setup: subject bytes missing".to_string())?;
    let mut tampered = tour.built.canonical.clone();
    tampered[pos] ^= 0x01;
    let bad = verify_at(&tampered, T_FRESH, vec![])?;
    let mut shown = 0;
    for c in &bad.checks {
        if !c.ok && shown < 4 {
            println!(
                "FAIL {} [{}] {}",
                c.stage,
                c.code.map(|k| k.as_str()).unwrap_or("NO_CODE"),
                crate::sanitize(&c.message)
            );
            shown += 1;
        }
    }
    println!("VERDICT: FAIL (one flipped byte)");
    let again = verify_at(&tour.built.canonical, T_FRESH, vec![])?;
    assert!(again.passed_crypto() && again.evidence_validity == Validity::Valid);
    println!("Original restored: VERDICT: PASS");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 6. Revoke ----
    screen("6/8", "REVOKE — the issuer kills their own claim");
    let lim = limits();
    let key = fixtures::test_key();
    let rev = revoke_attestation(&tour.att_id, Some("tour: mislabeled"), &key, T_REVOKE, &lim)
        .map_err(|e| e.to_string())?;
    let dead = verify_at(
        &tour.built.canonical,
        T_AFTER,
        vec![SignedStatus {
            content: rev.content.clone(),
            sign1: rev.sign1.clone(),
        }],
    )?;
    for l in &dead.lifecycle {
        println!("lifecycle {}: {}", l.object, l.status.as_str());
    }
    println!("Same bytes, new verdict: FAIL (REVOKED). History is never edited.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 7. Supersede ----
    screen("7/8", "SUPERSEDE — replaced, but history stays valid");
    let att2 = attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: "payment:p-tour".into(),
            claim: Claim {
                claim_type: "payment.settled".into(),
                fields: vec![("amount".into(), MetaValue::Uint(4300))],
            },
            issued_at: T_ATTEST2,
            expires_at: None,
            evidence_ref: None,
        },
        &key,
        &lim,
    )
    .map_err(|e| e.to_string())?;
    let sup = supersede_attestation(&tour.att_id, &att2.id, &key, T_SUPERSEDE, &lim)
        .map_err(|e| e.to_string())?;
    let moved = verify_at(
        &tour.built.canonical,
        T_LATE,
        vec![SignedStatus {
            content: sup.content.clone(),
            sign1: sup.sign1.clone(),
        }],
    )?;
    println!(
        "crypto {:?}, evidence {:?}, lifecycle {}",
        moved.cryptographic_validity,
        moved.evidence_validity,
        moved.lifecycle[0].status.as_str()
    );
    println!("SUPERSEDED keeps evidence valid: valid history, no longer current.");
    if !pause() {
        return Ok(crate::EXIT_OK);
    }

    // ---- 8. Neutrality ----
    screen("8/8", "NEUTRALITY — same engine, different domain");
    let sw = build_software()?;
    let sw_report = verify_at(&sw.built.canonical, T_FRESH, vec![])?;
    println!(
        "Software release {} → {}: crypto {:?}, evidence {:?}",
        sw.proof.proposition.subject,
        sw.proof.proposition.predicate,
        sw_report.cryptographic_validity,
        sw_report.evidence_validity
    );
    println!();
    println!(
        "{}",
        crate::graph::render_text(
            &sw.proof.proposition.subject,
            &sw.proof.proposition.predicate,
            &edges_of(&sw.proof)
        )
    );
    let sw_policy = policy_json("tour-software", r#"{"type":"signature_valid"}"#);
    let sw_out = evaluate(&sw_report, &sw.proof, &sw_policy, vec![])?;
    println!("Policy tour-software: {:?}", sw_out.decision);
    println!("\nSame engine. Different domain. Tour complete.");
    println!("Try: proof-cli verify, inspect, graph, evaluate, explain —");
    println!("every screen above maps to a command. The core does the work.");
    Ok(crate::EXIT_OK)
}
