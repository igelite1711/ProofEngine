//! PE-NEUT-003 — the constructive neutrality proof (docs/NEUTRALITY.md §6).
//! PE-NEUT-004 co-assertion: every domain word below lives in a test file,
//! never in a mechanism crate source (enforced by tools/check_neutrality.py).
//!
//! Ten unrelated industries (payment, credential lifecycle, media licensing,
//! AI-action provenance, sensor calibration, logistics, legal, supply-chain,
//! healthcare, government) traverse the SAME core:
//! same builder, same 11-stage pipeline, same policy engine. The differential
//! assertions prove the verdict shape is a pure function of artifact STRUCTURE,
//! never of the domain vocabulary riding on it. If a future change makes the
//! core care about any industry, these tests fail.

mod ai;
mod credential;
mod gov;
mod health;
mod legal;
mod logistics;
mod media;
mod payment;
mod sensor;
mod supplychain;

use proof_core::{ErrorCode, Limits};
use proof_crypto::build::to_signed_status;
use proof_policy::{evaluate_policy, parse_policy, state_from_report_and_proof};
use proof_verify::{verify_proof, PolicyDecision, Validity, VerifyCtx};

/// The exact caller context every domain uses: one shape, ten industries.
fn ctx(clock: u64) -> VerifyCtx {
    VerifyCtx {
        verified_at: clock,
        clock_skew_leeway: 300,
        revocations_known_at: Some(clock),
        ..VerifyCtx::default()
    }
}

/// What a successful domain journey must look like — identical for every
/// industry. `domain` names the journey only for failure messages.
fn assert_healthy_shape(domain: &str, report: &proof_verify::VerifyReport) {
    assert_eq!(
        report.cryptographic_validity,
        Validity::Valid,
        "{domain}: crypto validity must be Valid"
    );
    assert_eq!(
        report.evidence_validity,
        Validity::Valid,
        "{domain}: evidence validity must be Valid"
    );
    assert_eq!(
        report.policy_decision,
        PolicyDecision::Indeterminate,
        "{domain}: pipeline must leave the decision to policy (PE-NEUT-002)"
    );
    assert!(
        report
            .lifecycle
            .iter()
            .all(|l| l.status == proof_core::LifecycleStatus::Active),
        "{domain}: every attestation must be lifecycle-ACTIVE at the happy clock"
    );
    // The pipeline ran to the end for every domain: the last stage is POLICY,
    // where the pipeline explicitly hands the decision to the caller
    // (PE-NEUT-002 — the pipeline never PASSes by itself).
    assert_eq!(
        report.checks.last().map(|c| c.stage),
        Some("POLICY"),
        "{domain}: pipeline must reach the POLICY hand-off stage"
    );
}

/// One executed journey: name, built proof, caller policy, evaluation inputs.
type DomainJourney = (
    &'static str,
    proof_verify::BuiltProof,
    serde_json::Value,
    proof_policy::EvalInputs,
);

#[test]
fn ten_domains_same_core_same_verdict_shape() {
    let domains: [DomainJourney; 10] = [
        (
            "payment",
            payment::journey(),
            payment::policy(),
            payment::inputs(),
        ),
        (
            "credential",
            credential::journey(),
            credential::policy(),
            credential::inputs(),
        ),
        ("media", media::journey(), media::policy(), media::inputs()),
        ("ai", ai::journey(), ai::policy(), ai::inputs()),
        (
            "sensor",
            sensor::journey(),
            sensor::policy(),
            sensor::inputs(),
        ),
        (
            "logistics",
            logistics::journey(),
            logistics::policy(),
            logistics::inputs(),
        ),
        ("legal", legal::journey(), legal::policy(), legal::inputs()),
        (
            "supplychain",
            supplychain::journey(),
            supplychain::policy(),
            supplychain::inputs(),
        ),
        (
            "health",
            health::journey(),
            health::policy(),
            health::inputs(),
        ),
        ("gov", gov::journey(), gov::policy(), gov::inputs()),
    ];

    for (name, built, policy_json, inputs) in domains {
        let lim = Limits::default();
        let report = verify_proof(&built.canonical, &ctx(1_700_000_200)).unwrap();
        assert_healthy_shape(name, &report);

        // Verdict: PASS under the domain's own caller-supplied policy.
        let state = state_from_report_and_proof(&report, &built.proof).unwrap();
        let policy = parse_policy(&policy_json, &lim).unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs);
        assert_eq!(
            outcome.decision,
            PolicyDecision::Pass,
            "{name}: healthy journey must PASS its own policy (results: {:?})",
            outcome.results
        );

        // Stage shape is domain-independent: the pipeline visits the same
        // stages in the same order regardless of industry.
        let mut stages: Vec<&str> = report.checks.iter().map(|c| c.stage).collect();
        stages.dedup();
        let expected_prefix = ["PARSE", "SCHEMA", "CANONICAL", "IDENTIFIERS"];
        assert_eq!(
            &stages[..expected_prefix.len()],
            &expected_prefix[..],
            "{name}: pipeline stage order must be domain-independent"
        );
    }
}

#[test]
fn grounding_rule_is_domain_independent() {
    // The trust-relevant-edge rule (edge needs evidence/attestation backing)
    // must fire identically for the payment SETTLES edge and the AI EXECUTED
    // edge — structure, not vocabulary.
    for (name, journey_fn) in [
        (
            "payment",
            payment::journey as fn() -> proof_verify::BuiltProof,
        ),
        ("ai", ai::journey),
    ] {
        let built = journey_fn();
        // Null the edge's evidence_ref in the CBOR envelope directly: a
        // grounding-required relationship with no backing material.
        let mut v = proof_format::decode_strict(&built.canonical, &Limits::default()).unwrap();
        if let proof_format::CborValue::Map(pairs) = &mut v {
            for (k, val) in pairs.iter_mut() {
                if matches!(k, proof_format::CborValue::Text(s) if s == "relationships") {
                    if let proof_format::CborValue::Array(rels) = val {
                        if let Some(proof_format::CborValue::Map(rel)) = rels.first_mut() {
                            for (rk, rval) in rel.iter_mut() {
                                if matches!(rk, proof_format::CborValue::Text(s) if s == "evidence_ref")
                                {
                                    *rval = proof_format::CborValue::Null;
                                }
                            }
                        }
                    }
                }
            }
        }
        let stripped = proof_format::encode_canonical(&v);
        // The pipeline REPORTS structural failures in-band (Ok(report)).
        let report = verify_proof(&stripped, &ctx(1_700_000_200)).unwrap();
        let ungrounded = report
            .checks
            .iter()
            .find(|c| c.stage == "RELATIONSHIPS" && !c.ok)
            .expect("{name}: RELATIONSHIPS stage must report the failure");
        assert_eq!(
            ungrounded.code,
            Some(ErrorCode::RelationshipUngrounded),
            "{name}: ungrounded edge must fail identically across domains"
        );
    }
}

#[test]
fn unknown_domain_vocabulary_survives_pipeline() {
    // A domain nobody predicted ("agritech.crop.harvested") must pass the
    // schema stage: the core transports vocabulary, it never judges it
    // (NEUTRALITY §2). Changing the type changes event bytes, so the proof id
    // no longer binds — the pipeline must catch that STRUCTURAL fact
    // (IdMismatch) while the SCHEMA stage itself stays green. That split —
    // schema accepts, identifiers bind — IS the neutrality assertion.
    let built = media::journey();
    let mut v = proof_format::decode_strict(&built.canonical, &Limits::default()).unwrap();
    if let proof_format::CborValue::Map(pairs) = &mut v {
        for (k, val) in pairs.iter_mut() {
            if matches!(k, proof_format::CborValue::Text(s) if s == "events") {
                if let proof_format::CborValue::Array(events) = val {
                    if let Some(proof_format::CborValue::Map(ev)) = events.first_mut() {
                        for (ek, eval) in ev.iter_mut() {
                            if matches!(ek, proof_format::CborValue::Text(s) if s == "type") {
                                *eval =
                                    proof_format::CborValue::Text("agritech.crop.harvested".into());
                            }
                        }
                    }
                }
            }
        }
    }
    let reencoded = proof_format::encode_canonical(&v);
    let report = verify_proof(&reencoded, &ctx(1_700_000_200)).unwrap();
    let schema = report
        .checks
        .iter()
        .find(|c| c.stage == "SCHEMA")
        .expect("SCHEMA stage must run");
    assert!(
        schema.ok,
        "unknown domain vocabulary must pass the schema stage (message: {})",
        schema.message
    );
    assert!(
        report.failure_codes().contains(&ErrorCode::IdMismatch),
        "changed bytes must be caught structurally by the identifier binding"
    );
}

#[test]
fn unknown_domain_vocabulary_policy_fail_closed() {
    // The same unpredicted vocabulary, run through policy: a caller policy
    // that does not know it must FAIL closed — never silently PASS.
    let built = media::journey();
    let lim = Limits::default();
    let report = verify_proof(&built.canonical, &ctx(1_700_000_200)).unwrap();
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();

    // Policy demands an unrelated domain edge; the media journey does not
    // carry it → FAIL (explicit, explained), for ANY vocabulary.
    let stranger = serde_json::json!({
        "policy_version": 1,
        "policy_id": "unrelated_domain_v1",
        "requirements": [
            {"type": "relationship_exists", "relationship": "AGRITECH_DELIVERED_TO"}
        ]
    });
    let policy = parse_policy(&stranger, &lim).unwrap();
    let outcome = evaluate_policy(&state, &policy, &media::inputs());
    assert_eq!(outcome.decision, PolicyDecision::Fail);
    assert!(outcome
        .results
        .iter()
        .any(|r| r.requirement.contains("AGRITECH_DELIVERED_TO") && !r.passed));
}

/// One domain case: name, journey builder, policy, evaluation inputs.
type DomainCase = (
    &'static str,
    fn() -> proof_verify::BuiltProof,
    fn() -> serde_json::Value,
    fn() -> proof_policy::EvalInputs,
);

#[test]
fn cross_domain_failure_verdict_shape_identical() {
    // Revoke each domain's journey with a signed status object; the resulting
    // verdict shape (evidence invalid, REVOKED code, policy INDETERMINATE
    // with an explanatory note) must be logically identical across all ten
    // industries. Failure is structural; none of the domains is special.
    let cases: [DomainCase; 10] = [
        (
            "payment",
            payment::journey,
            payment::policy,
            payment::inputs,
        ),
        (
            "credential",
            credential::journey,
            credential::policy,
            credential::inputs,
        ),
        ("media", media::journey, media::policy, media::inputs),
        ("ai", ai::journey, ai::policy, ai::inputs),
        (
            "sensor",
            sensor::journey,
            sensor::policy,
            sensor::inputs,
        ),
        (
            "logistics",
            logistics::journey,
            logistics::policy,
            logistics::inputs,
        ),
        ("legal", legal::journey, legal::policy, legal::inputs),
        (
            "supplychain",
            supplychain::journey,
            supplychain::policy,
            supplychain::inputs,
        ),
        (
            "health",
            health::journey,
            health::policy,
            health::inputs,
        ),
        ("gov", gov::journey, gov::policy, gov::inputs),
    ];
    for (name, journey_fn, policy_fn, inputs_fn) in cases {
        let built = journey_fn();
        let att_id = attestation_id(&built);
        let lim = Limits::default();
        let rev = proof_crypto::build::revoke_attestation(
            &att_id,
            Some("screening"),
            payment::issuer_key(),
            1_700_000_250,
            &lim,
        )
        .unwrap();
        let signed = to_signed_status(&rev).unwrap();
        let mut c = ctx(1_700_000_300);
        c.status_objects = vec![signed];
        let report = verify_proof(&built.canonical, &c).unwrap();

        assert_eq!(
            report.evidence_validity,
            Validity::Invalid,
            "{name}: revoked journey must be evidence-invalid"
        );
        assert!(
            report.failure_codes().contains(&ErrorCode::Revoked),
            "{name}: REVOKED code must be reported"
        );
        let state = state_from_report_and_proof(&report, &built.proof).unwrap();
        let policy = parse_policy(&policy_fn(), &lim).unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs_fn());
        assert_eq!(
            outcome.decision,
            PolicyDecision::Indeterminate,
            "{name}: broken preconditions are INDETERMINATE, never a domain opinion"
        );
        assert!(
            outcome.note.is_some(),
            "{name}: INDETERMINATE must explain why"
        );
    }
}

/// Recompute the attestation id from stored content (the id is
/// sha256(canonical content), per PE-CRYPTO-006) — used to target the revoke.
fn attestation_id(built: &proof_verify::BuiltProof) -> String {
    let att = built
        .proof
        .attestations
        .first()
        .expect("journey has one attestation");
    let canonical =
        proof_format::encode_canonical(&proof_format::attestation_to_cbor(&att.content));
    format!(
        "{}:v1:{}",
        proof_core::model::id_prefix::ATTESTATION,
        proof_crypto::id::b64u_nopad(&proof_crypto::hash::sha256(&canonical))
    )
}
