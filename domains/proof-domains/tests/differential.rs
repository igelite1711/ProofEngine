//! PE-NEUT-003 — the constructive neutrality proof (docs/NEUTRALITY.md §6).
//! PE-NEUT-004 co-assertion: every domain word below lives in a test file,
//! never in a mechanism crate source (enforced by tools/check_neutrality.py).
//!
//! Thirteen unrelated industries (payment, credential lifecycle, media licensing,
//! AI-action provenance, sensor calibration, logistics, legal, supply-chain,
//! healthcare, government, cybersecurity incident response, scientific
//! replication, election certification) traverse the SAME core:
//! same builder, same 11-stage pipeline, same policy engine. The differential
//! assertions prove the verdict shape is a pure function of artifact STRUCTURE,
//! never of the domain vocabulary riding on it. If a future change makes the
//! core care about any industry, these tests fail.

mod ai;
mod credential;
mod cyber;
mod election;
mod gov;
mod health;
mod legal;
mod logistics;
mod media;
mod payment;
mod science;
mod sensor;
mod supplychain;

use proof_core::{ErrorCode, Limits};
use proof_crypto::build::{attest, supersede_attestation, to_signed_status};
use proof_policy::{evaluate_policy, parse_policy, state_from_report_and_proof};
use proof_verify::{verify_proof, PolicyDecision, Validity, VerifyCtx};

/// The exact caller context every domain uses: one shape, thirteen industries.
/// Explicit caller-asserted absence (domain journeys pin vocabulary
/// neutrality, not feed behavior; the fail-closed default is pinned by the
/// core lifecycle tests).
fn ctx(clock: u64) -> VerifyCtx {
    VerifyCtx {
        verified_at: clock,
        clock_skew_leeway: 300,
        revocations_known_at: Some(clock),
        require_status_feed: false,
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

/// Shared journey check: healthy shape + PASS under own policy + stable stage order.
fn check_journey(
    name: &str,
    built: &proof_verify::BuiltProof,
    policy_json: &serde_json::Value,
    inputs: &proof_policy::EvalInputs,
) {
    let lim = Limits::default();
    let report = verify_proof(&built.canonical, &ctx(1_700_000_200)).unwrap();
    assert_healthy_shape(name, &report);

    // Verdict: PASS under the domain's own caller-supplied policy.
    let state = state_from_report_and_proof(&report, &built.proof).unwrap();
    let policy = parse_policy(policy_json, &lim).unwrap();
    let outcome = evaluate_policy(&state, &policy, inputs);
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

fn all_thirteen_domains() -> [DomainJourney; 13] {
    [
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
        (
            "science",
            science::journey(),
            science::policy(),
            science::inputs(),
        ),
        ("cyber", cyber::journey(), cyber::policy(), cyber::inputs()),
        (
            "election",
            election::journey(),
            election::policy(),
            election::inputs(),
        ),
    ]
}

#[test]
fn thirteen_domains_same_core_same_verdict_shape() {
    for (name, built, policy_json, inputs) in all_thirteen_domains() {
        check_journey(name, &built, &policy_json, &inputs);
    }
}

#[test]
fn ten_domains_same_core_same_verdict_shape() {
    // Backward-compat wrapper: the first ten of the canonical thirteen.
    // New code should use thirteen_domains_same_core_same_verdict_shape.
    for (name, built, policy_json, inputs) in all_thirteen_domains().into_iter().take(10) {
        check_journey(name, &built, &policy_json, &inputs);
    }
}

#[test]
fn science_cybersecurity_and_election_ride_the_same_core() {
    // Backward-compat wrapper: last three of the canonical thirteen.
    // New code should use thirteen_domains_same_core_same_verdict_shape.
    for (name, built, policy_json, inputs) in all_thirteen_domains().into_iter().skip(10) {
        check_journey(name, &built, &policy_json, &inputs);
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
    // with an explanatory note) must be logically identical across all thirteen
    // industries. Failure is structural; none of the domains is special.
    // (All journeys share the fixed test key, so the payment issuer key
    // authorizes every revocation — exactly like the per-domain issuer keys.)
    let cases: [DomainCase; 13] = [
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
        ("sensor", sensor::journey, sensor::policy, sensor::inputs),
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
        ("health", health::journey, health::policy, health::inputs),
        ("gov", gov::journey, gov::policy, gov::inputs),
        (
            "science",
            science::journey,
            science::policy,
            science::inputs,
        ),
        ("cyber", cyber::journey, cyber::policy, cyber::inputs),
        ("election", election::journey, election::policy, election::inputs),
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

#[test]
fn tamper_breaks_every_domain_identically() {
    // One flipped byte in the middle of each domain's canonical proof must
    // fail closed with identical shape (crypto Invalid + ≥1 code) in all
    // thirteen industries. Tamper-evidence is structural; no vocabulary is
    // special. (Middle-of-bytes avoids the informational `created_at` tail;
    // the pipeline reports structural failure in-band as Ok(report).)
    for (name, built, _, _) in all_thirteen_domains() {
        let mut mutant = built.canonical.clone();
        let mid = mutant.len() / 2;
        mutant[mid] ^= 0x01;
        let report = verify_proof(&mutant, &ctx(1_700_000_200))
            .unwrap_or_else(|_| panic!("{name}: tampered bytes must report in-band, never Err"));
        assert_ne!(
            report.cryptographic_validity,
            Validity::Valid,
            "{name}: tampered proof must never verify as cryptographically valid"
        );
        assert!(
            !report.failure_codes().is_empty(),
            "{name}: invalid verdict must carry at least one error code"
        );
    }
}

#[test]
fn foreign_policy_fails_closed_in_every_domain() {
    // The same stranger policy (demanding transparency no journey carries)
    // must FAIL in all thirteen industries while each journey still PASSes its
    // own policy (pinned by thirteen_domains_...). Policy governs acceptance;
    // the core never smuggles trust across vocabularies.
    let lim = Limits::default();
    let stranger = serde_json::json!({
        "policy_version": 1,
        "policy_id": "stranger_transparency_v1",
        "requirements": [{"type": "transparency_present"}]
    });
    let policy = parse_policy(&stranger, &lim).unwrap();
    for (name, built, _, inputs) in all_thirteen_domains() {
        let report = verify_proof(&built.canonical, &ctx(1_700_000_200)).unwrap();
        assert_healthy_shape(name, &report);
        let state = state_from_report_and_proof(&report, &built.proof).unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs);
        assert_eq!(
            outcome.decision,
            PolicyDecision::Fail,
            "{name}: stranger policy must FAIL (results: {:?})",
            outcome.results
        );
    }
}

#[test]
fn cross_domain_supersession_preserves_history() {
    // Supersede each domain's attestation with a newer sibling from the same
    // issuer: history must stay valid (SUPERSEDED preserves evidence
    // validity) while a `not_superseded` policy FAILs it for current use —
    // identically across all thirteen industries. This is the lifecycle
    // dimension revocation alone cannot show (revocation kills validity;
    // supersession preserves it).
    let cases: [DomainCase; 13] = [
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
        ("sensor", sensor::journey, sensor::policy, sensor::inputs),
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
        ("health", health::journey, health::policy, health::inputs),
        ("gov", gov::journey, gov::policy, gov::inputs),
        (
            "science",
            science::journey,
            science::policy,
            science::inputs,
        ),
        ("cyber", cyber::journey, cyber::policy, cyber::inputs),
        ("election", election::journey, election::policy, election::inputs),
    ];
    for (name, journey_fn, _, inputs_fn) in cases {
        let built = journey_fn();
        let old = attestation_id(&built);
        // The per-domain helper must agree exactly: identifiers are a pure
        // function of canonical bytes, so no domain remembers an id.
        let remembered = match name {
            "payment" => payment::attestation_id(),
            "credential" => credential::attestation_id(),
            "media" => media::attestation_id(),
            "ai" => ai::attestation_id(),
            "sensor" => sensor::attestation_id(),
            "logistics" => logistics::attestation_id(),
            "legal" => legal::attestation_id(),
            "supplychain" => supplychain::attestation_id(),
            "health" => health::attestation_id(),
            "gov" => gov::attestation_id(),
            "science" => science::attestation_id(),
            "cyber" => cyber::attestation_id(),
            "election" => election::attestation_id(),
            _ => unreachable!("unknown domain {name}"),
        };
        assert_eq!(
            remembered, old,
            "{name}: helper id must equal recomputed id"
        );
        let lim = Limits::default();
        // Sibling attestation: same claim, newer issuance, hence a new id.
        let mut content = built.proof.attestations[0].content.clone();
        content.issued_at += 50;
        let next = attest(content, payment::issuer_key(), &lim).unwrap();
        assert_ne!(next.id, old, "{name}: sibling must get a distinct id");
        let sup = supersede_attestation(&old, &next.id, payment::issuer_key(), 1_700_000_250, &lim)
            .unwrap();
        let mut c = ctx(1_700_000_300);
        c.status_objects = vec![to_signed_status(&sup).unwrap()];
        let report = verify_proof(&built.canonical, &c).unwrap();
        // History preserved: crypto and evidence stay Valid...
        assert_eq!(
            report.cryptographic_validity,
            Validity::Valid,
            "{name}: supersession must not rewrite crypto validity"
        );
        assert_eq!(
            report.evidence_validity,
            Validity::Valid,
            "{name}: superseded evidence stays valid (history preserved)"
        );
        // ...while the lifecycle names the superseded attestation.
        assert!(
            report
                .lifecycle
                .iter()
                .any(|l| l.status == proof_core::LifecycleStatus::Superseded),
            "{name}: lifecycle must report SUPERSEDED"
        );
        // ...and current-use policy fails it.
        let state = state_from_report_and_proof(&report, &built.proof).unwrap();
        let policy = parse_policy(
            &serde_json::json!({
                "policy_version": 1,
                "policy_id": "current_use_v1",
                "requirements": [
                    {"type": "signature_valid"},
                    {"type": "not_superseded"},
                ]
            }),
            &lim,
        )
        .unwrap();
        let outcome = evaluate_policy(&state, &policy, &inputs_fn());
        assert_eq!(
            outcome.decision,
            PolicyDecision::Fail,
            "{name}: not_superseded must FAIL superseded material (results: {:?})",
            outcome.results
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
