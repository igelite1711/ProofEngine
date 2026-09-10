// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Evidence-derived explanations. Pure projections of report + outcome:
//! the text can never contradict the machine verdict (tested on every vector).

use crate::eval::PolicyOutcome;
use proof_verify::{PolicyDecision, VerifyReport};

/// One line per failed check plus a one-line verdict summary of the report.
pub fn explain_report(report: &VerifyReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "cryptographic_validity: {}
",
        validity_word(report.cryptographic_validity)
    ));
    out.push_str(&format!(
        "evidence_validity: {}
",
        validity_word(report.evidence_validity)
    ));
    out.push_str(&format!(
        "policy_decision: {}
",
        report.policy_decision.as_str()
    ));
    for c in &report.checks {
        if c.ok {
            continue;
        }
        let code = c.code.map(|k| k.as_str()).unwrap_or("NO_CODE");
        out.push_str(&format!(
            "{} [{}] {}: {}
",
            "FAIL", c.stage, code, c.message
        ));
    }
    if report.checks.iter().all(|c| c.ok) {
        out.push_str(
            "all pipeline checks passed
",
        );
    }
    out
}

/// Requirement-by-requirement verdict for one policy evaluation.
pub fn explain_outcome(outcome: &PolicyOutcome) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "POLICY: {}

",
        outcome.policy_id
    ));
    if outcome.results.is_empty() {
        out.push_str(&format!(
            "{}

",
            outcome
                .note
                .as_deref()
                .unwrap_or("no requirements evaluated")
        ));
    }
    for r in &outcome.results {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "{} {} — {}
",
            mark, r.requirement, r.message
        ));
    }
    out.push_str(&format!(
        "
Decision: {}
",
        decision_word(outcome.decision)
    ));
    out
}

/// Combined view: pipeline verdict, then policy verdict.
// PE-POLICY-010: pure projections; can never contradict the verdict.
pub fn explain_full(report: &VerifyReport, outcome: &PolicyOutcome) -> String {
    format!(
        "{}
{}",
        explain_report(report),
        explain_outcome(outcome)
    )
}

fn validity_word(v: proof_verify::Validity) -> &'static str {
    match v {
        proof_verify::Validity::Valid => "valid",
        proof_verify::Validity::Invalid => "invalid",
    }
}

fn decision_word(d: PolicyDecision) -> &'static str {
    match d {
        PolicyDecision::Pass => "PASS",
        PolicyDecision::Fail => "FAIL",
        PolicyDecision::Indeterminate => "INDETERMINATE",
    }
}
