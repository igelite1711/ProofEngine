// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic policy evaluator (implicit AND). Pure function of
//! (state, policy, explicit trust inputs) — no I/O, no crypto, no AI.
// PE-TRUST-005: trusted_issuers is caller input; constrain it by evaluation
// time for key-rotation semantics (TRUST.md "Key lifetime").
// PE-NEUT-002: broken cryptographic/evidence preconditions short-circuit to
// INDETERMINATE here — PASS is only ever produced by satisfied requirements,
// never by signature validity alone (valid ≠ trusted ≠ accepted).

use crate::policy::{Policy, Requirement};
use crate::state::VerifiedState;
use proof_verify::PolicyDecision;
use std::collections::HashSet;

/// Caller-supplied revocation data. V0.1 semantics: an id present here is
/// revoked; anything else is "no revocation known" (NOT "fresh"). Freshness
/// windows and transparency-anchored status land in Phase 6.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    pub revoked: HashSet<String>,
}

impl RevocationSet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            revoked: ids.into_iter().collect(),
        }
    }
}

/// Explicit trust inputs. `verified_at` must be a trustworthy clock reading;
/// `skew_leeway` (default 300s) absorbs honest clock drift only.
#[derive(Debug, Clone)]
pub struct EvalInputs {
    pub trusted_issuers: Vec<String>,
    pub revocations: RevocationSet,
    pub verified_at: u64,
    pub skew_leeway: u64,
}

impl Default for EvalInputs {
    fn default() -> Self {
        Self {
            trusted_issuers: vec![],
            revocations: RevocationSet::empty(),
            // Zero clock fails time requirements until the caller supplies a
            // real one — fail-closed default.
            verified_at: 0,
            skew_leeway: 300,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequirementResult {
    pub requirement: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    pub policy_id: String,
    pub decision: PolicyDecision,
    /// Why, when the decision is INDETERMINATE (proof-side failure).
    pub note: Option<String>,
    pub results: Vec<RequirementResult>,
}

fn pass(req: &str, message: impl Into<String>) -> RequirementResult {
    RequirementResult {
        requirement: req.into(),
        passed: true,
        message: message.into(),
    }
}

fn fail(req: &str, message: impl Into<String>) -> RequirementResult {
    RequirementResult {
        requirement: req.into(),
        passed: false,
        message: message.into(),
    }
}

/// Evaluate a validated policy against verified state. Deterministic: same
/// inputs always yield the same outcome.
pub fn evaluate_policy(
    state: &VerifiedState,
    policy: &Policy,
    inputs: &EvalInputs,
) -> PolicyOutcome {
    // Broken evidence makes policy evaluation meaningless — and must never
    // degrade into PASS. INDETERMINATE, not FAIL: the policy wasn't refuted,
    // its preconditions weren't met.
    // PE-NEUT-002: verification, trust, and policy verdicts stay distinct —
    // a broken proof is a precondition failure, never a domain opinion.
    if !state.crypto_valid || !state.evidence_valid {
        return PolicyOutcome {
            policy_id: policy.id.clone(),
            decision: PolicyDecision::Indeterminate,
            note: Some(format!(
                "proof not valid (crypto={}, evidence={}); policy not evaluated",
                onoff(state.crypto_valid),
                onoff(state.evidence_valid)
            )),
            results: vec![],
        };
    }
    let mut results = Vec::with_capacity(policy.requirements.len());
    for req in &policy.requirements {
        results.push(eval_one(req, state, inputs));
    }
    let decision = if results.iter().all(|r| r.passed) {
        PolicyDecision::Pass
    } else {
        PolicyDecision::Fail
    };
    PolicyOutcome {
        policy_id: policy.id.clone(),
        decision,
        note: None,
        results,
    }
}

fn onoff(b: bool) -> &'static str {
    if b {
        "valid"
    } else {
        "invalid"
    }
}

/// PE-POLICY-001..008 dispatch (PE-POLICY-009 gate above in evaluate_policy).
fn eval_one(req: &Requirement, state: &VerifiedState, inputs: &EvalInputs) -> RequirementResult {
    let name = req.describe();
    match req {
        // PE-POLICY-001
        Requirement::SignatureValid => pass(
            &name,
            "pipeline established cryptographic validity for this proof",
        ),
        // PE-POLICY-002 · PE-TRUST-001 · PE-NEUT-002 (valid signature and
        // trusted issuer are never conflated: both the trust list AND a
        // signature-verified attestation are required).
        Requirement::IssuerTrusted { issuer } => {
            let listed = inputs.trusted_issuers.iter().any(|t| t == issuer);
            let present = state.verified_issuers.iter().any(|i| i == issuer);
            match (listed, present) {
                (true, true) => pass(&name, format!("issuer {issuer} verified and trusted")),
                (false, _) => fail(&name, format!("issuer {issuer} not in trust list")),
                (true, false) => fail(
                    &name,
                    format!("trusted issuer {issuer} has no verified attestation here"),
                ),
            }
        }
        // PE-POLICY-003
        Requirement::IssuerExcluded { issuer } => {
            if state.verified_issuers.iter().any(|i| i == issuer) {
                fail(
                    &name,
                    format!("excluded issuer {issuer} has a verified attestation in this proof"),
                )
            } else {
                pass(
                    &name,
                    format!("excluded issuer {issuer} absent from this proof"),
                )
            }
        }
        Requirement::RelationshipExists { relationship } => {
            if state.rel_types.contains(relationship) {
                pass(
                    &name,
                    format!("edge {} present in validated graph", relationship.as_str()),
                )
            } else {
                fail(
                    &name,
                    format!("no {} edge in validated graph", relationship.as_str()),
                )
            }
        }
        // PE-POLICY-004
        Requirement::NotExpired => {
            for (id, (issued, expires)) in state
                .attestation_ids
                .iter()
                .zip(state.attestation_times.iter())
            {
                if *issued > inputs.verified_at.saturating_add(inputs.skew_leeway) {
                    return fail(
                        &name,
                        format!("attestation {id} issued in the future relative to verifier clock"),
                    );
                }
                if let Some(exp) = expires {
                    if inputs.verified_at > exp.saturating_add(inputs.skew_leeway) {
                        return fail(&name, format!("attestation {id} expired"));
                    }
                }
                // expires_at == None: no bounded validity to violate (a policy
                // needing mandatory expiry wants a future requirement type).
            }
            pass(
                &name,
                format!(
                    "{} attestation(s) within validity at {}",
                    state.attestation_ids.len(),
                    inputs.verified_at
                ),
            )
        }
        // PE-POLICY-005
        Requirement::NotRevoked => {
            for id in &state.attestation_ids {
                if inputs.revocations.revoked.contains(id) {
                    return fail(&name, format!("attestation {id} revoked"));
                }
            }
            pass(
                &name,
                format!(
                    "no known revocation among {} attestation(s)",
                    state.attestation_ids.len()
                ),
            )
        }
        // PE-POLICY-006
        Requirement::NotSuperseded => {
            if state.superseded_ids.is_empty() {
                pass(&name, "no attestation in this proof is superseded")
            } else {
                fail(
                    &name,
                    format!(
                        "superseded attestation(s) present: {}",
                        state.superseded_ids.join(", ")
                    ),
                )
            }
        }
        // PE-POLICY-007
        Requirement::EvidencePresent { kind } => {
            if state.evidence_kinds.contains(kind) {
                pass(&name, format!("evidence {} present", kind.as_str()))
            } else {
                fail(&name, format!("evidence {} missing", kind.as_str()))
            }
        }
        // PE-POLICY-007
        Requirement::TransparencyPresent => {
            if state.has_transparency() {
                pass(&name, "transparency_receipt present")
            } else {
                fail(&name, "no transparency_receipt in proof")
            }
        }
        // V1.1: Proof freshness (replay protection)
        Requirement::ProofFresh { max_age_seconds } => {
            let age = inputs.verified_at.saturating_sub(state.proof_created_at);
            if age <= *max_age_seconds {
                pass(&name, format!("proof age {age}s <= {max_age_seconds}s"))
            } else {
                fail(&name, format!("proof too old: {age}s > {max_age_seconds}s"))
            }
        }
    }
}
