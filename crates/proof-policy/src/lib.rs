// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-policy: declarative policy engine (ARCHITECTURE §5).
//! V1: implicit AND over a closed requirement set. V2 (`policy_version: 2`):
//! boolean connectives + thresholds over v1 leaves plus adjudication leaves
//! (delegation, identity, transparency, conflict, vocabulary, usability).
//! No code evaluation, no network. Same evidence under different policies
//! may yield different decisions: Evidence ≠ Policy, Proof ≠ Trust decision.

pub mod combine;
pub mod eval;
pub mod explain;
pub mod expr;
pub mod policy;
pub mod state;

pub use combine::{verify_and_evaluate, VerifiedDecision};

pub use eval::{evaluate_policy, EvalInputs, PolicyOutcome, RequirementResult, RevocationSet};
pub use explain::{explain_full, explain_outcome, explain_policy, explain_report};
pub use expr::PolicyExpr;
pub use policy::{
    canonical_policy_hash, parse_policy, policy_to_canonical_cbor, Policy, Requirement,
};

/// True when the policy evaluates `proof_fresh` anywhere (v1 list or v2 tree).
/// Diagnostic helper for front ends and tooling: `proof_fresh` reads
/// `created_at`, which IS covered by `proof_id` (re-stamping breaks the id and
/// fails at IDENTIFIERS), but it still only bounds self-declared age against
/// the verifier clock. Pair with `not_expired` (signed windows) for strong
/// freshness.
pub fn policy_uses_proof_fresh(policy: &Policy) -> bool {
    if policy.version == 2 {
        if let Some(expr) = &policy.expression {
            return expr_uses(expr, "proof_fresh");
        }
        return false;
    }
    policy
        .requirements
        .iter()
        .any(|r| r.type_str() == "proof_fresh")
}

/// True when the policy evaluates `not_expired` anywhere (signed windows).
pub fn policy_uses_not_expired(policy: &Policy) -> bool {
    if policy.version == 2 {
        if let Some(expr) = &policy.expression {
            return expr_uses(expr, "not_expired");
        }
        return false;
    }
    policy
        .requirements
        .iter()
        .any(|r| r.type_str() == "not_expired")
}

fn expr_uses(expr: &PolicyExpr, want: &str) -> bool {
    match expr {
        PolicyExpr::Leaf(r) => r.type_str() == want,
        PolicyExpr::All(cs) | PolicyExpr::Any(cs) => cs.iter().any(|c| expr_uses(c, want)),
        PolicyExpr::Not(c) => expr_uses(c, want),
        PolicyExpr::Threshold { options, .. } => options.iter().any(|c| expr_uses(c, want)),
    }
}
pub use state::{
    state_from_report_and_proof, ClaimSummary, Delegation, EdgeFact, EvidenceStatusEntry,
    IdentityBinding, VerifiedState,
};
