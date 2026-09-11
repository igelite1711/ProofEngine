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
pub use state::{
    state_from_report_and_proof, ClaimSummary, Delegation, EdgeFact, EvidenceStatusEntry,
    IdentityBinding, VerifiedState,
};
