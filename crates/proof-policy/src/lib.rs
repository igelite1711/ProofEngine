// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-policy: minimal declarative policy engine (ARCHITECTURE §5).
//! Implicit AND over a closed requirement set. No OR/NOT, no code evaluation,
//! no network. Same evidence under different policies may yield different
//! decisions: Evidence ≠ Policy, Proof ≠ Trust decision.

pub mod eval;
pub mod explain;
pub mod policy;
pub mod state;

pub use eval::{evaluate_policy, EvalInputs, PolicyOutcome, RequirementResult, RevocationSet};
pub use explain::{explain_full, explain_outcome, explain_report};
pub use policy::{
    canonical_policy_hash, parse_policy, policy_to_canonical_cbor, Policy, Requirement,
};
pub use state::{state_from_report_and_proof, VerifiedState};
