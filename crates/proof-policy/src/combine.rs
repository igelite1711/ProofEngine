// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-shot verify+policy helper (P2).
//!
//! Running policy on the wrong report (mismatched proof, divergent clock or
//! trust list) is a classic integration foot-gun. This typed helper makes
//! that pairing error impossible: one context in, one report plus one outcome
//! out. The pipeline and policy semantics are unchanged; this only pairs them.

use proof_core::ProofError;
use proof_verify::{VerificationContext, VerifyReport};

use crate::eval::{evaluate_policy, EvalInputs, PolicyOutcome, RevocationSet};
use crate::policy::Policy;
use crate::state::{state_from_report_and_proof, VerifiedState};

/// Typed verify+decide output.
#[derive(Debug, Clone)]
pub struct VerifiedDecision {
    pub report: VerifyReport,
    pub state: VerifiedState,
    pub outcome: PolicyOutcome,
}

/// Verify `proof_bytes` under `ctx`, project the verified state, and evaluate
/// `policy` with trust inputs derived from the *same* context.
///
/// `trusted_issuers` is taken from `ctx`; `verified_at`/`skew` likewise, so
/// pipeline and policy can never diverge. Caller-supplied `revocations`
/// covers the policy-side unsigned revocation set (defense-in-depth alongside
/// the pipeline's signed status objects).
pub fn verify_and_evaluate(
    proof_bytes: &[u8],
    ctx: &VerificationContext,
    policy: &Policy,
    revocations: RevocationSet,
) -> Result<VerifiedDecision, ProofError> {
    // Bounded inputs (DoS prevention): the one-shot path enforces the same
    // vector bounds the pipeline enforces, so pipeline and policy can never
    // diverge on trust-list size either.
    if ctx.trusted_issuers.len() > ctx.limits.max_trusted_issuers {
        return Err(proof_core::ErrorCode::LimitExceeded.err(format!(
            "trusted_issuers count {} exceeds max_trusted_issuers {}",
            ctx.trusted_issuers.len(),
            ctx.limits.max_trusted_issuers
        )));
    }
    // Revocation-set size is bounded by max_status_objects (the pipeline's
    // signed-status bound), not max_trusted_issuers. The previous check
    // copy-pasted the trust-list limit (32 vs 64) and message.
    if revocations.revoked.len() > ctx.limits.max_status_objects {
        return Err(proof_core::ErrorCode::LimitExceeded.err(format!(
            "revocations count {} exceeds max_status_objects {}",
            revocations.revoked.len(),
            ctx.limits.max_status_objects
        )));
    }
    let vctx = ctx.to_verify_ctx();
    let report = proof_verify::verify_proof(proof_bytes, &vctx)?;
    // Re-parse the proof for state projection (bytes already verified above;
    // parse failure here mirrors the report's own PARSE/SCHEMA records).
    let value = proof_format::decode_strict(proof_bytes, &ctx.limits)?;
    let proof = proof_format::cbor_to_proof(&value, &ctx.limits)?;
    let state = state_from_report_and_proof(&report, &proof)?;
    let mut inputs = EvalInputs::from(ctx);
    inputs.revocations = revocations;
    let outcome = evaluate_policy(&state, policy, &inputs);
    Ok(VerifiedDecision {
        report,
        state,
        outcome,
    })
}
