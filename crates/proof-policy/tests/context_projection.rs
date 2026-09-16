// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! F6 closure: `EvalInputs` is a thin projection of the single normative
//! `VerificationContext` — pipeline and policy can never diverge on
//! clock/trust.

use proof_policy::EvalInputs;
use proof_verify::VerificationContext;

#[test]
fn eval_inputs_projects_clock_and_trust_from_verification_context() {
    let ctx = VerificationContext {
        verified_at: 1_700_000_200,
        clock_skew_leeway: 60,
        trusted_issuers: vec!["key:ed25519:AAA".into()],
        ..VerificationContext::default()
    };
    let inputs = EvalInputs::from(&ctx);
    assert_eq!(inputs.verified_at, 1_700_000_200);
    assert_eq!(inputs.skew_leeway, 60);
    assert_eq!(inputs.trusted_issuers, vec!["key:ed25519:AAA".to_string()]);
    // The unsigned policy revocation set has no signed-pipeline counterpart:
    // the projection starts empty and the caller supplies it separately
    // (see `verify_and_evaluate`, which pairs both layers from one context).
    assert!(inputs.revocations.revoked.is_empty());
}
