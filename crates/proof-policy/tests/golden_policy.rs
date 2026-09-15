// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy golden vectors (13 merchant PASS, 14 strict FAIL).
//! Re-verifies proof bytes and re-evaluates the stored policy from scratch.

use proof_policy::{
    evaluate_policy, parse_policy, state_from_report_and_proof, EvalInputs, RevocationSet,
};
use proof_verify::{PolicyDecision, VerifyCtx};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn load(name: &str) -> serde_json::Value {
    let p = fixtures().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
    serde_json::from_str(&s).unwrap()
}

fn check(name: &str) {
    let v = load(name);
    let limits = proof_core::Limits::default();
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    // Pipeline context embedded in the vector: live clock + fresh revocations
    // (matches the `eval_inputs` clock the policy decision expects).
    // Grandfathered fixtures predate the fail-closed default: explicit
    // caller-asserted absence (see proof-verify golden_proof.rs note).
    let vctx = &v["verify_ctx"];
    let vctx = VerifyCtx {
        verified_at: vctx["verified_at"].as_u64().unwrap(),
        clock_skew_leeway: vctx["skew_leeway"].as_u64().unwrap(),
        revocations_known_at: vctx["revocations_known_at"].as_u64(),
        require_status_feed: false,
        ..VerifyCtx::default()
    };
    let report = proof_verify::verify_proof(&bytes, &vctx).unwrap();
    let value = proof_format::decode_strict(&bytes, &limits).unwrap();
    let proof = proof_format::cbor_to_proof(&value, &limits).unwrap();
    let state = state_from_report_and_proof(&report, &proof).unwrap();

    let policy = parse_policy(&v["policy"], &limits).unwrap();
    let ei = &v["eval_inputs"];
    let inputs = EvalInputs {
        trusted_issuers: ei["trusted_issuers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect(),
        revocations: RevocationSet::new(
            ei["revoked"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string()),
        ),
        verified_at: ei["verified_at"].as_u64().unwrap(),
        skew_leeway: ei["skew_leeway"].as_u64().unwrap(),
    };
    let outcome = evaluate_policy(&state, &policy, &inputs);
    let want = v["expected"]["decision"].as_str().unwrap();
    let got = match outcome.decision {
        PolicyDecision::Pass => "pass",
        PolicyDecision::Fail => "fail",
        PolicyDecision::Indeterminate => "indeterminate",
    };
    assert_eq!(got, want, "{name}");
    // Stored per-requirement results must reproduce exactly.
    let want_results = v["expected"]["results"].as_array().unwrap();
    assert_eq!(outcome.results.len(), want_results.len(), "{name}");
    for (got_r, want_r) in outcome.results.iter().zip(want_results) {
        assert_eq!(
            got_r.requirement,
            want_r["requirement"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(got_r.passed, want_r["passed"].as_bool().unwrap(), "{name}");
    }
    // Explanation projects the same decision.
    let text = proof_policy::explain_outcome(&outcome);
    assert!(
        text.contains(&format!("Decision: {}", want.to_uppercase())),
        "{name}"
    );
}

#[test]
fn golden_13_merchant_pass() {
    check("golden-13.json");
}

#[test]
fn golden_14_strict_fail() {
    check("golden-14.json");
}

#[test]
fn golden_19_superseded_fails_not_superseded() {
    check("golden-19.json");
}

#[test]
fn golden_28_conflict_quorum_pass() {
    check("golden-28.json");
    // The v2 expression shape itself is pinned: quorum over two issuers.
    let v = load("golden-28.json");
    assert_eq!(v["policy"]["policy_version"], 2);
}

#[test]
fn golden_31_sanctions_screen_fail() {
    check("golden-31.json");
}
