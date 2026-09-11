// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proof golden vectors (11 valid, 12 mutated). Portable: fresh context derived
//! from the fixture's embedded `verify_ctx` (clock + revocation freshness).

use proof_core::LifecycleStatus;
use proof_verify::{verify_proof, PolicyDecision, Validity, VerifyCtx};
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

/// Rebuild the embedded `verify_ctx` (FORMAT §8) exactly: the fixture records
/// the clock and revocation freshness its expected verdict depends on.
fn ctx_from(v: &serde_json::Value) -> VerifyCtx {
    let c = &v["verify_ctx"];
    VerifyCtx {
        verified_at: c["verified_at"].as_u64().unwrap(),
        clock_skew_leeway: c["skew_leeway"].as_u64().unwrap(),
        revocations_known_at: c["revocations_known_at"].as_u64(),
        ..VerifyCtx::default()
    }
}

#[test]
fn golden_11_valid_proof() {
    let v = load("golden-11.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
    assert!(r.lifecycle_checked);
    assert!(r
        .lifecycle
        .iter()
        .all(|l| l.status == LifecycleStatus::Active));
    assert_eq!(r.proof_id.as_deref(), Some(v["proof_id"].as_str().unwrap()));
}

#[test]
fn golden_12_mutated_proof() {
    let v = load("golden-12.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok
            && c.stage == v["expected"]["stage"].as_str().unwrap()
            && c.code.map(|c| c.as_str()) == Some(v["expected"]["code"].as_str().unwrap())
    }));
}

/// Composition vectors 24–26 (SPEC §7): linkage binds when present (24 valid,
/// echoed as REFERENCED); stale self-links refuse with an explicit
/// CYCLE_DETECTED alongside ID_MISMATCH (25); malformed references fail
/// closed at SCHEMA (26).
#[test]
fn golden_24_composed_proof_with_references() {
    let v = load("golden-24.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
    assert_eq!(r.proof_id.as_deref(), Some(v["proof_id"].as_str().unwrap()));
    let expect_refs: Vec<String> = v["referenced_proofs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(r.referenced_proofs, expect_refs);
    assert!(r
        .checks
        .iter()
        .any(|c| c.ok && c.message.contains("REFERENCED")));
}

#[test]
fn golden_25_self_reference_refused() {
    let v = load("golden-25.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    let codes = r.failure_codes();
    for want in v["expected"]["codes"].as_array().unwrap() {
        let want = want.as_str().unwrap();
        assert!(
            codes.iter().any(|c| c.as_str() == want),
            "missing code {want} in {codes:?}"
        );
    }
}

#[test]
fn golden_26_malformed_reference_refused() {
    let v = load("golden-26.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Invalid);
    assert!(r.checks.iter().any(|c| {
        !c.ok
            && c.stage == v["expected"]["stage"].as_str().unwrap()
            && c.code.map(|c| c.as_str()) == Some(v["expected"]["code"].as_str().unwrap())
    }));
}

#[test]
fn golden_27_vocabulary_declaration_binds() {
    let v = load("golden-27.json");
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
    assert_eq!(r.evidence_validity, Validity::Valid);
    assert_eq!(r.policy_decision, PolicyDecision::Indeterminate);
    assert_eq!(r.proof_id.as_deref(), Some(v["proof_id"].as_str().unwrap()));
    let declared: Vec<(String, u64)> = r
        .vocabularies
        .iter()
        .map(|vd| (vd.ns.clone(), vd.version))
        .collect();
    assert_eq!(declared, vec![("acme".to_string(), 2)]);
    // Legacy labels alongside a declaration surface an informational note;
    // validity is unchanged (declaration is provenance, acceptance policy).
    assert!(r
        .checks
        .iter()
        .any(|c| c.ok && c.stage == "SCHEMA" && c.message.contains("used but not declared")));
}

/// Lifecycle vectors 15–18, 29–30 (acceptance A3): the embedded `verify_ctx`
/// must reproduce the recorded verdict, lifecycle flags, id, and failure
/// codes on a clean checkout — expired EXPIRED, revoked REVOKED, superseded
/// history preserved, missing revocation info REVOCATION_UNKNOWN, withdrawn
/// WITHDRAWN, compromised COMPROMISED (never PASS).
#[test]
fn golden_lifecycle_vectors_verify_as_recorded() {
    for name in [
        "golden-15.json",
        "golden-16.json",
        "golden-17.json",
        "golden-18.json",
        "golden-29.json",
        "golden-30.json",
    ] {
        let v = load(name);
        let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
        let r = verify_proof(&bytes, &ctx_from(&v)).unwrap();
        let expected = &v["expected"];
        let crypto = match expected["cryptographic_validity"].as_str().unwrap() {
            "valid" => Validity::Valid,
            _ => Validity::Invalid,
        };
        let evidence = match expected["evidence_validity"].as_str().unwrap() {
            "valid" => Validity::Valid,
            _ => Validity::Invalid,
        };
        assert_eq!(r.cryptographic_validity, crypto, "{name}");
        assert_eq!(r.evidence_validity, evidence, "{name}");
        assert!(r.lifecycle_checked, "{name}");
        if let Some(id) = v["proof_id"].as_str() {
            assert_eq!(r.proof_id.as_deref(), Some(id), "{name}");
        }
        let got = r.failure_codes();
        for want in expected["codes"].as_array().unwrap() {
            let want = want.as_str().unwrap();
            assert!(
                got.iter().any(|c| c.as_str() == want),
                "{name}: expected code {want} in {got:?}"
            );
        }
    }
}
