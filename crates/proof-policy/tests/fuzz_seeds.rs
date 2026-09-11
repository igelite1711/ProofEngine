// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stable mirror of `fuzz/fuzz_targets/policy_parser.rs`.
//! libFuzzer runs nightly-only (and cannot mmap under PRoot), so the checked-in
//! seed corpus (`fuzz/seeds/policy_parser/`) is replayed here on stable to
//! enforce the same invariants on every push: never panics, closed
//! requirement set, deterministic re-parse.

use proof_core::Limits;
use proof_policy::{parse_policy, Requirement};

fn seeds_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/policy_parser")
}

fn check_invariants(text: &str) {
    let limits = Limits::default();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Ok(policy) = parse_policy(&v, &limits) {
            assert!(
                !policy.requirements.is_empty(),
                "parser let an empty policy through: {text}"
            );
            for r in &policy.requirements {
                assert!(
                    !r.describe().is_empty(),
                    "requirement must always describe itself"
                );
                // Closed set: every variant is named here, so adding a
                // Requirement variant without updating this match fails
                // closed — same tripwire as the fuzz target.
                match r {
                    Requirement::SignatureValid
                    | Requirement::IssuerTrusted { .. }
                    | Requirement::IssuerExcluded { .. }
                    | Requirement::RelationshipExists { .. }
                    | Requirement::NotExpired
                    | Requirement::NotRevoked
                    | Requirement::NotSuperseded
                    | Requirement::EvidencePresent { .. }
                    | Requirement::TransparencyPresent
                    | Requirement::ProofFresh { .. }
                    | Requirement::DelegatedAuthority { .. }
                    | Requirement::IdentityBound { .. }
                    | Requirement::TransparencyInclusion { .. }
                    | Requirement::NoConflictingEvidence
                    | Requirement::VocabularyAccepted { .. }
                    | Requirement::EvidenceUsable { .. } => {}
                }
            }
            let reparsed = parse_policy(&v, &limits).expect("same input, same result");
            let a: Vec<_> = policy.requirements.iter().map(|r| r.describe()).collect();
            let b: Vec<_> = reparsed.requirements.iter().map(|r| r.describe()).collect();
            assert_eq!(a, b, "parsing must be deterministic");
        }
    }
}

#[test]
fn fuzz_seed_corpus_upholds_parser_invariants() {
    let dir = seeds_dir();
    let mut count = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("fuzz seed corpus must exist")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        check_invariants(&text);
        count += 1;
    }
    assert!(count >= 3, "expected at least the 3 checked-in seeds");
}

#[test]
fn fuzz_seed_hostiles_stay_rejected() {
    // unknown-req.json and extra-keys.json must never parse: closed set,
    // closed fields (PE-POLICY-008).
    let limits = Limits::default();
    for name in ["unknown-req.json", "extra-keys.json"] {
        let text = std::fs::read_to_string(seeds_dir().join(name)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            parse_policy(&v, &limits).is_err(),
            "{name} must stay rejected"
        );
    }
}
