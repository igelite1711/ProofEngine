//! Fuzz target: the policy parser. Invariants: (1) never panics on arbitrary
//! bytes (interpreted as UTF-8 JSON); (2) the accepted requirement set is
//! closed — a parsed policy only contains the eighteen known requirement types
//! (ten v1 leaves + eight v2 adjudication leaves); v2 expressions validate
//! before anything evaluates;
//! (3) parsing is deterministic: the same input yields the same policy.

#![no_main]

use libfuzzer_sys::fuzz_target;
use proof_core::Limits;
use proof_policy::{parse_policy, Requirement};

fuzz_target!(|data: &[u8]| { // PE-POLICY-008
    let limits = Limits::default();
    let text = String::from_utf8_lossy(data);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Ok(policy) = parse_policy(&v, &limits) {
            assert!(!policy.requirements.is_empty(), "parser let an empty policy through");
            for r in &policy.requirements {
                let described = r.describe();
                assert!(
                    !described.is_empty(),
                    "requirement must always describe itself"
                );
                // Closed set: describe() output for every variant is stable.
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
                    | Requirement::EvidenceUsable { .. }
                    | Requirement::RequiresReference { .. }
                    | Requirement::ForbidsReference { .. } => {}
                }
            }
            // Determinism: re-parse must yield the identical description set.
            let reparsed = parse_policy(&v, &limits).expect("same input, same result");
            let a: Vec<_> = policy.requirements.iter().map(|r| r.describe()).collect();
            let b: Vec<_> = reparsed.requirements.iter().map(|r| r.describe()).collect();
            assert_eq!(a, b);
        }
    }
});
