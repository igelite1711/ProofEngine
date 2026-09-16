//! Fuzz target: the full 11-stage verification pipeline. Invariants for
//! arbitrary input: (1) the pipeline never panics (any panic is a finding);
//! (2) report coherence — an `Invalid` verdict always carries at least one
//! failure code (no silent failure); (3) determinism — the same input always
//! yields the same verdict and codes.
//!
//! NOTE: `cryptographic_validity == Valid` on arbitrary input is NOT a
//! violation by itself: the seed corpus intentionally contains a legitimate
//! proof, and a well-formed proof with valid signatures is crypto-Valid
//! under a matching context. Tamper-resistance (mutants must fail) is
//! covered by the stable mutation-soak (`crates/proof-verify/tests/soak.rs`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use proof_verify::{verify_proof, Validity, VerifyCtx};

fuzz_target!(|data: &[u8]| { // PE-VERIFY-012
    // Deterministic context derived from the input itself (no hidden clocks).
    let mut t = [0u8; 8];
    for (i, b) in data.iter().take(8).enumerate() {
        t[i] = *b;
    }
    let ctx = VerifyCtx {
        verified_at: u64::from_be_bytes(t),
        ..VerifyCtx::default()
    };
    if let Ok(report) = verify_proof(data, &ctx) {
        if report.cryptographic_validity == Validity::Invalid {
            assert!(
                !report.failure_codes().is_empty(),
                "invalid verdict must carry at least one error code"
            );
        }
        // Determinism: same bytes + same context => same verdict and codes.
        let again = verify_proof(data, &ctx).expect("deterministic re-run must succeed");
        assert_eq!(
            again.cryptographic_validity, report.cryptographic_validity,
            "verdict must be deterministic"
        );
        assert_eq!(
            again.failure_codes(),
            report.failure_codes(),
            "failure codes must be deterministic"
        );
    }
});
