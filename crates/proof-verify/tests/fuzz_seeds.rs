// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stable mirror of `fuzz/fuzz_targets/proof_verify.rs`.
//! libFuzzer runs nightly-only (and cannot mmap under PRoot), so the checked-in
//! seed corpus (`fuzz/seeds/proof_verify/`) is replayed here on stable to
//! enforce the same invariants on every push: never panics; an `Invalid`
//! verdict always carries codes; same bytes + same context give the same
//! verdict and codes (PE-VERIFY-012). The 2000-mutant soak in `soak.rs`
//! covers tamper-resistance; these seeds pin the corpus itself.

use proof_verify::{verify_proof, Validity, VerifyCtx};

fn seeds_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/proof_verify")
}

fn check_invariants(data: &[u8], tag: &str) {
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
                "{tag}: invalid verdict must carry at least one error code"
            );
        }
        let again = verify_proof(data, &ctx).expect("deterministic re-run must succeed");
        assert_eq!(
            again.cryptographic_validity, report.cryptographic_validity,
            "{tag}: verdict must be deterministic"
        );
        assert_eq!(
            again.failure_codes(),
            report.failure_codes(),
            "{tag}: failure codes must be deterministic"
        );
    }
    // Err(...) is fine: rejection is the expected outcome for most inputs.
}

#[test]
fn seed_corpus_holds_pipeline_invariants() {
    let dir = seeds_dir();
    let mut count = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("missing seed corpus {}: {e}", dir.display()))
        .collect::<Result<_, _>>()
        .unwrap();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let bytes = std::fs::read(entry.path()).unwrap();
        let tag = entry.file_name().to_string_lossy().into_owned();
        check_invariants(&bytes, &tag);
        count += 1;
    }
    assert!(count > 0, "seed corpus is empty: {}", dir.display());
}
