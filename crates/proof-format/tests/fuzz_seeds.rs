// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stable mirror of `fuzz/fuzz_targets/cbor_decoder.rs`.
//! libFuzzer runs nightly-only (and cannot mmap under PRoot), so the checked-in
//! seed corpus (`fuzz/seeds/cbor_decoder/`) is replayed here on stable to
//! enforce the same invariant on every push: `decode_strict` either rejects
//! (`Err`) or returns a value whose canonical re-encoding is byte-identical
//! to the input (PE-FMT-007). Any other outcome is a canonicalization bug.

use proof_core::Limits;
use proof_format::cbor::{decode_strict, encode_canonical};

fn seeds_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/cbor_decoder")
}

fn check_invariants(data: &[u8], tag: &str) {
    let limits = Limits::default();
    if let Ok(value) = decode_strict(data, &limits) {
        let re = encode_canonical(&value);
        assert_eq!(
            re, data,
            "{tag}: decode_strict accepted bytes that do not re-encode identically"
        );
        let again = decode_strict(&re, &limits).expect("canonical re-encode must re-decode");
        assert_eq!(
            encode_canonical(&again),
            re,
            "{tag}: re-decode must be stable"
        );
    }
    // Err(...) is fine: rejection is the expected outcome for most inputs.
}

#[test]
fn seed_corpus_holds_decoder_invariants() {
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

#[test]
fn hostile_inputs_reject_cleanly() {
    // Never panics; every case is either Ok-with-identical-re-encode or Err.
    for case in [
        vec![],
        vec![0xff],
        vec![0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        b"\x84\x01\x02".to_vec(),             // short array, truncated
        b"\xa1\x61a\x61b\x61a\x61c".to_vec(), // duplicate map key
    ] {
        check_invariants(&case, "hostile");
    }
}
