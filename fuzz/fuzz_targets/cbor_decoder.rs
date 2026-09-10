//! Fuzz target: the CBOR decoder — the outermost parser and first thing every
//! artifact hits. Invariant: `decode_strict` either rejects (`Err`) or returns
//! a value whose canonical re-encoding is byte-identical to the input. Any
//! other outcome is a canonicalization bug (the highest interop risk in the
//! threat model).

#![no_main]

use libfuzzer_sys::fuzz_target;
use proof_core::Limits;
use proof_format::cbor::{decode_strict, encode_canonical};

fuzz_target!(|data: &[u8]| { // PE-FMT-007
    let limits = Limits::default();
    if let Ok(value) = decode_strict(data, &limits) {
        let re = encode_canonical(&value);
        assert_eq!(
            re, data,
            "decode_strict accepted bytes that do not re-encode identically"
        );
        // Decoding our own canonical output must also succeed and match.
        let again = decode_strict(&re, &limits).expect("canonical re-encode must re-decode");
        assert_eq!(encode_canonical(&again), re);
    }
    // Err(...) is fine: rejection is the expected outcome for most inputs.
});
