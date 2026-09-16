// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Mutation-soak tests: the stable-runnable counterpart of the `proof_verify`
//! cargo-fuzz target (see fuzz/README.md). Takes the valid golden proof and
//! applies thousands of deterministic mutations (bit flips, byte deletions,
//! truncations, splices). Every mutant must either be rejected outright or
//! produce a report with `cryptographic_validity == Invalid` — never a false
//! PASS, never a panic.

use proof_verify::{verify_proof, Validity, VerifyCtx};
use std::path::PathBuf;

fn golden_proof() -> (Vec<u8>, VerifyCtx) {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("golden-11.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("golden-11.json")).unwrap();
    let bytes = hex::decode(v["proof_canonical_hex"].as_str().unwrap()).unwrap();
    let c = &v["verify_ctx"];
    let ctx = VerifyCtx {
        verified_at: c["verified_at"].as_u64().unwrap(),
        clock_skew_leeway: c["skew_leeway"].as_u64().unwrap(),
        revocations_known_at: c["revocations_known_at"].as_u64(),
        ..VerifyCtx::default()
    };
    (bytes, ctx)
}

/// LCG so the soak is fully deterministic across machines and runs.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// Byte ranges the proof id deliberately does NOT cover. Since the wire fix
/// (V1 CORE freeze deviation) `created_at` IS covered by `proof_id`, so there
/// are no unprotected value ranges left: every byte flip must fail closed.
/// Kept as a thin wrapper so the soak tests keep one place documenting the
/// (now empty) trust-boundary exception list.
fn unprotected_value_ranges(_bytes: &[u8]) -> Vec<(usize, usize)> {
    vec![]
}

fn assert_fails_closed(bytes: &[u8], ctx: &VerifyCtx, tag: &str) {
    if let Ok(report) = verify_proof(bytes, ctx) {
        assert_ne!(
            report.cryptographic_validity,
            Validity::Valid,
            "{tag}: mutant must never verify as cryptographically valid"
        );
        assert!(
            !report.failure_codes().is_empty(),
            "{tag}: invalid verdict must carry at least one error code"
        );
    }
}

#[test]
fn baseline_proof_is_valid() {
    let (bytes, ctx) = golden_proof();
    let r = verify_proof(&bytes, &ctx).unwrap();
    assert_eq!(r.cryptographic_validity, Validity::Valid);
}

#[test]
fn bit_flips_fail_closed() {
    let (bytes, ctx) = golden_proof();
    let mut rng = Lcg(0x5EED_1234_ABCD_0001);
    let n = bytes.len();
    for _ in 0..2000 {
        let mut m = bytes.clone();
        let pos = (rng.next() as usize) % n;
        let bit = (rng.next() % 8) as u32;
        m[pos] ^= 1 << bit;
        assert_fails_closed(&m, &ctx, &format!("bitflip@{pos}::{bit}"));
    }
}

#[test]
fn byte_deletions_fail_closed() {
    let (bytes, ctx) = golden_proof();
    let mut rng = Lcg(0x5EED_1234_ABCD_0002);
    let n = bytes.len();
    for _ in 0..1000 {
        let pos = (rng.next() as usize) % n;
        let mut m = bytes.clone();
        m.remove(pos);
        assert_fails_closed(&m, &ctx, &format!("delete@{pos}"));
    }
}

#[test]
fn truncations_fail_closed() {
    let (bytes, ctx) = golden_proof();
    let n = bytes.len();
    // Deterministic sweep: every 16th prefix length, plus tiny ones.
    for len in (0..n).step_by(16).chain(0..8) {
        assert_fails_closed(&bytes[..len], &ctx, &format!("trunc@{len}"));
    }
}

#[test]
fn byte_insertions_fail_closed() {
    let (bytes, ctx) = golden_proof();
    let mut rng = Lcg(0x5EED_1234_ABCD_0003);
    let n = bytes.len();
    for _ in 0..1000 {
        let pos = (rng.next() as usize) % n;
        let b = (rng.next() % 256) as u8;
        let mut m = Vec::with_capacity(n + 1);
        m.extend_from_slice(&bytes[..pos]);
        m.push(b);
        m.extend_from_slice(&bytes[pos..]);
        assert_fails_closed(&m, &ctx, &format!("insert@{pos}::{b:02x}"));
    }
}

#[test]
fn random_garbage_fail_closed() {
    let ctx = VerifyCtx::default();
    let mut rng = Lcg(0x5EED_1234_ABCD_0004);
    for _ in 0..500 {
        let len = (rng.next() as usize) % 2000;
        let m: Vec<u8> = (0..len).map(|_| (rng.next() % 256) as u8).collect();
        assert_fails_closed(&m, &ctx, &format!("garbage len={len}"));
    }
}

#[test]
fn codes_are_stable_across_runs() {
    // A fixed mutation outside the informational `created_at` value must
    // always produce the same code: report stability.
    let (bytes, ctx) = golden_proof();
    let free = unprotected_value_ranges(&bytes);
    let mut m = bytes.clone();
    let at = (0..m.len())
        .find(|&i| m[i] == 0x63 && !free.iter().any(|&(a, b)| i >= a && i < b))
        .expect("a 0x63 byte outside created_at");
    m[at] ^= 0x40;
    let first = verify_proof(&m, &ctx).unwrap();
    let second = verify_proof(&m, &ctx).unwrap();
    assert_eq!(
        first.failure_codes(),
        second.failure_codes(),
        "same input must produce identical codes"
    );
    assert!(
        !first.failure_codes().is_empty(),
        "mutant must fail closed with at least one code"
    );
}
