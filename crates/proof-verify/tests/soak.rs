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

/// Byte ranges the proof id deliberately does NOT cover (FORMAT.md §6: the
/// proof's `created_at` value is informational). Mutating these bits changes
/// no verification decision, so a mutant there must stay Valid — this pins
/// the documented trust boundary from the other side.
fn unprotected_value_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    let label = b"created_at";
    let mut out = vec![];
    let mut i = 0;
    while let Some(p) = bytes[i..]
        .windows(label.len())
        .position(|w| w == label)
        .map(|p| p + i)
    {
        let vstart = p + label.len();
        if let Some(&head) = bytes.get(vstart) {
            let len = match head & 0x1f {
                0..=23 => 1,
                24 => 2,
                25 => 3,
                26 => 5,
                27 => 9,
                _ => 0, // forbidden construct; not an unprotected value
            };
            if len > 0 && vstart + len <= bytes.len() {
                out.push((vstart, vstart + len));
            }
        }
        i = p + label.len();
    }
    out
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
    let free = unprotected_value_ranges(&bytes);
    let mut rng = Lcg(0x5EED_1234_ABCD_0001);
    let n = bytes.len();
    for _ in 0..2000 {
        let mut m = bytes.clone();
        let pos = (rng.next() as usize) % n;
        let bit = (rng.next() % 8) as u32;
        m[pos] ^= 1 << bit;
        if free.iter().any(|&(a, b)| pos >= a && pos < b) {
            // Documented exception: `created_at` is informational. Flipping a
            // bit must keep the proof Valid — no decision depends on it.
            let r = verify_proof(&m, &ctx).expect("created_at flip stays decodable");
            assert_eq!(
                r.cryptographic_validity,
                Validity::Valid,
                "bitflip@{pos}::{bit}: informational created_at must not affect the verdict"
            );
        } else {
            assert_fails_closed(&m, &ctx, &format!("bitflip@{pos}::{bit}"));
        }
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
