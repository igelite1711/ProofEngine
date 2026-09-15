// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rot guard for the shipped worked example (`examples/live/`).
//!
//! These artifacts are real canonical bytes with id bindings, so a wire-format
//! or binding change silently rots them: the proof then fails with
//! `ID_MISMATCH` and the example teaches the wrong thing. This test fails as
//! soon as that happens (regenerate with `bash tools/gen_examples_live.sh`).
//!
//! Library-level (no subprocesses), deterministic, read-only: it never writes
//! to the repository.

use proof_cli::Cli;

/// Repository root, from this crate's manifest dir (`crates/proof-cli`).
fn repo_root() -> String {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/<name> layout")
        .to_string_lossy()
        .into_owned()
}

fn cli(cmd: &str, pairs: &[&str]) -> Cli {
    let mut args = vec![cmd.to_string()];
    args.extend(pairs.iter().map(|s| s.to_string()));
    Cli::parse(&args).expect("parse")
}

#[test]
fn shipped_example_artifacts_load_and_keep_their_ids() {
    let root = repo_root();
    let limits = proof_core::Limits::default();
    let dir = format!("{root}/examples/live");
    // Every loader recomputes the id from the bytes and rejects a mismatch:
    // this is the rot check for the individual artifacts.
    proof_cli::artifact::load_event(&format!("{dir}/ev1.json"), &limits, true).unwrap();
    proof_cli::artifact::load_event(&format!("{dir}/inv1.json"), &limits, true).unwrap();
    proof_cli::artifact::load_attestation(&format!("{dir}/att.json"), &limits, true).unwrap();
    proof_cli::artifact::load_evidence(&format!("{dir}/evd.json"), &limits, true).unwrap();
    proof_cli::artifact::load_relationship(&format!("{dir}/rel.json"), &limits, true).unwrap();
    // Proof wrapper: the stored `id` must equal the id the bytes bind
    // (load_proof rejects a wrapper/bytes disagreement with ID_MISMATCH).
    let loaded = proof_cli::check::load_proof(&format!("{dir}/proof.json"), true).unwrap();
    assert!(loaded.proof.proof_id.starts_with("prf:v1:"));
    assert_eq!(
        loaded.proof.events.len(),
        2,
        "example proof: two events (payment + invoice)"
    );
    assert_eq!(loaded.proof.attestations.len(), 1);
    assert_eq!(loaded.proof.evidence.len(), 1);
    assert_eq!(loaded.proof.relationships.len(), 1);
    assert_eq!(loaded.proof.created_at, 1_700_000_200);
}

#[test]
fn shipped_example_verifies_and_satisfies_the_shipped_policy() {
    let root = repo_root();
    let dir = format!("{root}/examples/live");
    let proof = format!("{dir}/proof.json");
    let policy = format!("{dir}/policy.json");
    let issuer = "key:ed25519:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg";

    // Genesis/demo profile: empty feed asserted explicitly, fresh info.
    let v = cli(
        "verify",
        &[
            "--proof",
            &proof,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
            "--quiet",
        ],
    );
    assert_eq!(
        proof_cli::make::verify(&v).expect("verify runs"),
        proof_cli::EXIT_OK,
        "examples/live/proof.json must verify (regenerate with tools/gen_examples_live.sh)"
    );

    let e = cli(
        "evaluate",
        &[
            "--proof",
            &proof,
            "--policy",
            &policy,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
            "--trusted",
            issuer,
            "--quiet",
        ],
    );
    assert_eq!(
        proof_cli::make::evaluate(&e, false).expect("evaluate runs"),
        proof_cli::EXIT_OK,
        "examples/live must satisfy examples/live/policy.json"
    );
}
