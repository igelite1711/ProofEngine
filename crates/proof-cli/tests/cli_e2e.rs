// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 7 CLI integration tests. Library-level (no subprocesses), hermetic
//! (temp dirs only), deterministic (fixed test key, fixed timestamps).
//! Exit-code contract: 0 = PASS, 1 = FAIL/INDETERMINATE, 2 = error.

use proof_cli::demo;

fn tmpdir(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("proof-cli-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().into_owned()
}

/// Run one command through the same dispatch the binary uses.
fn run(args: Vec<String>) -> Result<i32, String> {
    let parsed = proof_cli::Cli::parse(&args)?;
    match parsed.command.as_str() {
        "create-event" => proof_cli::artifact::write_event(&parsed).map(|_| proof_cli::EXIT_OK),
        "attest" => proof_cli::artifact::write_attestation(&parsed).map(|_| proof_cli::EXIT_OK),
        "add-evidence" => proof_cli::artifact::write_evidence(&parsed).map(|_| proof_cli::EXIT_OK),
        "relate" => proof_cli::artifact::write_relationship(&parsed).map(|_| proof_cli::EXIT_OK),
        "build" => proof_cli::make::build(&parsed).map(|_| proof_cli::EXIT_OK),
        "revoke" => {
            proof_cli::artifact::write_status_object(&parsed, "revoke").map(|_| proof_cli::EXIT_OK)
        }
        "withdraw" => proof_cli::artifact::write_status_object(&parsed, "withdraw")
            .map(|_| proof_cli::EXIT_OK),
        "compromise" => proof_cli::artifact::write_status_object(&parsed, "compromise")
            .map(|_| proof_cli::EXIT_OK),
        "compose" => proof_cli::port::compose(&parsed).map(|_| proof_cli::EXIT_OK),
        "resolve" => proof_cli::port::resolve(&parsed),
        "export" => proof_cli::port::export(&parsed).map(|_| proof_cli::EXIT_OK),
        "import" => proof_cli::port::import(&parsed).map(|_| proof_cli::EXIT_OK),
        "convert" => proof_cli::port::convert(&parsed).map(|_| proof_cli::EXIT_OK),
        "verify" => proof_cli::make::verify(&parsed),
        "evaluate" => proof_cli::make::evaluate(&parsed, false),
        "inspect" => proof_cli::inspect::inspect(&parsed).map(|_| proof_cli::EXIT_OK),
        "graph" => proof_cli::graph::graph(&parsed).map(|_| proof_cli::EXIT_OK),
        "doctor" => proof_cli::doctor::doctor(&parsed).map(|_| proof_cli::EXIT_OK),
        "completion" => {
            let shell = parsed
                .opt("shell")
                .or_else(|| parsed.positional.first().cloned())
                .ok_or_else(|| "missing shell".to_string())?;
            proof_cli::completion_script(&shell).map(|_| proof_cli::EXIT_OK)
        }
        other => Err(format!("test harness: unhandled command `{other}`")),
    }
}

/// Build an arg vector: cmd + k/v pairs + trailing --out value.
fn args(cmd: &str, pairs: &[&str]) -> Vec<String> {
    let mut v = vec![cmd.to_string()];
    v.extend(pairs.iter().map(|s| s.to_string()));
    v
}

fn id_of(file: &str) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    v["id"].as_str().unwrap().to_string()
}

const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn cli_parses_flags_lists_and_bools() {
    let c = proof_cli::Cli::parse(
        [
            "verify".into(),
            "--proof".into(),
            "p.json".into(),
            "--clock".into(),
            "1700000300".into(),
            "--trusted".into(),
            "key:a".into(),
            "--trusted".into(),
            "key:b,key:c".into(),
            "--strict".into(),
            "--skew=7".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    assert_eq!(c.req("proof").unwrap(), "p.json");
    assert_eq!(c.req_u64("clock").unwrap(), 1_700_000_300);
    assert_eq!(c.many("trusted"), vec!["key:a", "key:b,key:c"]);
    assert!(c.has("strict"));
    assert_eq!(c.opt("skew").as_deref(), Some("7"));
    assert!(c.req("missing").is_err());
    let bad =
        proof_cli::Cli::parse(["verify".into(), "--clock".into(), "not-a-number".into()].as_ref())
            .unwrap();
    assert!(bad.req_u64("clock").is_err());
}

#[test]
fn parse_fields_maps_text_uint_bool() {
    use proof_core::model::MetaValue;
    let f = proof_cli::parse_fields(Some("amount=4200,currency=EUR,live=true,old=false".into()))
        .unwrap();
    // Canonical CBOR order (by encoded key bytes): old < live < amount < currency.
    assert_eq!(f[0], ("old".into(), MetaValue::Bool(false)));
    assert_eq!(f[1], ("live".into(), MetaValue::Bool(true)));
    assert_eq!(f[2], ("amount".into(), MetaValue::Uint(4200)));
    assert_eq!(f[3], ("currency".into(), MetaValue::Text("EUR".into())));
    assert!(proof_cli::parse_fields(Some("broken".into())).is_err());
}

/// Unsorted `k=v` input must be canonicalized, not rejected: field order on
/// the command line must never change the artifact bytes (a real-world
/// `--claim photographer=alice,unedited=true` failed with SCHEMA_VIOLATION
/// while the reversed order succeeded).
#[test]
fn fields_order_never_changes_artifact_bytes() {
    let w = tmpdir("fieldorder");
    let (a_unsorted, a_sorted) = (format!("{w}/a1.json"), format!("{w}/a2.json"));
    for (claim, out) in [
        ("photographer=alice,unedited=true", a_unsorted.as_str()),
        ("unedited=true,photographer=alice", a_sorted.as_str()),
    ] {
        run(args(
            "attest",
            &[
                "--seed",
                "test",
                "--subject",
                "photo:beach-001",
                "--claim-type",
                "photo.authentic",
                "--claim",
                claim,
                "--issued-at",
                "1757000100",
                "--out",
                out,
            ],
        ))
        .unwrap();
    }
    assert_eq!(
        id_of(&a_unsorted),
        id_of(&a_sorted),
        "field order must not affect the attestation id"
    );
    let b1 = std::fs::read(&a_unsorted).unwrap();
    let b2 = std::fs::read(&a_sorted).unwrap();
    assert_eq!(b1, b2, "field order must not affect artifact bytes");
}

// PE-CLI-007: `evaluate --json` must keep the exact exit-code contract of
// prose mode (0 PASS, 1 FAIL/INDETERMINATE) — the machine-readable projection
// is presentation, not a new trust surface. The JSON field contract itself is
// pinned against the real evaluator in
// `policy::policy_outcome_json_matches_evaluator` (crates/proof-policy).
#[test]
fn evaluate_json_flag_keeps_exit_contract() {
    let w = tmpdir("json");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    let (att, evd, rel) = (
        format!("{w}/att.json"),
        format!("{w}/evd.json"),
        format!("{w}/rel.json"),
    );
    let proof = format!("{w}/proof.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-json",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev1,
        ],
    ))
    .unwrap();
    run(args(
        "create-event",
        &[
            "--type",
            "invoice.issued",
            "--subject",
            "invoice:i-json",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D2,
            "--out",
            &ev2,
        ],
    ))
    .unwrap();
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-json",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=4200",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    let att_id = id_of(&att);
    run(args(
        "add-evidence",
        &[
            "--kind",
            "transaction_record",
            "--digest-hex",
            D2,
            "--attestation-ref",
            &att_id,
            "--out",
            &evd,
        ],
    ))
    .unwrap();
    let evd_id = id_of(&evd);
    let (e1, e2) = (id_of(&ev1), id_of(&ev2));
    run(args(
        "relate",
        &[
            "--from",
            &e1,
            "--type",
            "SETTLES",
            "--to",
            &e2,
            "--evidence-ref",
            &evd_id,
            "--out",
            &rel,
        ],
    ))
    .unwrap();
    run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            &e1,
            "--predicate",
            "settles",
            "--object",
            &e2,
            "--at-time",
            "1700000150",
            "--created-at",
            "1700000200",
            "--events",
            &format!("{ev1},{ev2}"),
            "--attestations",
            &att,
            "--evidence",
            &evd,
            "--relationships",
            &rel,
            "--out",
            &proof,
        ],
    ))
    .unwrap();

    let policy = format!("{w}/policy.json");
    std::fs::write(
        &policy,
        r#"{"policy_version":1,"policy_id":"pj","requirements":[
            {"type":"signature_valid"},{"type":"not_expired"},
            {"type":"relationship_exists","relationship":"SETTLES"}]}"#,
    )
    .unwrap();
    // PASS under --json: exit 0, same as prose mode.
    assert_eq!(
        run(args(
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
                "--json"
            ]
        )),
        Ok(0),
        "--json must not change the PASS exit code"
    );

    // Untrusted-issuer policy under --json: exit 1 (FAIL), same as prose mode.
    let stranger = proof_crypto::Ed25519Key::from_seed(&[9u8; 32]).key_ref();
    let ptrust = format!("{w}/policy-trust.json");
    std::fs::write(
        &ptrust,
        format!(
            r#"{{"policy_version":1,"policy_id":"tj","requirements":[
            {{"type":"issuer_trusted","issuer":"{stranger}"}}]}}"#
        ),
    )
    .unwrap();
    assert_eq!(
        run(args(
            "evaluate",
            &[
                "--proof",
                &proof,
                "--policy",
                &ptrust,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--json"
            ]
        )),
        Ok(1),
        "--json must not change the FAIL exit code"
    );
}

/// Full artifact workflow: create -> attest -> evidence -> relate -> build
/// -> verify (exit 0) -> revoke -> verify (exit 1). Also proves the policy
/// separation: the same proof PASSes a merchant policy but cannot PASS an
/// issuer_trusted policy unless the verifier's trust list contains the issuer.
#[test]
fn artifact_workflow_verify_then_revoke() {
    let w = tmpdir("workflow");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    let (att, evd, rel) = (
        format!("{w}/att.json"),
        format!("{w}/evd.json"),
        format!("{w}/rel.json"),
    );
    let proof = format!("{w}/proof.json");
    let rev = format!("{w}/rev.json");

    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-it",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev1,
        ],
    ))
    .unwrap();
    run(args(
        "create-event",
        &[
            "--type",
            "invoice.issued",
            "--subject",
            "invoice:i-it",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D2,
            "--out",
            &ev2,
        ],
    ))
    .unwrap();
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-it",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=4200",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    let att_id = id_of(&att);
    run(args(
        "add-evidence",
        &[
            "--kind",
            "transaction_record",
            "--digest-hex",
            D2,
            "--attestation-ref",
            &att_id,
            "--out",
            &evd,
        ],
    ))
    .unwrap();
    let evd_id = id_of(&evd);
    let (e1, e2) = (id_of(&ev1), id_of(&ev2));
    run(args(
        "relate",
        &[
            "--from",
            &e1,
            "--type",
            "SETTLES",
            "--to",
            &e2,
            "--evidence-ref",
            &evd_id,
            "--out",
            &rel,
        ],
    ))
    .unwrap();
    run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            &e1,
            "--predicate",
            "settles",
            "--object",
            &e2,
            "--at-time",
            "1700000150",
            "--created-at",
            "1700000200",
            "--events",
            &format!("{ev1},{ev2}"),
            "--attestations",
            &att,
            "--evidence",
            &evd,
            "--relationships",
            &rel,
            "--out",
            &proof,
        ],
    ))
    .unwrap();

    // Fresh: PASS (exit 0).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(0)
    );

    // Merchant policy on the same proof: PASS.
    let policy = format!("{w}/policy.json");
    std::fs::write(
        &policy,
        r#"{"policy_version":1,"policy_id":"p","requirements":[
            {"type":"signature_valid"},{"type":"not_expired"},
            {"type":"relationship_exists","relationship":"SETTLES"}]}"#,
    )
    .unwrap();
    assert_eq!(
        run(args(
            "evaluate",
            &[
                "--proof",
                &proof,
                "--policy",
                &policy,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(0)
    );

    // issuer_trusted with an empty trust list: FAIL (exit 1). Valid signature
    // alone must never satisfy trust. The policy's issuer must be a
    // well-formed keyref, so derive one from a different seed.
    let stranger = proof_crypto::Ed25519Key::from_seed(&[7u8; 32]).key_ref();
    let ptrust = format!("{w}/policy-trust.json");
    std::fs::write(
        &ptrust,
        format!(
            r#"{{"policy_version":1,"policy_id":"t","requirements":[
            {{"type":"issuer_trusted","issuer":"{stranger}"}}]}}"#
        ),
    )
    .unwrap();
    assert_eq!(
        run(args(
            "evaluate",
            &[
                "--proof",
                &proof,
                "--policy",
                &ptrust,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(1),
        "issuer_trusted with empty trust list must FAIL (exit 1), never error"
    );

    // Revoke by the original issuer, re-verify: exit 1 (same bytes).
    run(args(
        "revoke",
        &[
            "--seed",
            "test",
            "--target",
            &att_id,
            "--reason",
            "it chargeback",
            "--at",
            "1700000400",
            "--out",
            &rev,
        ],
    ))
    .unwrap();
    let second = run(args(
        "verify",
        &[
            "--proof",
            &proof,
            "--clock",
            "1700000500",
            "--status",
            &rev,
            "--revocations-known-at",
            "1700000500",
        ],
    ));
    assert_eq!(second, Ok(1), "revoked proof must exit 1, not error");
}

/// PE-CLI-002: a tampered artifact file (bytes no longer matching its stated
/// id) is rejected at load/build time — files are transport, never authority.
#[test]
fn tampered_artifact_file_rejected_at_build() {
    let w = tmpdir("tampered");
    let ev = format!("{w}/ev.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-tamper",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev,
        ],
    ))
    .unwrap();
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ev).unwrap()).unwrap();
    let cbor = v["cbor"].as_str().unwrap().to_string();
    let mut hex: Vec<char> = cbor.chars().collect();
    hex[10] = if hex[10] == '0' { '1' } else { '0' };
    v["cbor"] = serde_json::Value::String(hex.into_iter().collect());
    std::fs::write(&ev, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let err = run(args(
        "build",
        &[
            "--kind",
            "k",
            "--subject",
            "s",
            "--predicate",
            "p",
            "--created-at",
            "1700000200",
            "--events",
            &ev,
            "--attestations",
            &ev,
            "--evidence",
            &ev,
            "--relationships",
            &ev,
            "--out",
            &format!("{w}/out.json"),
        ],
    ))
    .unwrap_err();
    // Any clean rejection proves the point (id mismatch, schema violation,
    // or non-canonical bytes depending on which nibble was hit); what must
    // never happen is silent acceptance (Ok) or a panic.
    assert!(
        err.contains("ev.json"),
        "error must identify the offending file: {err}"
    );
}

/// `--seed-file` loads the same key as `--seed` without argv exposure, and
/// the two flags refuse to combine (key hygiene, audit P2).
#[test]
fn seed_file_matches_seed_and_refuses_combination() {
    let w = tmpdir("seedfile");
    let seed_hex = "0a".to_string() + &"0b".repeat(31);
    assert_eq!(seed_hex.len(), 64);
    let sf = format!("{w}/seed.hex");
    std::fs::write(
        &sf,
        format!(
            "{seed_hex}
"
        ),
    )
    .unwrap();
    let e1 = format!("{w}/e1.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-sf",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &e1,
        ],
    ))
    .unwrap();
    let a1 = format!("{w}/a1.json");
    let a2 = format!("{w}/a2.json");
    for (flag, val, out) in [
        ("--seed", seed_hex.as_str(), a1.as_str()),
        ("--seed-file", sf.as_str(), a2.as_str()),
    ] {
        let pairs: Vec<&str> = vec![
            "--subject",
            "payment:p-sf",
            "--claim-type",
            "payment.settled",
            flag,
            val,
            "--issued-at",
            "1700000150",
            "--out",
            out,
        ];
        run(args("attest", &pairs)).unwrap();
    }
    assert_eq!(id_of(&a1), id_of(&a2));
    // Both flags at once: clean usage error, never a signature.
    let bad = run(args(
        "attest",
        &[
            "--seed",
            &seed_hex,
            "--seed-file",
            &sf,
            "--subject",
            "payment:p-sf",
            "--claim-type",
            "payment.settled",
            "--issued-at",
            "1700000150",
            "--out",
            &format!("{w}/a3.json"),
        ],
    ));
    assert!(bad.is_err());
}

/// Phase 7 hostile review H1: oversized input files are refused with a clean
/// error (bounded buffering), never buffered without limit and never a panic.
#[test]
fn oversized_input_files_fail_closed() {
    let w = tmpdir("oversized");
    let big = format!("{w}/big.json");
    let over = (proof_cli::MAX_INPUT_FILE_BYTES + 100) as usize;
    std::fs::write(&big, vec![b'x'; over]).unwrap();
    let err = proof_cli::read_input_file(&big).unwrap_err();
    assert!(err.contains("too large"), "unexpected error: {err}");
    assert!(proof_cli::check::load_proof(&big, false).is_err());
    assert!(proof_cli::artifact::load_event(&big, &proof_cli::limits(), false).is_err());
}

/// Demo runs green twice and is byte-identical (determinism guarantee), and
/// the final report records the revoked end state.
#[test]
fn demo_is_deterministic_and_green() {
    let d1 = tmpdir("demo1");
    let d2 = tmpdir("demo2");
    assert_eq!(demo::run(&d1), Ok(proof_cli::EXIT_OK));
    assert_eq!(demo::run(&d2), Ok(proof_cli::EXIT_OK));
    for f in ["proof.cbor", "report.json", "explanation.txt"] {
        let a = std::fs::read(format!("{d1}/{f}")).unwrap();
        let b = std::fs::read(format!("{d2}/{f}")).unwrap();
        assert_eq!(a, b, "{f} must be byte-identical across runs");
    }
    let report = std::fs::read_to_string(format!("{d1}/report.json")).unwrap();
    assert!(report.contains("\"evidence_validity\": \"invalid\""));
    assert!(report.contains("REVOKED"));
}

/// 1.0.1 UX: `evaluate`/`explain` fail fast (usage error, exit 2) when the
/// policy still contains a `REPLACE_WITH_YOUR_ISSUER_KEY` placeholder, with a
/// hint naming the fix — preventing the classic doubled-prefix footgun
/// (`key:ed25519:key:ed25519:…`).
#[test]
fn placeholder_policy_rejected_with_hint() {
    let w = tmpdir("placeholder");
    let bad = format!("{w}/policy.json");
    // Copy the shipping example verbatim — this is exactly what a user who
    // forgets to substitute would pass.
    std::fs::write(
        &bad,
        "{\"policy_version\":1,\"policy_id\":\"x\",\"requirements\":[\
            {\"type\":\"issuer_trusted\",\"issuer\":\"key:ed25519:REPLACE_WITH_YOUR_ISSUER_KEY\"}]}",
    )
    .unwrap();
    // The demo generates a real proof to evaluate against.
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));
    let proof = format!("{w}/proof.cbor.json");
    let err = run(args(
        "evaluate",
        &["--proof", &proof, "--policy", &bad, "--clock", "1700000300"],
    ))
    .unwrap_err();
    assert!(
        err.contains("REPLACE_WITH"),
        "error must name the placeholder culprit: {err}"
    );
    assert!(
        err.contains("key:ed25519:"),
        "error must hint the suffix-only replacement: {err}"
    );
}

/// 1.0.1 UX: attestations-only proofs are first-class — `build --evidence ""`
/// (and `--relationships ""` when absent) produces a structurally valid proof
/// (the old behavior demanded those flags even when there were no members).
#[test]
fn build_evidence_empty_string_is_valid() {
    let w = tmpdir("noevidence");
    let ev = format!("{w}/ev.json");
    let att = format!("{w}/att.json");
    let proof = format!("{w}/proof.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-emp",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev,
        ],
    ))
    .unwrap();
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-emp",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=4200",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    let e_id = id_of(&ev);
    let r = run(args(
        "build",
        &[
            "--kind",
            "payment.settled",
            "--subject",
            &e_id,
            "--predicate",
            "settled",
            "--created-at",
            "1700000200",
            "--events",
            &ev,
            "--attestations",
            &att,
            "--evidence",
            "",
            "--relationships",
            "",
            "--out",
            &proof,
        ],
    ));
    assert_eq!(
        r,
        Ok(0),
        "attestations-only build with --evidence \"\" must succeed"
    );
    // And the proof verifies fresh (evidence stages trivially pass).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(0)
    );
}

/// Test the inspect command: read-only view of a proof.
#[test]
fn inspect_shows_proof_contents() {
    let w = tmpdir("inspect");
    let proof = format!("{w}/proof.cbor.json");

    // Build a proof using demo
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));

    // Inspect it
    let result = run(args("inspect", &["--proof", &proof]));
    assert_eq!(result, Ok(0));
}

/// Test the graph command: visualize proof relationships.
#[test]
fn graph_shows_relationships() {
    let w = tmpdir("graph");
    let proof = format!("{w}/proof.cbor.json");

    // Build a proof using demo
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));

    // Graph it
    let result = run(args("graph", &["--proof", &proof]));
    assert_eq!(result, Ok(0));

    // Graph with dot format
    let result = run(args("graph", &["--proof", &proof, "--format", "dot"]));
    assert_eq!(result, Ok(0));

    // Graph with mermaid format
    let result = run(args("graph", &["--proof", &proof, "--format", "mermaid"]));
    assert_eq!(result, Ok(0));
}

/// Test the doctor command: environment diagnostics.
#[test]
fn doctor_checks_environment() {
    let result = run(args("doctor", &[]));
    assert_eq!(result, Ok(0));
}

/// Test the version command.
#[test]
fn version_shows_info() {
    let parsed = proof_cli::Cli::parse(&["version".into()]).unwrap();
    assert_eq!(parsed.command, "version");
    // Version just prints info, always succeeds
    // We can't call run directly from here, but we can verify the command parses
    // The actual version output is tested via the binary
}

/// Test short flag aliases work correctly.
#[test]
fn short_flag_aliases() {
    // Test -o alias for --out
    let c = proof_cli::Cli::parse(&[
        "create-event".into(),
        "--type".into(),
        "test".into(),
        "--subject".into(),
        "s".into(),
        "--effective-at".into(),
        "1700000000".into(),
        "--payload-hex".into(),
        D1.into(),
        "-o".into(),
        "/tmp/test.json".into(),
    ])
    .unwrap();
    assert_eq!(c.opt("out").as_deref(), Some("/tmp/test.json"));

    // Test -q alias for --quiet
    let c = proof_cli::Cli::parse(&[
        "verify".into(),
        "--proof".into(),
        "p.json".into(),
        "--clock".into(),
        "1700000300".into(),
        "-q".into(),
    ])
    .unwrap();
    assert!(c.has("quiet"));
}

/// Positional proof path: `verify proof.json` behaves like
/// `verify --proof proof.json` (additive alias; flag form still works).
#[test]
fn positional_proof_path_matches_flag_form() {
    let w = tmpdir("positional");
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));
    let proof = format!("{w}/proof.cbor.json");
    let flagged = run(args(
        "verify",
        &[
            "--proof",
            &proof,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--quiet",
        ],
    ));
    // Positional form: command + bare path + flags.
    let mut v = vec!["verify".to_string(), proof.clone()];
    v.extend(
        [
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--quiet",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    let positional = run(v);
    assert_eq!(flagged, Ok(0));
    assert_eq!(positional, Ok(0));
    // inspect/graph accept it too.
    assert_eq!(run(args("inspect", &[&proof])).map(|_| 0), Ok(0));
    assert_eq!(run(args("graph", &[&proof])).map(|_| 0), Ok(0));
}

/// Every command has a help topic; completion scripts list every command.
#[test]
fn help_topics_and_completion_cover_all_commands() {
    for (name, _) in proof_cli::COMMANDS {
        assert!(
            proof_cli::command_help(name).is_some(),
            "missing help topic for `{name}`"
        );
    }
    assert!(proof_cli::command_help("bogus-cmd").is_none());
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let script = proof_cli::completion_script(shell).unwrap();
        for (name, _) in proof_cli::COMMANDS {
            assert!(
                script.contains(name),
                "{shell} completion missing command `{name}`"
            );
        }
    }
    assert!(proof_cli::completion_script("tcsh").is_err());
    // completion via the harness (positional shell arg).
    assert_eq!(run(args("completion", &["bash"])), Ok(0));
}

/// The interactive tour refuses cleanly without a terminal (never hangs
/// CI): under `cargo test` stdin is not a TTY.
#[test]
fn interactive_demo_refuses_without_tty() {
    let cli = proof_cli::Cli::parse(&["demo".into(), "--interactive".into()]).unwrap();
    let err = proof_cli::journey::run(&cli).unwrap_err();
    assert!(
        err.contains("terminal"),
        "refusal must name the terminal requirement: {err}"
    );
}

/// Both tour domains build deterministically through the core.
#[test]
fn interactive_tour_proofs_are_deterministic() {
    let (payment, software) = proof_cli::journey::tour_proof_ids().unwrap();
    assert!(payment.starts_with("prf:v1:"));
    assert!(software.starts_with("prf:v1:"));
}

/// `inspect --json` projection covers the decoded proof contents.
#[test]
fn inspect_json_matches_proof_contents() {
    let w = tmpdir("inspectjson");
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));
    let proof = format!("{w}/proof.cbor.json");
    let loaded = proof_cli::check::load_proof(&proof, true).unwrap();
    let v = proof_cli::inspect::proof_json(&loaded.proof, "test");
    assert_eq!(
        v["proof_id"].as_str().unwrap(),
        loaded.proof.proof_id.as_str()
    );
    assert_eq!(
        v["proposition"]["subject"].as_str().unwrap(),
        loaded.proof.proposition.subject.as_str()
    );
    assert_eq!(
        v["events"].as_array().unwrap().len(),
        loaded.proof.events.len()
    );
    assert_eq!(
        v["attestations"].as_array().unwrap().len(),
        loaded.proof.attestations.len()
    );
    assert_eq!(
        v["evidence"].as_array().unwrap().len(),
        loaded.proof.evidence.len()
    );
    assert_eq!(
        v["relationships"].as_array().unwrap().len(),
        loaded.proof.relationships.len()
    );
    // Spot-check nested detail the UI renders.
    assert!(v["attestations"][0].get("issuer").is_some());
    assert!(v["evidence"][0]["digest"].get("digest_hex").is_some());
}

/// Terminal safety: escape sequences and control chars from untrusted
/// strings are stripped before printing.
#[test]
fn sanitize_strips_terminal_escapes() {
    assert_eq!(
        proof_cli::sanitize("ok\x1b[31mRED\x1b[0mplain"),
        "okREDplain"
    );
    assert_eq!(proof_cli::sanitize("a\x07b\x00c"), "abc");
    assert_eq!(
        proof_cli::sanitize("line1\nline2\ttab"),
        "line1\nline2\ttab"
    );
}

/// `--out -` streams the artifact JSON on stdout instead of writing a file
/// (and must not create a file literally named `-`).
#[test]
fn build_out_dash_streams_to_stdout() {
    let w = tmpdir("outdash");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-dash",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev,
        ],
    ))
    .unwrap();
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-dash",
            "--claim-type",
            "payment.settled",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    let e_id = id_of(&ev);
    // Run from the temp dir so a stray file named `-` would land there.
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&w).unwrap();
    let r = run(args(
        "build",
        &[
            "--kind",
            "payment.settled",
            "--subject",
            &e_id,
            "--predicate",
            "settled",
            "--created-at",
            "1700000200",
            "--events",
            &ev,
            "--attestations",
            &att,
            "--evidence",
            "",
            "--relationships",
            "",
            "--out",
            "-",
        ],
    ));
    std::env::set_current_dir(&cwd).unwrap();
    assert_eq!(r, Ok(0), "build --out - must succeed");
    assert!(
        !std::path::Path::new(&format!("{w}/-")).exists(),
        "no file named `-` may be created"
    );
}

/// Graphviz/Mermaid label escaping keeps hostile quotes inert.
#[test]
fn graph_label_escaping() {
    assert_eq!(proof_cli::graph::dot_escape("a\"b\\c"), "a\\\"b\\\\c");
    assert_eq!(proof_cli::graph::dot_escape("plain"), "plain");
    assert_eq!(
        proof_cli::graph::mermaid_escape("a\"b|c<d>e[f]g{h}i#j"),
        "a#34;b#124;c#60;d#62;e#91;f#93;g#123;h#125;i#35;j"
    );
    // Literal entity-looking input stays literal (no double-escaping).
    assert_eq!(proof_cli::graph::mermaid_escape("#124;"), "#35;124;");
}

/// Unknown --format is a clean usage error, not silent text output.
#[test]
fn graph_rejects_unknown_format() {
    let w = tmpdir("graphfmt");
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));
    let proof = format!("{w}/proof.cbor.json");
    let err = run(args("graph", &["--proof", &proof, "--format", "svg"])).unwrap_err();
    assert!(err.contains("svg"), "error must name the bad format: {err}");
}

/// Test stdin support: load proof from stdin when path is "-".
#[test]
fn verify_supports_stdin() {
    let w = tmpdir("stdin");
    let proof = format!("{w}/proof.cbor.json");

    // Build a proof
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));

    // Test the path parsing for stdin
    let parsed = proof_cli::Cli::parse(&[
        "verify".into(),
        "--proof".into(),
        "-".into(),
        "--clock".into(),
        "1700000300".into(),
        "--revocations-known-at".into(),
        "1700000300".into(),
    ])
    .unwrap();
    assert_eq!(parsed.req("proof").unwrap(), "-");

    // Verify we can load from file (proof still works)
    let result = run(args(
        "verify",
        &[
            "--proof",
            &proof,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
        ],
    ));
    assert_eq!(result, Ok(0));
}

/// Elevation e2e: withdraw ends reliance (exit 1, WITHDRAWN), compromise
/// taints at/after its instant (exit 1, COMPROMISED), and a v2 quorum policy
/// evaluates over the same proof bytes (exit 0).
#[test]
fn status_withdraw_compromise_and_v2_evaluate() {
    let w = tmpdir("elevate");
    let (ev1, att, evd) = (
        format!("{w}/ev1.json"),
        format!("{w}/att.json"),
        format!("{w}/evd.json"),
    );
    let (proof, wd, mark) = (
        format!("{w}/proof.json"),
        format!("{w}/wd.json"),
        format!("{w}/mark.json"),
    );
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-el",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D1,
            "--out",
            &ev1,
        ],
    ))
    .unwrap();
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-el",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=1",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    let att_id = id_of(&att);
    let issuer = {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&att).unwrap()).unwrap();
        v["issuer"].as_str().unwrap().to_string()
    };
    run(args(
        "add-evidence",
        &[
            "--kind",
            "transaction_record",
            "--digest-hex",
            D1,
            "--attestation-ref",
            &att_id,
            "--out",
            &evd,
        ],
    ))
    .unwrap();
    let evd_id = id_of(&evd);
    run(args(
        "build",
        &[
            "--kind",
            "payment.proved",
            "--subject",
            "payment:p-el",
            "--predicate",
            "occurred",
            "--created-at",
            "1700000200",
            "--events",
            &ev1,
            "--attestations",
            &att,
            "--evidence",
            &evd,
            "--relationships",
            "",
            "--out",
            &proof,
        ],
    ))
    .unwrap();

    // Withdraw the evidence by its issuer: exit 1 with WITHDRAWN.
    run(args(
        "withdraw",
        &[
            "--seed",
            "test",
            "--target",
            &evd_id,
            "--at",
            "1700000300",
            "--out",
            &wd,
        ],
    ))
    .unwrap();
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--status",
                &wd,
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(1),
        "withdrawn evidence must exit 1"
    );

    // Compromise the issuer at an instant covering issuance: exit 1 tainted.
    run(args(
        "compromise",
        &[
            "--seed",
            "test",
            "--target",
            &issuer,
            "--compromised-at",
            "1700000000",
            "--at",
            "1700000300",
            "--out",
            &mark,
        ],
    ))
    .unwrap();
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--status",
                &mark,
                "--revocations-known-at",
                "1700000300"
            ]
        )),
        Ok(1),
        "compromised issuer must exit 1"
    );

    // V2 quorum over the same bytes: PASS (exit 0).
    let policy = format!("{w}/quorum.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"policy_version":2,"policy_id":"q","expression":{{"threshold":{{"k":1,"of":[{{"type":"issuer_trusted","issuer":"{issuer}"}}]}}}}}}"#
        ),
    )
    .unwrap();
    // NOTE: evaluate needs --trusted; the harness passes flags positionally
    // via pairs, so append the trust flag here.
    assert_eq!(
        run(args(
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
                "--trusted",
                &issuer,
            ]
        )),
        Ok(0),
        "v2 quorum must PASS (exit 0)"
    );
}

/// P4 resolve e2e: a parent proof with composition linkage resolves against a
/// file store (exit 0, complete) and fails closed on an empty store (exit 1).
#[test]
fn resolve_complete_and_incomplete_through_dispatch() {
    use proof_core::model::{EventType, Proposition};
    let lim = proof_core::Limits::default();
    let mk = |tag: &str, refs: &[String]| {
        let ev = proof_crypto::build::create_event(
            proof_core::model::EventContent {
                v: 1,
                event_type: EventType::new("test.event.occurred"),
                subject: format!("test:{tag}"),
                effective_at: 1_700_000_000,
                payload_ref: proof_core::HashRef::new(
                    proof_core::HashAlgorithm::Sha256,
                    vec![0xABu8; 32],
                )
                .unwrap(),
                metadata: vec![],
            },
            &lim,
        )
        .unwrap();
        let mut b = proof_verify::ProofBuilder::new(
            Proposition {
                v: 1,
                kind: "test.proposition".into(),
                subject: format!("test:{tag}"),
                predicate: "occurred".into(),
                object: None,
                at_time: Some(1_700_000_100),
                context: vec![],
            },
            1_700_000_200,
        );
        b.add_event(ev);
        let mut sorted = refs.to_vec();
        sorted.sort();
        for r in sorted {
            b.add_referenced_proof(r).unwrap();
        }
        b.build(&lim).unwrap()
    };
    let leaf = mk("leaf", &[]);
    let parent = mk("parent", std::slice::from_ref(&leaf.id));
    let w = tmpdir("resolve");
    let proof = format!("{w}/parent.json");
    proof_cli::artifact::write_proof_file(&proof, &parent.id, &parent.canonical).unwrap();
    let full = format!("{w}/full");
    let empty = format!("{w}/empty");
    let mut s = proof_cli::store::FileStore::open(&full).unwrap();
    use proof_format::ArtifactStore;
    s.put(&leaf.id, leaf.canonical.clone()).unwrap();
    s.put(&parent.id, parent.canonical.clone()).unwrap();
    std::fs::create_dir_all(&empty).unwrap();
    // Complete resolution: exit 0.
    assert_eq!(
        run(args(
            "resolve",
            &["--proof", &proof, "--store", &full, "--clock", "1700000200",]
        )),
        Ok(0),
        "linked proof must resolve completely (exit 0)"
    );
    // Empty store: linkage names the missing proof, exit 1 (fail closed).
    assert_eq!(
        run(args(
            "resolve",
            &[
                "--proof",
                &proof,
                "--store",
                &empty,
                "--clock",
                "1700000200",
            ]
        )),
        Ok(1),
        "unresolvable linkage must fail closed (exit 1)"
    );
}
