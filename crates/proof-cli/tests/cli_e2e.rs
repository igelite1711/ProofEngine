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
        "supersede" => proof_cli::artifact::write_status_object(&parsed, "supersede")
            .map(|_| proof_cli::EXIT_OK),
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
        "batch-verify" => proof_cli::make::batch_verify(&parsed),
        "ingest" => proof_cli::ingest::ingest(&parsed),
        "init-policy" => proof_cli::make::init_policy(&parsed).map(|_| proof_cli::EXIT_OK),
        "evaluate" => proof_cli::make::evaluate(&parsed, false),
        "explain" => proof_cli::make::evaluate(&parsed, true),
        "inspect" => proof_cli::inspect::inspect(&parsed).map(|_| proof_cli::EXIT_OK),
        "id" => proof_cli::id::value(&parsed).map(|v| {
            println!("{v}");
            proof_cli::EXIT_OK
        }),
        "commit" => proof_cli::commit::value(&parsed).map(|_| proof_cli::EXIT_OK),
        "graph" => proof_cli::graph::graph(&parsed).map(|_| proof_cli::EXIT_OK),
        "doctor" => proof_cli::doctor::doctor(&parsed),
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

fn issuer_of(file: &str) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    v["issuer"].as_str().unwrap().to_string()
}

fn id_value(args_vec: Vec<String>) -> Result<String, String> {
    let parsed = proof_cli::Cli::parse(&args_vec)?;
    proof_cli::id::value(&parsed)
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
            "--strict-current".into(),
            "--skew=7".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    assert_eq!(c.req("proof").unwrap(), "p.json");
    assert_eq!(c.req_u64("clock").unwrap(), 1_700_000_300);
    assert_eq!(c.many("trusted"), vec!["key:a", "key:b,key:c"]);
    assert!(c.has("strict-current"));
    assert_eq!(c.opt("skew").as_deref(), Some("7"));
    assert!(c.req("missing").is_err());
    let bad =
        proof_cli::Cli::parse(["verify".into(), "--clock".into(), "not-a-number".into()].as_ref())
            .unwrap();
    assert!(bad.req_u64("clock").is_err());
}

#[test]
fn unknown_flags_are_rejected_fail_closed() {
    // A flag the command does not implement is a usage error (exit 2 path),
    // never silently ignored: `--policy` on verify, or a typo of a
    // safety-profile flag, must not change the profile that runs.
    let err = proof_cli::Cli::parse(
        [
            "verify".into(),
            "--proof".into(),
            "p.json".into(),
            "--policy".into(),
            "pol.json".into(),
        ]
        .as_ref(),
    )
    .unwrap_err();
    assert!(err.contains("--policy") && err.contains("verify"), "{err}");
    let err = proof_cli::Cli::parse(["verify".into(), "--producton".into()].as_ref()).unwrap_err();
    assert!(err.contains("--producton"), "{err}");
    let err = proof_cli::Cli::parse(["evaluate".into(), "--trsuted".into(), "k".into()].as_ref())
        .unwrap_err();
    assert!(err.contains("--trsuted"), "{err}");
    // Short aliases stay wired; unknown short flags are rejected too.
    let ok = proof_cli::Cli::parse(
        [
            "verify".into(),
            "-p".into(),
            "p.json".into(),
            "-q".into(),
            "-j".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    assert!(ok.quiet() && ok.has("json") && ok.opt("proof").as_deref() == Some("p.json"));
    let err = proof_cli::Cli::parse(["verify".into(), "-z".into()].as_ref()).unwrap_err();
    assert!(err.contains("-z"), "{err}");
    // Global flags remain valid everywhere (here: a creation command).
    let ok = proof_cli::Cli::parse(
        [
            "create-event".into(),
            "--quiet".into(),
            "--out".into(),
            "e.json".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    assert!(ok.quiet() && ok.opt("out").as_deref() == Some("e.json"));
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
                "--no-require-status",
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
                "--no-require-status",
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
                "1700000300",
                "--no-require-status",
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
                "1700000300",
                "--no-require-status",
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
                "1700000300",
                "--no-require-status",
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

/// Envelope consistency (fail closed): a proof wrapper whose `id` disagrees
/// with the canonical bytes it carries is rejected at load — never silently
/// verified under a different identity. Wrappers without `id` still load by
/// bytes alone; the pipeline report's `proof_id` stays authoritative.
#[test]
fn proof_wrapper_id_mismatch_rejected_at_load() {
    let w = tmpdir("wrapper-id");
    let (ev1, att) = (format!("{w}/ev1.json"), format!("{w}/att.json"));
    let proof = format!("{w}/proof.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-wrap",
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
            "payment:p-wrap",
            "--claim-type",
            "payment.settled",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            "payment:p-wrap",
            "--predicate",
            "settles",
            "--created-at",
            "1700000200",
            "--events",
            &ev1,
            "--attestations",
            &att,
            "--evidence",
            "",
            "--relationships",
            "",
            "--out",
            &proof,
        ],
    ))
    .unwrap();
    // Sanity: intact wrapper verifies.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(0)
    );
    // Swap the wrapper id; bytes unchanged. M1 contract: tamper evidence is a
    // FAIL verdict (exit 1) with a JSON IDENTIFIERS/ID_MISMATCH report naming
    // both ids — never VALID under the wrong identity, never prose-only exit 2.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    v["id"] =
        serde_json::Value::String("prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    let bad = format!("{w}/proof-bad-id.json");
    std::fs::write(&bad, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    // Direct library check: envelope mismatch helper builds the FAIL report.
    let report = proof_cli::check::envelope_mismatch_report(
        "prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "prf:v1:placeholder",
    );
    assert_eq!(
        report.cryptographic_validity,
        proof_verify::Validity::Invalid,
        "envelope mismatch must be crypto Invalid"
    );
    assert!(
        report
            .failure_codes()
            .contains(&proof_core::ErrorCode::IdMismatch),
        "envelope mismatch must carry ID_MISMATCH"
    );
    // CLI contract (M1): mismatch is a FAIL verdict Ok(1) with JSON, never
    // VALID under the wrong identity and never prose-only Err.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &bad,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(1),
        "wrapper id mismatch must be FAIL verdict Ok(1)"
    );
    // A wrapper with no `id` at all still loads by bytes (raw transport).
    let mut v2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    v2.as_object_mut().unwrap().remove("id");
    let noid = format!("{w}/proof-no-id.json");
    std::fs::write(&noid, serde_json::to_string_pretty(&v2).unwrap()).unwrap();
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &noid,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(0)
    ); // A bare cbor+id wrapper (no kind) still loads by bytes (raw transport).
    let mut v3: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    v3.as_object_mut().unwrap().remove("kind");
    let bare = format!("{w}/proof-bare.json");
    std::fs::write(&bare, serde_json::to_string_pretty(&v3).unwrap()).unwrap();
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &bare,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(0),
        "bare cbor+id wrapper (no kind) must still load"
    );
}

/// M-5 strict wrappers (CLI-layer only): unknown top-level fields in
/// proof/artifact JSON wrappers are rejected fail-closed (exit 2, names
/// the field) -- never silently verified under extra keys.
#[test]
fn wrapper_unknown_fields_rejected_fail_closed() {
    let w = tmpdir("wrapper-strict");
    let (ev1, att) = (format!("{w}/ev1.json"), format!("{w}/att.json"));
    let proof = format!("{w}/proof.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-strict",
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
            "payment:p-strict",
            "--claim-type",
            "payment.settled",
            "--issued-at",
            "1700000150",
            "--out",
            &att,
        ],
    ))
    .unwrap();
    run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            "payment:p-strict",
            "--predicate",
            "settles",
            "--created-at",
            "1700000200",
            "--events",
            &ev1,
            "--attestations",
            &att,
            "--evidence",
            "",
            "--relationships",
            "",
            "--out",
            &proof,
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
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(0),
        "valid wrapper must still verify"
    );
    let mut evil: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    evil["evil"] = serde_json::Value::String("injected".into());
    let evil_path = format!("{w}/proof-evil.json");
    std::fs::write(&evil_path, serde_json::to_string_pretty(&evil).unwrap()).unwrap();
    let err = run(args(
        "verify",
        &[
            "--proof",
            &evil_path,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
        ],
    ))
    .unwrap_err();
    assert!(
        err.contains("wrapper has unknown field \"evil\""),
        "unknown field must be named, got: {err}"
    );
    let mut injected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    injected["proof_id"] =
        serde_json::Value::String("prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    let injected_path = format!("{w}/proof-injected.json");
    std::fs::write(
        &injected_path,
        serde_json::to_string_pretty(&injected).unwrap(),
    )
    .unwrap();
    let err2 = run(args(
        "verify",
        &[
            "--proof",
            &injected_path,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
        ],
    ))
    .unwrap_err();
    assert!(
        err2.contains("wrapper has unknown field \"proof_id\""),
        "injected proof_id key must be rejected by name, got: {err2}"
    );
    let load_err = match proof_cli::check::load_proof(&evil_path, true) {
        Ok(_) => panic!("evil wrapper must not load"),
        Err(e) => e,
    };
    assert!(
        load_err.contains("wrapper has unknown field \"evil\""),
        "load_proof must name the unknown field, got: {load_err}"
    );
    let mut bad_ev: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ev1).unwrap()).unwrap();
    bad_ev["evil"] = serde_json::Value::String("injected".into());
    let bad_ev_path = format!("{w}/ev-evil.json");
    std::fs::write(&bad_ev_path, serde_json::to_string_pretty(&bad_ev).unwrap()).unwrap();
    let build_err = run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            "payment:p-strict",
            "--predicate",
            "settles",
            "--created-at",
            "1700000200",
            "--events",
            &bad_ev_path,
            "--attestations",
            &att,
            "--out",
            &format!("{w}/must-not-exist.json"),
        ],
    ))
    .unwrap_err();
    assert!(
        build_err.contains("wrapper has unknown field \"evil\""),
        "member artifact unknown field must be named, got: {build_err}"
    );
    assert!(
        !std::path::Path::new(&format!("{w}/must-not-exist.json")).exists(),
        "no proof may be built from a smuggled wrapper"
    );
    let mut bad_att: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&att).unwrap()).unwrap();
    bad_att["evil"] = serde_json::Value::String("injected".into());
    let bad_att_path = format!("{w}/att-evil.json");
    std::fs::write(
        &bad_att_path,
        serde_json::to_string_pretty(&bad_att).unwrap(),
    )
    .unwrap();
    let limits = proof_cli::limits();
    let att_err = match proof_cli::artifact::load_attestation(&bad_att_path, &limits, true) {
        Ok(_) => panic!("evil attestation must not load"),
        Err(e) => e,
    };
    assert!(
        att_err.contains("wrapper has unknown field \"evil\""),
        "attestation unknown field must be named, got: {att_err}"
    );
    let evil_text = std::fs::read_to_string(&evil_path).unwrap();
    let evil_value: serde_json::Value = serde_json::from_str(&evil_text).unwrap();
    let stdin_err = proof_cli::artifact::reject_unknown_wrapper_fields(
        &evil_value,
        "stdin",
        proof_cli::artifact::PROOF_WRAPPER_ALLOWED,
    )
    .unwrap_err();
    assert!(
        stdin_err.contains("wrapper has unknown field \"evil\""),
        "stdin wrapper must name the unknown field, got: {stdin_err}"
    );
    assert_eq!(
        proof_cli::artifact::PROOF_WRAPPER_ALLOWED,
        &["cbor", "id", "kind", "container_version"]
    );
    assert!(
        proof_cli::artifact::ATTESTATION_WRAPPER_ALLOWED.contains(&"sign1_b64")
            && proof_cli::artifact::ATTESTATION_WRAPPER_ALLOWED.contains(&"issuer")
    );
    assert!(
        proof_cli::artifact::STATUS_WRAPPER_ALLOWED.contains(&"claim_type")
            && proof_cli::artifact::STATUS_WRAPPER_ALLOWED.contains(&"sign1_b64")
    );
}

/// H-1 historic-VALID currency (CLI-layer only, frozen verdicts unchanged):
/// after supersede, bare verify stays exit 0 (historical VALID) with
/// currently_acceptable:false in JSON and an unambiguous HISTORICALLY_VALID
/// human label -- while --strict-current and --production exit 1 on the same
/// bytes. JSON field names stay stable.
#[test]
fn superseded_proof_bare_verify_is_historical_strict_fails() {
    let w = tmpdir("historical");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    let (att, att2, evd, rel) = (
        format!("{w}/att.json"),
        format!("{w}/att2.json"),
        format!("{w}/evd.json"),
        format!("{w}/rel.json"),
    );
    let (proof, sup, rep) = (
        format!("{w}/proof.json"),
        format!("{w}/sup.json"),
        format!("{w}/rep.json"),
    );
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:h1",
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
            "invoice:h1",
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
            "payment:h1",
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
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:h1",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=2",
            "--issued-at",
            "1700000450",
            "--out",
            &att2,
        ],
    ))
    .unwrap();
    let att_id = id_of(&att);
    let att2_id = id_of(&att2);
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
            "--attestation-ref",
            &att_id,
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
    run(args(
        "supersede",
        &[
            "--seed",
            "test",
            "--old",
            &att_id,
            "--new",
            &att2_id,
            "--at",
            "1700000450",
            "--out",
            &sup,
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
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup,
                "--out",
                &rep,
            ]
        )),
        Ok(0),
        "superseded proof bare verify must stay exit 0 (historical VALID)"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&rep).unwrap()).unwrap();
    assert_eq!(v["currently_acceptable"], serde_json::Value::Bool(false));
    assert_eq!(
        v["cryptographic_validity"],
        serde_json::Value::String("valid".into())
    );
    assert_eq!(
        v["evidence_validity"],
        serde_json::Value::String("valid".into())
    );
    let loaded = proof_cli::check::load_proof(&proof, true).unwrap();
    let ctx = proof_verify::VerifyCtx {
        verified_at: 1700000500,
        clock_skew_leeway: 300,
        revocations_known_at: Some(1700000500),
        status_objects: vec![
            proof_cli::artifact::load_status(&sup, &proof_cli::limits(), true).unwrap(),
        ],
        ..Default::default()
    };
    let report = proof_verify::verify_proof(&loaded.canonical, &ctx).unwrap();
    let label = proof_cli::check::human_verdict_label(&report);
    assert!(
        label.contains("HISTORICALLY_VALID"),
        "human label must be HISTORICALLY_VALID, got: {label}"
    );
    assert!(
        !label.starts_with("VALID"),
        "bare VALID label must not appear for not-current proofs, got: {label}"
    );
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup,
                "--strict-current",
            ]
        )),
        Ok(1),
        "--strict-current must exit 1 on superseded history"
    );
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup,
                "--production",
            ]
        )),
        Ok(1),
        "--production must exit 1 on superseded history"
    );
}

/// H-2 no-require-status footgun guard (backward compatible): the flag keeps
/// working (genesis genuinely needs it), but emits a loud WARNING naming the
/// risk and production remedy. Default stays fail-closed.
#[test]
fn no_require_status_emits_loud_warning() {
    let text = proof_cli::check::no_require_status_warning(1700000300);
    assert!(
        text.contains("WARNING: --no-require-status asserts"),
        "warning must name the flag loudly, got: {text}"
    );
    assert!(
        text.contains("NEVER use in production; supply --status feed files"),
        "warning must name the production remedy, got: {text}"
    );
    let help = proof_cli::command_help("verify").unwrap();
    assert!(
        help.contains("--no-require-status") && help.contains("NEVER use in production"),
        "help verify must carry the footgun warning"
    );
    assert!(
        help.contains("genesis"),
        "help verify must mention the genesis/demo-only intent"
    );
    assert!(
        help.contains("--revocations-known-at"),
        "help must document that --revocations-known-at is still required for PASS"
    );
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
                "1700000300",
                "--no-require-status",
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
    // Exit 0 all healthy, 1 any check fails (cwd-dependent: demo/examples
    // relative paths miss when tests run from crates/proof-cli). Either is a
    // successful run; usage errors (exit 2 / Err) are the failure mode.
    let result = run(args("doctor", &[]));
    assert!(
        matches!(result, Ok(0) | Ok(1)),
        "doctor must exit 0/1, got {result:?}"
    );
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
            "--no-require-status",
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
            "--no-require-status",
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

#[test]
fn gnu_help_and_version_aliases() {
    // `proof-cli --help` / `-h` behave like `help`; `--version` like `version`.
    // Regression: `--help` used to be consumed as an unknown command (exit 2).
    assert_eq!(
        proof_cli::Cli::parse(&["--help".into()]).unwrap().command,
        "help"
    );
    assert_eq!(
        proof_cli::Cli::parse(&["-h".into()]).unwrap().command,
        "help"
    );
    assert_eq!(
        proof_cli::Cli::parse(&["--version".into()])
            .unwrap()
            .command,
        "version"
    );
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
        "--no-require-status".into(),
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
            "--no-require-status",
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
                "--no-require-status",
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

/// batch-verify e2e: two valid proofs exit 0 with counts; a tampered member
/// exits 1 while the valid member still verifies (independence).
#[test]
fn batch_verify_all_valid_and_one_tampered_through_dispatch() {
    use proof_core::model::{EventType, Proposition};
    let lim = proof_core::Limits::default();
    let mk = |tag: &str| {
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
        b.build(&lim).unwrap()
    };
    let w = tmpdir("batch");
    let good = mk("good");
    let other = mk("other");
    let p1 = format!("{w}/p1.json");
    let p2 = format!("{w}/p2.json");
    proof_cli::artifact::write_proof_file(&p1, &good.id, &good.canonical).unwrap();
    proof_cli::artifact::write_proof_file(&p2, &other.id, &other.canonical).unwrap();
    let both = format!("{p1},{p2}");
    assert_eq!(
        run(args(
            "batch-verify",
            &["--proofs", &both, "--clock", "1700000200", "--quiet"]
        )),
        Ok(0),
        "two valid proofs must exit 0"
    );
    // Tamper a value byte inside the subject string (map structure and
    // UTF-8 intact → loads fine, fails at IDENTIFIERS with ID_MISMATCH).
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&p2).unwrap()).unwrap();
    let hexs = v["cbor"].as_str().unwrap().to_string();
    let mut raw: Vec<u8> = (0..hexs.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexs[i..i + 2], 16).unwrap())
        .collect();
    let needle = b"test:other";
    let pos = raw
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("subject must be present");
    raw[pos + 5] = b'X';
    let tampered: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    v["cbor"] = serde_json::Value::String(tampered);
    std::fs::write(&p2, serde_json::to_string(&v).unwrap()).unwrap();
    assert_eq!(
        run(args(
            "batch-verify",
            &["--proofs", &both, "--clock", "1700000200", "--quiet"]
        )),
        Ok(1),
        "tampered member must fail the batch (exit 1)"
    );
    // Missing flag and over-cap are usage/engine errors (exit 2 path).
    assert!(run(args("batch-verify", &["--clock", "1700000200"])).is_err());
    assert!(run(args(
        "batch-verify",
        &[
            "--proofs",
            &both,
            "--clock",
            "1700000200",
            "--max-batch",
            "1"
        ]
    ))
    .is_err());
}

/// ingest e2e: JSONL records become canonical event artifacts + manifest;
/// malformed lines fail closed with line numbers unless --skip-bad.
#[test]
fn ingest_jsonl_records_fail_closed_with_line_numbers() {
    let w = tmpdir("ingest");
    let rec = format!("{w}/records.jsonl");
    let ab = "ab".repeat(32);
    let cd = "cd".repeat(32);
    std::fs::write(
        &rec,
        format!(
            "{{\"type\":\"test.event.occurred\",\"subject\":\"test:a\",\"effective_at\":1700000000,\"payload_hex\":\"{ab}\",\"meta\":\"k=v\"}}\n\
             {{\"type\":\"test.event.occurred\",\"subject\":\"test:b\",\"effective_at\":1700000001,\"payload_hex\":\"{cd}\"}}\n"
        ),
    )
    .unwrap();
    let out = format!("{w}/events");
    let manifest = format!("{w}/manifest.json");
    assert_eq!(
        run(args(
            "ingest",
            &["--in", &rec, "--out-dir", &out, "--out", &manifest]
        )),
        Ok(0),
        "two valid records must ingest (exit 0)"
    );
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    assert_eq!(m["ingested"], 2);
    assert_eq!(m["ids"].as_array().unwrap().len(), 2);
    assert!(m["skipped"].as_array().unwrap().is_empty());
    // Artifacts reload as events (re-verify on load, like any file).
    for id in m["ids"].as_array().unwrap() {
        let path = format!("{out}/{}.json", id.as_str().unwrap());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["kind"], "event");
    }
    // Malformed second line aborts fail-closed with its line number.
    let bad = format!("{w}/bad.jsonl");
    std::fs::write(
        &bad,
        "{\"type\":\"t\",\"subject\":\"s\",\"effective_at\":1,\"payload_hex\":\"zz\"}\n",
    )
    .unwrap();
    let err = run(args(
        "ingest",
        &["--in", &bad, "--out-dir", &format!("{w}/e2")],
    ));
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("line 1"), "must name the line");
    // Unknown fields are rejected, never silently swallowed.
    let unk = format!("{w}/unk.jsonl");
    std::fs::write(
        &unk,
        format!(
            "{{\"type\":\"t\",\"subject\":\"s\",\"effective_at\":1,\"payload_hex\":\"{}\",\"typo\":1}}\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    assert!(run(args(
        "ingest",
        &["--in", &unk, "--out-dir", &format!("{w}/e3")]
    ))
    .is_err());
    // --skip-bad continues and lists the skip in the manifest.
    let mixed = format!("{w}/mixed.jsonl");
    std::fs::write(
        &mixed,
        format!(
            "{{\"type\":\"t\",\"subject\":\"s\",\"effective_at\":1,\"payload_hex\":\"{0}\"}}\nNOT-JSON\n",
            "ab".repeat(32)
        ),
    )
    .unwrap();
    let m2 = format!("{w}/m2.json");
    // Partial batch (--skip-bad with 1 skip) is exit 1, not 0.
    assert_eq!(
        run(args(
            "ingest",
            &[
                "--in",
                &mixed,
                "--out-dir",
                &format!("{w}/e4"),
                "--out",
                &m2,
                "--skip-bad"
            ]
        )),
        Ok(1)
    );
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&m2).unwrap()).unwrap();
    assert_eq!(m["ingested"], 1);
    assert_eq!(m["skipped"].as_array().unwrap().len(), 1);
    // --dry-run validates without writing anything.
    let dry = format!("{w}/dry");
    assert_eq!(
        run(args(
            "ingest",
            &["--in", &rec, "--out-dir", &dry, "--dry-run"]
        )),
        Ok(0)
    );
    assert!(!std::path::Path::new(&dry).exists());
}

/// Full VerifyCtx surface is reachable from the CLI (previously hardcoded
/// strict-only): --esp256, --historical, --report-all, --accepted-vocab,
/// --extra-grounded thread into verify without changing strict defaults.
#[test]
fn verifier_policy_flags_parse_and_thread() {
    // Parsing: all flags on.
    let c = proof_cli::Cli::parse(
        [
            "verify".into(),
            "--proof".into(),
            "p.json".into(),
            "--clock".into(),
            "1700000300".into(),
            "--esp256".into(),
            "--historical".into(),
            "--report-all".into(),
            "--accepted-vocab".into(),
            "acme:2,other:3".into(),
            "--extra-grounded".into(),
            "MYEDGE,OTHER".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    let vp = proof_cli::make::verifier_policy(&c).unwrap();
    assert!(vp.allowed_algs.esp256);
    assert!(vp.allowed_algs.allow_deprecated);
    assert!(vp.report_all_failures);
    assert_eq!(vp.accepted_vocabularies.len(), 2);
    assert_eq!(vp.accepted_vocabularies[0].ns, "acme");
    assert_eq!(vp.accepted_vocabularies[0].max_version, 2);
    assert_eq!(vp.extra_grounded, vec!["MYEDGE", "OTHER"]);
    // Defaults unchanged when flags absent (strict Ed25519-only, fail-fast).
    let strict = proof_cli::Cli::parse(
        [
            "verify".into(),
            "--proof".into(),
            "p.json".into(),
            "--clock".into(),
            "1".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    let vp = proof_cli::make::verifier_policy(&strict).unwrap();
    assert!(!vp.allowed_algs.esp256);
    assert!(!vp.allowed_algs.allow_deprecated);
    assert!(!vp.report_all_failures);
    assert!(vp.accepted_vocabularies.is_empty());
    assert!(vp.extra_grounded.is_empty());
    // Malformed vocab fails closed as usage error, never a silent default.
    let bad = proof_cli::Cli::parse(
        [
            "verify".into(),
            "--proof".into(),
            "p.json".into(),
            "--clock".into(),
            "1".into(),
            "--accepted-vocab".into(),
            "no-colon-here".into(),
        ]
        .as_ref(),
    )
    .unwrap();
    assert!(proof_cli::make::verifier_policy(&bad).is_err());
}

/// New flags are additive: an Ed25519 proof that verifies strict still
/// verifies with every flag on, and bad flag values are usage errors.
#[test]
fn verifier_flags_are_additive_on_real_proof() {
    let w = tmpdir("vflags");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    for (path, typ, subj, payload) in [
        (&ev1, "payment.created", "payment:p-vf", D1),
        (&ev2, "invoice.issued", "invoice:i-vf", D2),
    ] {
        run(args(
            "create-event",
            &[
                "--type",
                typ,
                "--subject",
                subj,
                "--effective-at",
                "1700000000",
                "--payload-hex",
                payload,
                "--out",
                path,
            ],
        ))
        .unwrap();
    }
    let (att, evd, rel) = (
        format!("{w}/att.json"),
        format!("{w}/evd.json"),
        format!("{w}/rel.json"),
    );
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:p-vf",
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
    // Evidence digests are id-bound references (like the existing e2e
    // proofs above, which pass D2 straight through as digest-hex).
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
    let (ev1_id, ev2_id, evd_id) = (id_of(&ev1), id_of(&ev2), id_of(&evd));
    run(args(
        "relate",
        &[
            "--from",
            &ev1_id,
            "--type",
            "SETTLES",
            "--to",
            &ev2_id,
            "--evidence-ref",
            &evd_id,
            "--attestation-ref",
            &att_id,
            "--out",
            &rel,
        ],
    ))
    .unwrap();
    let proof = format!("{w}/proof.json");
    run(args(
        "build",
        &[
            "--kind",
            "payment.settles-invoice",
            "--subject",
            &ev1_id,
            "--predicate",
            "settles",
            "--object",
            &ev2_id,
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
    let base = [
        "--proof".to_string(),
        proof.clone(),
        "--clock".to_string(),
        "1700000300".to_string(),
        "--revocations-known-at".to_string(),
        "1700000300".to_string(),
        "--no-require-status".to_string(),
    ];
    let mut strict_args = vec!["verify".to_string()];
    strict_args.extend(base.clone());
    assert_eq!(run(strict_args), Ok(0));
    // Every new flag on: same proof, same PASS (additive, never a bypass).
    let mut full = vec!["verify".to_string()];
    full.extend(base.clone());
    full.extend(
        [
            "--esp256",
            "--historical",
            "--report-all",
            "--accepted-vocab",
            "acme:2",
            "--extra-grounded",
            "MYEDGE",
            "--trusted",
            "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    assert_eq!(run(full), Ok(0));
    // Malformed vocab is a usage error (exit 2 via Err), not a silent PASS.
    let mut bad = vec!["verify".to_string()];
    bad.extend(base);
    bad.extend(
        ["--accepted-vocab", "no-colon"]
            .iter()
            .map(|s| s.to_string()),
    );
    assert!(run(bad).is_err());
}

/// Fix 8: `relate` fails fast on ungrounded trust-relevant edges (previously
/// built successfully and only failed later at `verify`).
#[test]
fn relate_rejects_ungrounded_trust_edges() {
    let w = tmpdir("ungrounded");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:u1",
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
            "invoice:u1",
            "--effective-at",
            "1700000000",
            "--payload-hex",
            D2,
            "--out",
            &ev2,
        ],
    ))
    .unwrap();
    let (e1, e2) = (id_of(&ev1), id_of(&ev2));
    // Bare SETTLES without grounding: must fail fast at relate.
    let bare = run(args(
        "relate",
        &[
            "--from",
            &e1,
            "--type",
            "SETTLES",
            "--to",
            &e2,
            "--out",
            &format!("{w}/bare.json"),
        ],
    ));
    assert!(
        bare.is_err(),
        "ungrounded SETTLES must fail fast at relate: {bare:?}"
    );
    // Explicit escape hatch for negative tests.
    run(args(
        "relate",
        &[
            "--from",
            &e1,
            "--type",
            "SETTLES",
            "--to",
            &e2,
            "--allow-ungrounded",
            "--out",
            &format!("{w}/neg.json"),
        ],
    ))
    .unwrap();
    // Non-trust linkage (REFERENCES) may stay bare.
    run(args(
        "relate",
        &[
            "--from",
            &e1,
            "--type",
            "REFERENCES",
            "--to",
            &e2,
            "--out",
            &format!("{w}/ref.json"),
        ],
    ))
    .unwrap();
}

/// Fail-closed empty feed (pre-launch core audit): bare verify on a fresh
/// demo proof with asserted freshness but zero status objects FAILS
/// (REVOCATION_UNKNOWN); explicit `--no-require-status` restores the
/// caller-asserted-absence PASS for genesis/demo flows.
#[test]
fn production_profile_enforces_currency() {
    let w = tmpdir("production");
    assert_eq!(demo::run(&w), Ok(proof_cli::EXIT_OK));
    let proof = format!("{w}/proof.cbor.json");
    // Bare verify on fresh demo proof with empty feed: FAILS closed.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--out",
                &format!("{w}/rep.json")
            ]
        )),
        Ok(1)
    );
    // Explicit caller-asserted absence restores the historical PASS.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
                "--out",
                &format!("{w}/rep.json")
            ]
        )),
        Ok(0)
    );
    let rep: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{w}/rep.json")).unwrap()).unwrap();
    assert_eq!(rep["currently_acceptable"], serde_json::Value::Bool(true));
    // --production on the same empty-feed proof: FAILS closed (feed gate).
    // Production implies --require-status; zero status objects with asserted
    // freshness is not feed-proved absence.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--production"
            ]
        )),
        Ok(1)
    );
    // --require-status on empty feed: fails closed (now the default too).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--require-status"
            ]
        )),
        Ok(1)
    );
    // Explicit opt-out restores historical behavior (but currency overlays
    // still apply: --production fails SUPERSEDED/provenance-hint proofs even
    // with the feed gate off; this fresh proof has neither, so PASS).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status"
            ]
        )),
        Ok(0)
    );
    // --production with explicit opt-out: feed gate off, still PASS here
    // (fresh proof, no currency issues).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--production",
                "--no-require-status"
            ]
        )),
        Ok(0)
    );
}

/// Evaluate/batch --production overlays currency on policy/validity:
/// VALID-but-not-current fails even when the policy itself would pass.
#[test]
fn production_overlays_currency_on_evaluate_and_batch() {
    let w = tmpdir("prod-currency");
    let (ev1, ev2) = (format!("{w}/ev1.json"), format!("{w}/ev2.json"));
    let (att, att2, evd, rel) = (
        format!("{w}/att.json"),
        format!("{w}/att2.json"),
        format!("{w}/evd.json"),
        format!("{w}/rel.json"),
    );
    let (proof, sup, policy) = (
        format!("{w}/proof.json"),
        format!("{w}/sup.json"),
        format!("{w}/policy.json"),
    );
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:pc1",
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
            "invoice:pc1",
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
            "payment:pc1",
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
    run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "payment:pc1",
            "--claim-type",
            "payment.settled",
            "--claim",
            "amount=2",
            "--issued-at",
            "1700000450",
            "--out",
            &att2,
        ],
    ))
    .unwrap();
    let att_id = id_of(&att);
    let att2_id = id_of(&att2);
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
            "--attestation-ref",
            &att_id,
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
    std::fs::write(
        &policy,
        r#"{"policy_version":1,"policy_id":"p","requirements":[{"type":"signature_valid"}]}"#,
    )
    .unwrap();
    run(args(
        "supersede",
        &[
            "--seed",
            "test",
            "--old",
            &att_id,
            "--new",
            &att2_id,
            "--at",
            "1700000450",
            "--out",
            &sup,
        ],
    ))
    .unwrap();
    let base = [
        "--proof".to_string(),
        proof.clone(),
        "--clock".to_string(),
        "1700000500".to_string(),
        "--revocations-known-at".to_string(),
        "1700000500".to_string(),
        "--status".to_string(),
        sup.clone(),
    ];
    let mut v = vec!["verify".to_string()];
    v.extend(base.clone());
    assert_eq!(run(v), Ok(0));
    let mut vp = vec!["verify".to_string()];
    vp.extend(base.clone());
    vp.push("--production".to_string());
    assert_eq!(run(vp), Ok(1));
    assert_eq!(
        run(args(
            "evaluate",
            &[
                "--proof",
                &proof,
                "--policy",
                &policy,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup
            ]
        )),
        Ok(0)
    );
    assert_eq!(
        run(args(
            "evaluate",
            &[
                "--proof",
                &proof,
                "--policy",
                &policy,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup,
                "--production"
            ]
        )),
        Ok(1)
    );
    assert_eq!(
        run(args(
            "batch-verify",
            &[
                "--proofs",
                &proof,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup,
                "--production"
            ]
        )),
        Ok(1)
    );
    assert_eq!(
        run(args(
            "batch-verify",
            &[
                "--proofs",
                &proof,
                "--clock",
                "1700000500",
                "--revocations-known-at",
                "1700000500",
                "--status",
                &sup
            ]
        )),
        Ok(0)
    );
}

/// `proof-cli id` prints artifact fields for shell plumbing (no python
/// one-liners): `id` on every artifact, `issuer` on attestations/status.
#[test]
fn id_prints_artifact_id_and_issuer() {
    let w = tmpdir("id-cmd");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-id",
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
            "payment:p-id",
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
    // Default field is the content id (== the file's id member).
    assert_eq!(
        id_value(args("id", &["--artifact", &ev])).unwrap(),
        id_of(&ev)
    );
    assert_eq!(
        id_value(args("id", &["--artifact", &att])).unwrap(),
        id_of(&att)
    );
    // Issuer comes from the attestation; events carry none.
    assert_eq!(
        id_value(args("id", &["--artifact", &att, "--field", "issuer"])).unwrap(),
        issuer_of(&att)
    );
    assert!(id_value(args("id", &["--artifact", &ev, "--field", "issuer"])).is_err());
    // Unknown fields and missing files are usage errors, not panics.
    assert!(id_value(args("id", &["--artifact", &ev, "--field", "digest"])).is_err());
    assert!(id_value(args("id", &["--artifact", &format!("{w}/nope.json")])).is_err());
    // Dispatch parity: exit 0 through the binary path.
    assert_eq!(run(args("id", &["--artifact", &ev])), Ok(0));
}

/// `explain --json` carries the same merged machine document as
/// `evaluate --json`, plus the human explanation as a string field.
/// Exit contract matches prose mode in both directions.
#[test]
fn explain_json_carries_merged_outcome_and_explanation() {
    let w = tmpdir("explain-json");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    let (proof, policy) = (format!("{w}/proof.json"), format!("{w}/policy.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-ex",
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
            "payment:p-ex",
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
    let e_id = id_of(&ev);
    // Omitted --evidence/--relationships: zero members, no hatch needed.
    run(args(
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
            "--out",
            &proof,
        ],
    ))
    .unwrap();
    let issuer = issuer_of(&att);
    run(args(
        "init-policy",
        &[
            "--issuer",
            &issuer,
            "--template",
            "minimal",
            "--out",
            &policy,
        ],
    ))
    .unwrap();
    let base = [
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
        &issuer,
    ];
    let mut prose: Vec<String> = vec!["explain".into()];
    prose.extend(base.iter().map(|s| s.to_string()));
    assert_eq!(run(prose), Ok(0));
    let mut js = vec!["explain".into(), "--json".into()];
    js.extend(base.iter().map(|s| s.to_string()));
    assert_eq!(run(js), Ok(0));
    // Failing policy keeps the exit contract in both modes. Note: the fixed
    // `--seed test` key IS from_seed([9u8; 32]), so the stranger must use a
    // different seed ([7u8; 32]) to genuinely mismatch.
    let stranger = proof_crypto::Ed25519Key::from_seed(&[7u8; 32]).key_ref();
    let bad = format!("{w}/bad.json");
    std::fs::write(
        &bad,
        format!(
            r#"{{"policy_version":1,"policy_id":"x","requirements":[{{"type":"issuer_trusted","issuer":"{stranger}"}}]}}"#
        ),
    )
    .unwrap();
    let mut prose_bad = vec!["explain".into()];
    prose_bad.extend(
        [
            "--proof",
            &proof,
            "--policy",
            &bad,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
            "--trusted",
            &issuer,
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    assert_eq!(run(prose_bad), Ok(1));
    let mut js_bad = vec!["explain".into(), "--json".into()];
    js_bad.extend(
        [
            "--proof",
            &proof,
            "--policy",
            &bad,
            "--clock",
            "1700000300",
            "--revocations-known-at",
            "1700000300",
            "--no-require-status",
            "--trusted",
            &issuer,
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    assert_eq!(run(js_bad), Ok(1));
}

/// Attest fail-fast for opt-in semantic binding (Fix 5 creation-time):
/// malformed digest, missing evidence-ref, and non-text values are creation
/// errors (exit 2), not late verify failures.
#[test]
fn attest_rejects_bad_evidence_digest_fast() {
    let w = tmpdir("attest-bind");
    // Malformed hex.
    assert!(run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "s:1",
            "--claim-type",
            "t",
            "--claim",
            "evidence_digest=xyz",
            "--issued-at",
            "1700000150",
            "--out",
            &format!("{w}/a.json"),
        ],
    ))
    .is_err());
    // Valid hex but no --evidence-ref to bind it to.
    assert!(run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "s:1",
            "--claim-type",
            "t",
            "--claim",
            "evidence_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--issued-at",
            "1700000150",
            "--out",
            &format!("{w}/b.json"),
        ],
    ))
    .is_err());
    // Non-text value cannot encode hex (numbers become Uint).
    assert!(run(args(
        "attest",
        &[
            "--seed",
            "test",
            "--subject",
            "s:1",
            "--claim-type",
            "t",
            "--claim",
            "evidence_digest=123",
            "--issued-at",
            "1700000150",
            "--out",
            &format!("{w}/c.json"),
        ],
    ))
    .is_err());
    // Well-formed binding inputs are still accepted (verify decides).
    assert_eq!(
        run(args(
            "attest",
            &[
                "--seed",
                "test",
                "--subject",
                "s:1",
                "--claim-type",
                "t",
                "--claim",
                "evidence_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--evidence-ref",
                "evd:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "--issued-at",
                "1700000150",
                "--out",
                &format!("{w}/d.json"),
            ]
        )),
        Ok(0)
    );
}

/// `minimal` template is domain-agnostic: no relationship/evidence
/// vocabulary, so sensor/legal/science proofs get a passing starter policy
/// without payment-kind editing.
#[test]
fn init_policy_minimal_has_no_domain_vocabulary() {
    let w = tmpdir("init-minimal");
    let out = format!("{w}/policy.json");
    let issuer = proof_crypto::Ed25519Key::from_seed(&[9u8; 32]).key_ref();
    assert_eq!(
        run(args(
            "init-policy",
            &["--issuer", &issuer, "--template", "minimal", "--out", &out]
        )),
        Ok(0)
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let types: Vec<&str> = v["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec![
            "signature_valid",
            "issuer_trusted",
            "not_expired",
            "not_revoked"
        ]
    );
}

/// Template names describe requirement shape, never industry: the default is
/// `standard_v1` (not `settlement_v1`) even for non-payment proofs, and the
/// pre-seal industry names survive only as aliases emitting shape-named ids.
#[test]
fn init_policy_template_names_are_shape_based() {
    let w = tmpdir("init-shape");
    let issuer = proof_crypto::Ed25519Key::from_seed(&[9u8; 32]).key_ref();
    for (template, expect_id) in [
        ("standard", "standard_v1"),
        ("settlement", "standard_v1"),
        ("strict", "strict_v1"),
        ("strict-document", "strict_v1"),
        ("fresh", "fresh_v1"),
        ("basic", "basic_v1"),
        ("minimal", "minimal_v1"),
    ] {
        let out = format!("{w}/policy-{template}.json");
        let mut a = vec![
            "init-policy".to_string(),
            "--issuer".to_string(),
            issuer.clone(),
            "--template".to_string(),
            template.to_string(),
            "--relationship".to_string(),
            "TESTS".to_string(),
            "--evidence-kind".to_string(),
            "test_kind".to_string(),
            "--out".to_string(),
            out.clone(),
        ];
        // fresh/minimal take no domain vocabulary; drop those flags for them.
        if template == "fresh" || template == "minimal" {
            a.retain(|x| {
                x != "--relationship" && x != "TESTS" && x != "--evidence-kind" && x != "test_kind"
            });
        }
        assert_eq!(run(a), Ok(0), "template {template}");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(v["policy_id"], serde_json::Value::String(expect_id.into()));
    }
}

/// `commit` computes hex(sha256("salt|value")) for confidential claims;
/// `--value` and `--value-file` agree; both flags together is a usage error.
#[test]
fn commit_computes_salted_commitment() {
    use sha2::{Digest, Sha256};
    let w = tmpdir("commit");
    let secret = format!("{w}/secret.txt");
    std::fs::write(&secret, "income:84000").unwrap();
    // printf 's3|income:84000' | sha256sum, recomputed here, never hardcoded.
    let expect = hex::encode(Sha256::digest(b"s3|income:84000"));
    let hex_of = |argv: Vec<String>| -> String {
        let parsed = proof_cli::Cli::parse(&argv).unwrap();
        proof_cli::commit::value(&parsed).unwrap()
    };
    assert_eq!(
        hex_of(args("commit", &["--salt", "s3", "--value", "income:84000"])),
        expect
    );
    assert_eq!(
        hex_of(args("commit", &["--salt", "s3", "--value-file", &secret])),
        expect
    );
    assert_ne!(
        run(args(
            "commit",
            &["--salt", "s3", "--value", "a", "--value-file", &secret]
        )),
        Ok(0)
    );
}
#[test]
fn add_evidence_digest_file_matches_digest_hex() {
    use sha2::{Digest, Sha256};
    let w = tmpdir("digest-file");
    let payload = format!("{w}/payload.bin");
    std::fs::write(&payload, b"sensor-bytes-42").unwrap();
    let hex = hex::encode(Sha256::digest(b"sensor-bytes-42"));
    let (via_file, via_hex) = (format!("{w}/f.json"), format!("{w}/h.json"));
    assert_eq!(
        run(args(
            "add-evidence",
            &[
                "--kind",
                "measurement",
                "--digest-file",
                &payload,
                "--out",
                &via_file
            ]
        )),
        Ok(0)
    );
    assert_eq!(
        run(args(
            "add-evidence",
            &[
                "--kind",
                "measurement",
                "--digest-hex",
                &hex,
                "--out",
                &via_hex
            ]
        )),
        Ok(0)
    );
    assert_eq!(id_of(&via_file), id_of(&via_hex));
    assert!(run(args("add-evidence", &["--kind", "measurement"])).is_err());
}

/// `build` without `--evidence`/`--relationships` means zero members
/// (no `--evidence ""` incantation); events/attestations stay required.
#[test]
fn build_omitted_evidence_and_relationships_means_empty() {
    let w = tmpdir("build-omitted");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    let proof = format!("{w}/proof.json");
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-omit",
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
            "payment:p-omit",
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
    let e_id = id_of(&ev);
    assert_eq!(
        run(args(
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
                "--out",
                &proof,
            ]
        )),
        Ok(0)
    );
    // And it verifies fresh (evidence stages trivially pass).
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--revocations-known-at",
                "1700000300",
                "--no-require-status",
            ]
        )),
        Ok(0)
    );
}

/// `--seen-store` turns the replay caller-contract into a guardrail:
/// unseen+record → 0, replay → 1, other contexts unaffected, corrupt stores
/// and flag misuse are usage/engine errors, verdict FAIL paths skip the gate.
#[test]
fn seen_store_rejects_replays_and_records() {
    let w = tmpdir("seen-store");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    let (proof, store) = (format!("{w}/proof.json"), format!("{w}/seen.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-seen",
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
            "payment:p-seen",
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
    let e_id = id_of(&ev);
    run(args(
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
            "--out",
            &proof,
        ],
    ))
    .unwrap();
    let v = |extra: &[&str]| {
        let mut a = vec![
            "verify".to_string(),
            "--proof".to_string(),
            proof.clone(),
            "--clock".to_string(),
            "1700000300".to_string(),
            "--revocations-known-at".to_string(),
            "1700000300".to_string(),
            "--no-require-status".to_string(),
        ];
        a.extend(extra.iter().map(|s| s.to_string()));
        run(a)
    };
    // Flag misuse is a usage error even on a valid proof.
    assert!(v(&["--seen-record"]).is_err());
    assert!(v(&["--seen-context", "tx:1"]).is_err());
    // Unseen + record → 0, store file appears in seen_set.py shape.
    assert_eq!(
        v(&[
            "--seen-store",
            &store,
            "--seen-context",
            "tx:1",
            "--seen-record"
        ]),
        Ok(0)
    );
    let sv: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&store).unwrap()).unwrap();
    assert_eq!(sv["seen"].as_array().unwrap().len(), 1);
    // Same proof + same context → replay → 1.
    assert_eq!(
        v(&[
            "--seen-store",
            &store,
            "--seen-context",
            "tx:1",
            "--seen-record"
        ]),
        Ok(1)
    );
    // Same proof + other context → unseen → 0 (contexts isolate actions).
    assert_eq!(
        v(&["--seen-store", &store, "--seen-context", "tx:2"]),
        Ok(0)
    );
    // Corrupt store with the gate requested → engine error, never silent pass.
    std::fs::write(&store, "not json{{{").unwrap();
    assert!(v(&["--seen-store", &store, "--seen-context", "tx:1"]).is_err());
}

/// Verdict FAIL paths skip the seen gate: an invalid proof with seen flags
/// still exits 1 from the verdict (not the gate) and writes no store.
#[test]
fn seen_store_skipped_on_verdict_fail() {
    let w = tmpdir("seen-skip");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    let (proof, store) = (format!("{w}/proof.json"), format!("{w}/seen.json"));
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-skip",
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
            "payment:p-skip",
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
    let e_id = id_of(&ev);
    run(args(
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
            "--out",
            &proof,
        ],
    ))
    .unwrap();
    // No freshness → UNKNOWN verdict FAIL; gate must not create the store.
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &proof,
                "--clock",
                "1700000300",
                "--seen-store",
                &store,
                "--seen-context",
                "tx:9",
                "--seen-record",
            ]
        )),
        Ok(1)
    );
    assert!(!std::path::Path::new(&store).exists());
}

/// Evaluate gates replays on policy-PASS paths (currency overlay applies
/// first): PASS+unseen records 0, PASS+replay exits 1 with the decision intact.
#[test]
fn seen_store_gates_evaluate_pass_paths() {
    let w = tmpdir("seen-eval");
    let (ev, att) = (format!("{w}/ev.json"), format!("{w}/att.json"));
    let (proof, policy, store) = (
        format!("{w}/proof.json"),
        format!("{w}/policy.json"),
        format!("{w}/seen.json"),
    );
    run(args(
        "create-event",
        &[
            "--type",
            "payment.created",
            "--subject",
            "payment:p-se",
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
            "payment:p-se",
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
    let e_id = id_of(&ev);
    run(args(
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
            "--out",
            &proof,
        ],
    ))
    .unwrap();
    let issuer = issuer_of(&att);
    run(args(
        "init-policy",
        &[
            "--issuer",
            &issuer,
            "--template",
            "minimal",
            "--out",
            &policy,
        ],
    ))
    .unwrap();
    let e = |extra: &[&str]| {
        let mut a = vec![
            "evaluate".to_string(),
            "--proof".to_string(),
            proof.clone(),
            "--policy".to_string(),
            policy.clone(),
            "--clock".to_string(),
            "1700000300".to_string(),
            "--revocations-known-at".to_string(),
            "1700000300".to_string(),
            "--no-require-status".to_string(),
            "--trusted".to_string(),
            issuer.clone(),
        ];
        a.extend(extra.iter().map(|s| s.to_string()));
        run(a)
    };
    assert_eq!(
        e(&[
            "--seen-store",
            &store,
            "--seen-context",
            "order:7",
            "--seen-record"
        ]),
        Ok(0)
    );
    assert_eq!(
        e(&[
            "--seen-store",
            &store,
            "--seen-context",
            "order:7",
            "--seen-record"
        ]),
        Ok(1)
    );
}

/// Compose asserts union coherence: two acyclic proofs sharing members
/// compose (and the composite verifies); a cross-proof derivation cycle
/// (acyclic alone, cyclic together) fails fast at compose time.
#[test]
fn compose_validates_union_graph_coherence() {
    let w = tmpdir("compose-coherence");
    let (ev_a, ev_b) = (format!("{w}/a.json"), format!("{w}/b.json"));
    let (att1, att2) = (format!("{w}/att1.json"), format!("{w}/att2.json"));
    for (ev, subj) in [(&ev_a, "item:a"), (&ev_b, "item:b")] {
        run(args(
            "create-event",
            &[
                "--type",
                "step.completed",
                "--subject",
                subj,
                "--effective-at",
                "1700000000",
                "--payload-hex",
                D1,
                "--out",
                ev,
            ],
        ))
        .unwrap();
    }
    for (att, i) in [(&att1, "1"), (&att2, "2")] {
        run(args(
            "attest",
            &[
                "--seed",
                "test",
                "--subject",
                "item:a",
                "--claim-type",
                "step.done",
                "--claim",
                &format!("n={i}"),
                "--issued-at",
                "1700000150",
                "--out",
                att,
            ],
        ))
        .unwrap();
    }
    let (a_id, b_id) = (id_of(&ev_a), id_of(&ev_b));
    // Bare PRODUCED edges (PRODUCED needs no grounding refs under V1
    // defaults; trust-relevant kinds still fail fast at relate).
    let (fwd, back) = (format!("{w}/fwd.json"), format!("{w}/back.json"));
    run(args(
        "relate",
        &[
            "--from", &a_id, "--type", "PRODUCED", "--to", &b_id, "--out", &fwd,
        ],
    ))
    .unwrap();
    run(args(
        "relate",
        &[
            "--from", &b_id, "--type", "PRODUCED", "--to", &a_id, "--out", &back,
        ],
    ))
    .unwrap();
    let build_proof = |tag: &str, att: &str, rel: &str| {
        let out = format!("{w}/{tag}.proof.json");
        run(args(
            "build",
            &[
                "--kind",
                "lineage.chain",
                "--subject",
                &a_id,
                "--predicate",
                "derived",
                "--created-at",
                "1700000200",
                "--events",
                &format!("{ev_a},{ev_b}"),
                "--attestations",
                att,
                "--evidence",
                "",
                "--relationships",
                rel,
                "--out",
                &out,
            ],
        ))
        .unwrap();
        out
    };
    let p_fwd = build_proof("fwd", &att1, &fwd);
    let p_back = build_proof("back", &att2, &back);
    // Each alone is acyclic; fwd+fwd2 share the same edge (deduped union)
    // for the OK path.
    let p_fwd2 = build_proof("fwd2", &att1, &fwd);
    let ok_out = format!("{w}/ok.json");
    assert_eq!(
        run(args(
            "compose",
            &[
                "--proofs",
                &format!("{p_fwd},{p_fwd2}"),
                "--kind",
                "composed.chain",
                "--subject",
                &a_id,
                "--predicate",
                "combines",
                "--created-at",
                "1700000300",
                "--out",
                &ok_out,
            ]
        )),
        Ok(0)
    );
    assert_eq!(
        run(args(
            "verify",
            &[
                "--proof",
                &ok_out,
                "--clock",
                "1700000400",
                "--revocations-known-at",
                "1700000400",
                "--no-require-status",
            ]
        )),
        Ok(0)
    );
    // Cross-proof cycle: acyclic alone, cyclic together → compose refuses.
    let bad_out = format!("{w}/bad.json");
    let r = run(args(
        "compose",
        &[
            "--proofs",
            &format!("{p_fwd},{p_back}"),
            "--kind",
            "composed.chain",
            "--subject",
            &a_id,
            "--predicate",
            "combines",
            "--created-at",
            "1700000300",
            "--out",
            &bad_out,
        ],
    ));
    assert!(r.is_err(), "cyclic union must fail fast at compose: {r:?}");
    assert!(!std::path::Path::new(&bad_out).exists());
}
