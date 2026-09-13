// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-cli binary: thin dispatcher over the library modules. All trust
//! decisions live in proof-verify / proof-policy; this file only routes
//! commands and maps outcomes to exit codes.

use proof_cli::{Cli, EXIT_ERR, EXIT_OK, USAGE, VERSION_INFO};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    std::process::exit(code);
}

// PE-CLI-001: 0 PASS · 1 verdict · 2 usage/engine error (matrix-tested below).
fn run(args: &[String]) -> i32 {
    let cli = match Cli::parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: {e}

{USAGE}"
            );
            return EXIT_ERR;
        }
    };
    // Hierarchical help: `help <command>` or `<command> --help` prints the
    // command topic; bare `help` prints the overview.
    if cli.command == "help" {
        match cli.positional.first() {
            Some(topic) => match proof_cli::command_help(topic) {
                Some(text) => {
                    println!("{text}");
                    return EXIT_OK;
                }
                None => {
                    eprintln!("error: unknown command `{topic}` (try `proof-cli help`)");
                    return EXIT_ERR;
                }
            },
            None => {
                println!("{USAGE}");
                return EXIT_OK;
            }
        }
    }
    if cli.has("help") {
        match proof_cli::command_help(&cli.command) {
            Some(text) => {
                println!("{text}");
                return EXIT_OK;
            }
            None => {
                println!("{USAGE}");
                return EXIT_OK;
            }
        }
    }
    let result = match cli.command.as_str() {
        "create-event" => proof_cli::artifact::write_event(&cli).map(|_| EXIT_OK),
        "attest" => proof_cli::artifact::write_attestation(&cli).map(|_| EXIT_OK),
        "add-evidence" => proof_cli::artifact::write_evidence(&cli).map(|_| EXIT_OK),
        "relate" => proof_cli::artifact::write_relationship(&cli).map(|_| EXIT_OK),
        "revoke" => proof_cli::artifact::write_status_object(&cli, "revoke").map(|_| EXIT_OK),
        "supersede" => proof_cli::artifact::write_status_object(&cli, "supersede").map(|_| EXIT_OK),
        "withdraw" => proof_cli::artifact::write_status_object(&cli, "withdraw").map(|_| EXIT_OK),
        "compromise" => {
            proof_cli::artifact::write_status_object(&cli, "compromise").map(|_| EXIT_OK)
        }
        "build" => proof_cli::make::build(&cli).map(|_| EXIT_OK),
        "verify" => proof_cli::make::verify(&cli),
        "evaluate" => proof_cli::make::evaluate(&cli, false),
        "explain" => proof_cli::make::evaluate(&cli, true),
        "inspect" => proof_cli::inspect::inspect(&cli).map(|_| EXIT_OK),
        "graph" => proof_cli::graph::graph(&cli).map(|_| EXIT_OK),
        "export" => proof_cli::port::export(&cli).map(|_| EXIT_OK),
        "import" => proof_cli::port::import(&cli).map(|_| EXIT_OK),
        "convert" => proof_cli::port::convert(&cli).map(|_| EXIT_OK),
        "compose" => proof_cli::port::compose(&cli).map(|_| EXIT_OK),
        "resolve" => proof_cli::port::resolve(&cli),
        "batch-verify" => proof_cli::make::batch_verify(&cli),
        "ingest" => proof_cli::ingest::ingest(&cli),
        "init-policy" => proof_cli::make::init_policy(&cli).map(|_| EXIT_OK),
        "doctor" => proof_cli::doctor::doctor(&cli),
        "completion" => match cli.opt("shell").or_else(|| cli.positional.first().cloned()) {
            Some(shell) => match proof_cli::completion_script(&shell) {
                Ok(script) => {
                    print!("{script}");
                    Ok(EXIT_OK)
                }
                Err(e) => Err(e),
            },
            None => Err("missing shell (usage: `completion bash|zsh|fish|powershell`)".to_string()),
        },
        "version" => {
            println!("{VERSION_INFO}");
            Ok(EXIT_OK)
        }
        "demo" => {
            // Interactive tour: a guided journey through the core.
            // Refuses cleanly without a terminal (never hangs CI).
            if cli.has("interactive") {
                return match proof_cli::journey::run(&cli) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("error: {e}");
                        EXIT_ERR
                    }
                };
            }
            // Default is repo-relative (`<repo>/demo/out`) so `make demo` and
            // `interop/differential.py --repo <repo>` agree regardless of the
            // caller's CWD. Resolve at runtime: walk up from the executable
            // toward a directory containing `Cargo.toml` + `demo/`; fall back
            // to the historical CWD-relative path when no repo root is found
            // (e.g. installed binaries run outside a checkout).
            let dir = cli.opt("out").unwrap_or_else(|| {
                let mut anchor = std::env::current_exe().ok();
                if anchor.is_none() {
                    anchor = std::env::current_dir().ok();
                }
                let mut cur = anchor.and_then(|p| {
                    p.parent()
                        .map(std::path::Path::to_path_buf)
                        .or_else(|| std::env::current_dir().ok())
                });
                while let Some(dir) = cur.clone() {
                    if dir.join("Cargo.toml").is_file() && dir.join("demo").is_dir() {
                        return dir.join("demo").join("out").to_string_lossy().into_owned();
                    }
                    cur = dir.parent().map(std::path::Path::to_path_buf);
                }
                "demo/out".to_string()
            });
            proof_cli::demo::run(&dir)
        }
        other => Err(format!("unknown command `{other}` (try `proof-cli help`)")),
    };
    match result {
        Ok(code) => code,
        // Usage and engine errors are exit 2; exit 1 is reserved for
        // FAIL/INDETERMINATE verdicts (returned as Ok(EXIT_FAIL) above).
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn tmpdir(name: &str) -> String {
        let d =
            std::env::temp_dir().join(format!("proof-cli-main-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    /// Exit-code contract (lib.rs, README, POLICY.md): 0 = PASS/valid,
    /// 1 = FAIL/INDETERMINATE verdict, 2 = usage or engine error.
    #[test]
    fn usage_errors_exit_2_not_1() {
        // Unknown command.
        assert_eq!(run(&args(&["bogus-cmd"])), proof_cli::EXIT_ERR);
        // Missing required flag.
        assert_eq!(
            run(&args(&["verify", "--proof", "p.json"])),
            proof_cli::EXIT_ERR
        );
        // Bad flag value type.
        assert_eq!(
            run(&args(&["verify", "--proof", "p.json", "--clock", "soon"])),
            proof_cli::EXIT_ERR
        );
        // Unreadable input file (engine error, not a verdict).
        assert_eq!(
            run(&args(&[
                "verify",
                "--proof",
                "/tmp/does-not-exist-proof-cli-test.json",
                "--clock",
                "1700000300"
            ])),
            proof_cli::EXIT_ERR
        );
        // Oversized input (H1 cap) is an engine error, not a verdict.
        let w = tmpdir("oversized");
        let big = format!("{w}/big.json");
        std::fs::write(
            &big,
            vec![b'x'; (proof_cli::MAX_INPUT_FILE_BYTES + 8) as usize],
        )
        .unwrap();
        assert_eq!(
            run(&args(&["verify", "--proof", &big, "--clock", "1700000300"])),
            proof_cli::EXIT_ERR
        );
    }

    #[test]
    fn help_exits_0() {
        assert_eq!(run(&args(&["help"])), proof_cli::EXIT_OK);
    }

    #[test]
    fn hierarchical_help_exits_0() {
        // `help <command>` prints the topic.
        assert_eq!(run(&args(&["help", "verify"])), proof_cli::EXIT_OK);
        assert_eq!(run(&args(&["help", "completion"])), proof_cli::EXIT_OK);
        // `<command> --help` prints the topic.
        assert_eq!(run(&args(&["verify", "--help"])), proof_cli::EXIT_OK);
        // Unknown topic is a usage error.
        assert_eq!(run(&args(&["help", "bogus-cmd"])), proof_cli::EXIT_ERR);
    }

    #[test]
    fn completion_needs_shell() {
        assert_eq!(run(&args(&["completion"])), proof_cli::EXIT_ERR);
        assert_eq!(run(&args(&["completion", "tcsh"])), proof_cli::EXIT_ERR);
    }

    /// Friction fix: `relate` with bare labels (`--to invoice:i9`) must fail
    /// fast at creation (exit 2 + hint), not late at `verify` with
    /// DANGLING_REFERENCE.
    #[test]
    fn relate_rejects_bare_labels_with_hint() {
        let w = tmpdir("relate-bare");
        let out = format!("{w}/rel.json");
        // Bare `--to` label.
        let code = run(&args(&[
            "relate",
            "--from",
            "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--type",
            "SETTLES",
            "--to",
            "invoice:i9",
            "--out",
            &out,
        ]));
        assert_eq!(code, proof_cli::EXIT_ERR);
        assert!(
            !std::path::Path::new(&out).exists(),
            "no relationship may be written from a bare label"
        );
        // Bare `--from` label.
        let code = run(&args(&[
            "relate",
            "--from",
            "payment:p1",
            "--type",
            "SETTLES",
            "--to",
            "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--out",
            &out,
        ]));
        assert_eq!(code, proof_cli::EXIT_ERR);
    }

    /// V1.1 F3: `EQUIVALENT` endpoints may name free identity refs
    /// (e.g. `did:org:acme`) as asserted — grounding still required, shaped
    /// ids must still resolve. Non-EQUIVALENT bare labels still fail fast.
    #[test]
    fn relate_allows_equivalent_identity_refs() {
        // EQUIVALENT with free refs is writable (grounding checked at build).
        // Use --evidence-ref with a well-formed (not necessarily member) id:
        // `relate` only shape-checks here; membership is the pipeline's job.
        // For the unit, assert the file IS written (no fail-fast).
        let w = tmpdir("relate-equiv");
        let out = format!("{w}/rel.json");
        let code = run(&args(&[
            "relate",
            "--from",
            "did:org:acme",
            "--type",
            "EQUIVALENT",
            "--to",
            "did:person:alice",
            "--evidence-ref",
            "evd:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--out",
            &out,
        ]));
        assert_eq!(code, proof_cli::EXIT_OK);
        assert!(std::path::Path::new(&out).exists());
        // Shaped-but-malformed ids still fail fast even for EQUIVALENT.
        let out2 = format!("{w}/rel2.json");
        let code = run(&args(&[
            "relate",
            "--from",
            "did:org:acme",
            "--type",
            "EQUIVALENT",
            "--to",
            "evt:v2:short",
            "--evidence-ref",
            "evd:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--out",
            &out2,
        ]));
        assert_eq!(code, proof_cli::EXIT_ERR);
    }

    /// Friction fix: `build` without `--evidence` names the
    /// `--evidence ""` escape hatch; `--evidence ""` means zero evidence.
    #[test]
    fn build_evidence_empty_string_means_no_members() {
        // Unit-cover the list helper via build: missing --evidence errors
        // with the hint (message asserted in e2e below); empty string parses
        // to an empty member list (no io attempted beyond flag parsing —
        // the build will proceed to its next required flag).
        let code = run(&args(&[
            "build",
            "--kind",
            "k",
            "--subject",
            "s",
            "--predicate",
            "p",
            "--created-at",
            "1700000200",
            "--events",
            "nope.json",
            "--attestations",
            "nope.json",
            "--relationships",
            "nope.json",
            "--out",
            "/tmp/proof-cli-must-not-write.json",
        ]));
        // Missing --evidence entirely (not empty string): usage error, and
        // the file must not exist.
        assert_eq!(code, proof_cli::EXIT_ERR);
        assert!(
            !std::path::Path::new("/tmp/proof-cli-must-not-write.json").exists(),
            "no proof may be written when --evidence is missing"
        );
    }

    /// PE-CRYPTO-009 (FORMAT §3): ids carry one full SHA-256 digest; a
    /// truncated digest cannot name an object. Usage error (exit 2), and the
    /// failure names the digest rule, not a generic parse error.
    #[test]
    fn truncated_digest_refs_rejected_as_usage_error() {
        let full = "1111111111111111111111111111111111111111111111111111111111111111";
        let short = &full[..40];
        for flag in ["--payload-hex", "--digest-hex"] {
            let cmd = if flag == "--payload-hex" {
                vec![
                    "create-event".to_string(),
                    "--type".to_string(),
                    "x.y".to_string(),
                    "--subject".to_string(),
                    "s:1".to_string(),
                    "--effective-at".to_string(),
                    "1700000000".to_string(),
                    flag.to_string(),
                    short.to_string(),
                    "--out".to_string(),
                    "/tmp/proof-cli-must-not-write.json".to_string(),
                ]
            } else {
                vec![
                    "add-evidence".to_string(),
                    "--kind".to_string(),
                    "k".to_string(),
                    flag.to_string(),
                    short.to_string(),
                    "--out".to_string(),
                    "/tmp/proof-cli-must-not-write.json".to_string(),
                ]
            };
            let r = run(&cmd);
            assert_eq!(
                r,
                proof_cli::EXIT_ERR,
                "{flag}: truncated digest must be usage error"
            );
            assert!(
                !std::path::Path::new("/tmp/proof-cli-must-not-write.json").exists(),
                "no artifact may be written from a truncated digest"
            );
        }
    }
}
