// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `doctor`: diagnose the local Proof Engine environment.

use crate::Cli;

struct Check {
    name: String,
    ok: bool,
    message: String,
}

/// Run environment diagnostics.
pub fn doctor(_cli: &Cli) -> Result<String, String> {
    let mut checks = vec![
        Check {
            name: "CLI version".to_string(),
            ok: true,
            message: env!("CARGO_PKG_VERSION").to_string(),
        },
        Check {
            name: "Protocol version".to_string(),
            ok: true,
            message: "V1".to_string(),
        },
        Check {
            name: "Format version".to_string(),
            ok: true,
            message: "V1".to_string(),
        },
        Check {
            name: "Crypto backend".to_string(),
            ok: true,
            message: "Ed25519/P-256 (proof-crypto)".to_string(),
        },
    ];

    // Check limits
    let limits = crate::limits();
    checks.push(Check {
        name: "Limits".to_string(),
        ok: true,
        message: format!(
            "max_edges={}, max_nodes={}, max_depth={}",
            limits.max_edges, limits.max_nodes, limits.max_depth
        ),
    });

    // Check max input file size
    checks.push(Check {
        name: "Max input file".to_string(),
        ok: true,
        message: format!("{} bytes", crate::MAX_INPUT_FILE_BYTES),
    });

    // Check if we can access the fixtures
    let fixtures_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("fixtures"));

    match fixtures_path {
        Some(path) if path.exists() => {
            checks.push(Check {
                name: "Fixtures".to_string(),
                ok: true,
                message: path.to_string_lossy().to_string(),
            });
        }
        _ => {
            checks.push(Check {
                name: "Fixtures".to_string(),
                ok: false,
                message: "not found (expected in repository root)".to_string(),
            });
        }
    }

    // Check demo directory
    let demo_dir = std::path::Path::new("demo");
    checks.push(Check {
        name: "Demo directory".to_string(),
        ok: demo_dir.exists(),
        message: if demo_dir.exists() {
            "exists".to_string()
        } else {
            "not found (run `proof-cli demo` to create)".to_string()
        },
    });

    // Check examples directory
    let examples_dir = std::path::Path::new("examples");
    checks.push(Check {
        name: "Examples".to_string(),
        ok: examples_dir.exists(),
        message: if examples_dir.exists() {
            format!("{} policy files", count_json_files(examples_dir))
        } else {
            "not found".to_string()
        },
    });

    // Print results
    let mut out = String::from(
        "Proof Engine Doctor

Environment checks:
",
    );

    let passed = checks.iter().filter(|c| c.ok).count();
    let total = checks.len();

    for check in &checks {
        let mark = if check.ok { "✓" } else { "✗" };
        out = format!(
            "{}  {} {} — {}
",
            out, mark, check.name, check.message
        );
    }

    out = format!(
        "{}

{}/{} checks passed",
        out, passed, total
    );

    if passed == total {
        out = format!(
            "{}

Everything looks good! Try `proof-cli demo` to see Proof Engine in action.",
            out
        );
    } else {
        out = format!(
            "{}

Some checks failed. See above for details.",
            out
        );
    }

    println!("{}", out);
    Ok(out)
}

fn count_json_files(dir: &std::path::Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("json") {
                count += 1;
            }
        }
    }
    count
}
