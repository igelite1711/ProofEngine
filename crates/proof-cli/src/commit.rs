// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `proof-cli commit`: salted-hash commitments for confidential claims.
//!
//! The core is plaintext (see CONFIDENTIALITY.md): claim fields travel
//! verbatim and are hashed into ids. To attest a sensitive fact without
//! publishing it, commit to `hex(hash("salt|value"))` in the claim field
//! and keep the preimage off-proof; policy `claim_field eq` checks the
//! commitment (see `v2_commitment_pattern_hides_value_but_binds_policy`).
//! This command computes that digest so shell flows need no manual hashing:
//!
//! ```sh
//! C=$(proof-cli commit --salt s3 --value 'income:84000')
//! proof-cli attest --seed-file k --subject employee:e7 \
//!   --claim-type income.committed --claim commit=$C --issued-at <u64> ...
//! ```
//!
//! Secrecy note: `--value` is visible to ps(1)/history like `--seed`;
//! prefer `--value-file <path>` for real secrets. The salt must be unique
//! per commitment (reuse enables dictionary comparison across proofs).

use sha2::{Digest, Sha256, Sha384};

use crate::Cli;

/// Compute `hex(hash("salt|value"))` and print it on stdout.
/// `--alg sha256|sha384` (default sha256; must match the verifier's
/// expectation — the core treats the hex as opaque text).
/// `--value` and `--value-file` are mutually exclusive.
pub fn value(cli: &Cli) -> Result<String, String> {
    let alg = cli.opt("alg").unwrap_or_else(|| "sha256".to_string());
    let salt = cli.req("salt")?;
    if salt.is_empty() {
        crate::progress(
            cli.quiet(),
            "warning: empty --salt weakens the commitment (reuse enables dictionary comparison across proofs); use a unique random salt per commitment",
        );
    }
    let inline = cli.opt("value");
    let from_file = cli.opt("value-file");
    let secret = match (inline, from_file) {
        (Some(_), Some(_)) => {
            return Err("--value and --value-file are mutually exclusive".to_string())
        }
        (None, None) => {
            return Err("commit needs --value <text> or --value-file <path>".to_string())
        }
        (Some(v), None) => {
            // M5 remediation (SECURITY HARDENING): production must not carry
            // secrets in argv. Reject --value under --production; warn elsewhere.
            if cli.has("production") {
                return Err(
                    "--value exposes secret material in argv (ps/history); in --production use --value-file <path> instead"
                        .to_string(),
                );
            }
            crate::progress(
                cli.quiet(),
                "warning: --value exposes secret material in argv (ps/history); prefer --value-file <path>",
            );
            v
        }
        (None, Some(path)) => String::from_utf8(crate::read_input_bytes(&path)?)
            .map_err(|_| format!("{path}: value file must be UTF-8 text"))?,
    };
    let input = format!("{salt}|{secret}");
    let hex = match alg.as_str() {
        "sha256" => hex::encode(Sha256::digest(input.as_bytes())),
        "sha384" => hex::encode(Sha384::digest(input.as_bytes())),
        other => return Err(format!("--alg must be sha256|sha384, got `{other}`")),
    };
    if let Some(out) = cli.opt("out") {
        crate::artifact::write_json(
            &out,
            serde_json::json!({"kind": "commitment", "alg": alg, "digest": hex}),
        )?;
        crate::progress(
            cli.quiet(),
            &format!("commitment ({alg} of {salt}|<value>) -> {out}"),
        );
    } else {
        println!("{hex}");
        crate::progress(
            cli.quiet(),
            &format!("  next: proof-cli attest --claim-type <t> --claim commit={hex} --issued-at <u64> --out att.json"),
        );
    }
    Ok(hex)
}
