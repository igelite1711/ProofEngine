// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `proof-cli id`: shell plumbing for content-addressed ids.
//!
//! Artifact ids (`evt:/att:/evd:/rel:/prf:…`) and issuer keyrefs live inside
//! JSON wrapper files. Shell flows need them as variables; without this
//! command that meant `python3 -c "import json;…"` one-liners per id.
//! `proof-cli id` replaces all of them:
//!
//! ```sh
//! EVT=$(proof-cli id --artifact ev1.json)
//! ISSUER=$(proof-cli id --artifact att.json --field issuer)
//! ```
//!
//! Read-only: prints one field on stdout, verifies nothing (use `verify`
//! for trust decisions, `inspect` to browse contents).

use crate::Cli;

/// Read `--field` (default `id`) from `--artifact` and return it.
/// `id` exists on every artifact; `issuer` only on attestations and status
/// objects. Anything else (or a missing/empty field) is a usage error.
pub fn value(cli: &Cli) -> Result<String, String> {
    let path = cli.req("artifact")?;
    let field = cli.opt("field").unwrap_or_else(|| "id".to_string());
    if field != "id" && field != "issuer" {
        return Err(format!("--field must be id|issuer, got `{field}`"));
    }
    let text = crate::read_input_file(&path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    v.get(&field)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            let kind = v
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("unknown");
            format!("{path}: no `{field}` field (kind `{kind}` carries none — `id` exists on every artifact, `issuer` only on attestations/status)")
        })
}
