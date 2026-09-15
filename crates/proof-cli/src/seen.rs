// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opt-in replay guardrail (CLI-side; the core stays stateless).
//!
//! The engine verifies bytes deterministically: re-presenting valid bytes
//! re-verifies, by design (PROTOCOL.md Gate H, SECURITY-MODEL T3). Replay
//! protection therefore lives with the caller: track seen proof ids per
//! binding context (nonce/tx/challenge, usually carried in claim fields or
//! metadata). `--seen-store <file> --seen-context <ctx>` wires that contract
//! into `verify`/`evaluate`: on success paths the proof id is checked
//! against the store (replay → exit 1) and, with `--seen-record`, appended.
//! Same file shape as `tools/seen_set.py` (`{"seen": ["<ctx>::<proof_id>", …]}`
//! sorted, pretty) so script and CLI interoperate on one store.
//!
//! Scope: single-writer, caller-owned state (back it up like any operator
//! state; concurrent writers can interleave — serialize calls or shard by
//! context). Verdict FAIL paths skip the gate entirely: nothing
//! acceptance-worthy to protect, and recording invalid proofs would pin
//! garbage. I/O failures with the flags present are usage/engine errors
//! (exit 2): a requested guardrail that cannot be enforced must fail
//! closed, never silently pass.

use std::collections::BTreeSet;

use crate::Cli;

/// Validated seen-store request (`None` = flags absent, gate off).
pub struct SeenRequest {
    pub store: String,
    pub context: String,
    pub record: bool,
}

/// Validate flag combos: a context or record without a store is meaningless.
pub fn request(cli: &Cli) -> Result<Option<SeenRequest>, String> {
    let store = cli.opt("seen-store");
    let context = cli.opt("seen-context");
    let record = cli.has("seen-record");
    match (store, context) {
        (None, None) => {
            if record {
                return Err(
                    "--seen-record needs --seen-store <file> and --seen-context <ctx>".to_string(),
                );
            }
            Ok(None)
        }
        (None, Some(_)) => Err("--seen-context needs --seen-store <file>".to_string()),
        (Some(_), None) => Err(
            "--seen-store needs --seen-context <ctx> to bind replays to one business action"
                .to_string(),
        ),
        (Some(store), Some(context)) => {
            if context.is_empty() {
                return Err("--seen-context must not be empty".to_string());
            }
            Ok(Some(SeenRequest {
                store,
                context,
                record,
            }))
        }
    }
}

fn key(context: &str, proof_id: &str) -> String {
    format!("{context}::{proof_id}")
}

fn load_seen(path: &str) -> Result<BTreeSet<String>, String> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(format!("seen-store read {path}: {e}")),
        Ok(text) => {
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("seen-store parse {path}: {e}"))?;
            v.get("seen")
                .and_then(|x| x.as_array())
                .ok_or_else(|| format!("seen-store {path}: missing `seen` string array"))?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("seen-store {path}: `seen` must be strings"))
                })
                .collect()
        }
    }
}

/// Check `proof_id` against the store; record it when requested.
/// Returns true on replay. Call only on success paths (see module docs).
pub fn gate(req: &SeenRequest, proof_id: &str, quiet: bool) -> Result<bool, String> {
    let mut seen = load_seen(&req.store)?;
    let k = key(&req.context, proof_id);
    if seen.contains(&k) {
        if !quiet {
            eprintln!(
                "  replay detected: {proof_id} already processed in context `{}` (seen-store {})",
                req.context, req.store
            );
        }
        return Ok(true);
    }
    if !quiet {
        eprintln!(
            "  seen-store: unseen {proof_id} in context `{}`",
            req.context
        );
    }
    if req.record {
        seen.insert(k);
        let doc = serde_json::json!({"seen": seen.into_iter().collect::<Vec<_>>()});
        let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())? + "\n";
        std::fs::write(&req.store, text)
            .map_err(|e| format!("seen-store write {}: {e}", req.store))?;
        if !quiet {
            eprintln!("  seen-store: recorded {proof_id} -> {}", req.store);
        }
    }
    Ok(false)
}
