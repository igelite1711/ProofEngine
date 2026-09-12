// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! File/stream ingestion adapter (P9, outside the core).
//!
//! `ingest` turns newline-delimited external event records into canonical
//! event artifacts. It is a normalization boundary, not a trust boundary:
//! every record is validated through the same `create_event` builder as
//! `create-event`, malformed lines fail with line numbers (never silently
//! dropped unless `--skip-bad` is passed, and then they are listed in the
//! manifest), and output artifacts re-verify on load like any other file.
//!
//! Input line shape (JSON, one object per line; blank lines ignored):
//! ```json
//! {"type": "sensor.measurement.recorded", "subject": "sensor:m1",
//!  "effective_at": 1700000000, "payload_hex": "ab..(64 hex)",
//!  "meta": "unit=celsius,value=36.8"}
//! ```
//! `meta` is optional (`k=v` pairs, same grammar as `create-event --meta`).

use crate::artifact::{hash_ref_from_hex, write_json};
use crate::Cli;

/// One ingested record: validated fields plus its artifact id.
fn ingest_line(
    value: &serde_json::Value,
    line_no: usize,
    out_dir: &str,
    dry_run: bool,
    quiet: bool,
) -> Result<String, String> {
    let label = format!("line {line_no}");
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{label}: must be a JSON object"))?;
    let str_field = |name: &str| {
        obj.get(name)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{label}: missing non-empty string field `{name}`"))
    };
    let event_type = str_field("type")?;
    let subject = str_field("subject")?;
    let payload_hex = str_field("payload_hex")?;
    let effective_at = obj
        .get("effective_at")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{label}: missing u64 field `effective_at`"))?;
    let meta = match obj.get("meta") {
        None => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(format!("{label}: `meta` must be a string")),
    };
    // Unknown top-level keys are rejected: ingestion must not silently
    // swallow fields the caller thought were significant.
    for key in obj.keys() {
        if !["type", "subject", "payload_hex", "effective_at", "meta"].contains(&key.as_str()) {
            return Err(format!("{label}: unknown field `{key}`"));
        }
    }
    let content = proof_core::model::EventContent {
        v: 1,
        event_type: proof_core::model::EventType::new(event_type),
        subject,
        effective_at,
        payload_ref: hash_ref_from_hex(&payload_hex).map_err(|e| format!("{label}: {e}"))?,
        metadata: crate::parse_fields(meta).map_err(|e| format!("{label}: {e}"))?,
    };
    let created = proof_crypto::build::create_event(content, &crate::limits())
        .map_err(|e| format!("{label}: {e}"))?;
    if !dry_run {
        let out = format!("{out_dir}/{}.json", created.id);
        write_json(
            &out,
            serde_json::json!({
                "kind": "event",
                "id": created.id,
                "cbor": crate::artifact::cbor_to_hex(&created.canonical),
            }),
        )?;
        crate::progress(quiet, &format!("event   {} -> {out}", created.id));
    }
    Ok(created.id)
}

/// `ingest`: JSONL records → event artifacts + manifest.
///
/// Exit 0 with a manifest listing every artifact id. Default is fail-closed
/// (first malformed line aborts, nothing after it is processed);
/// `--skip-bad` continues and lists skipped lines in the manifest instead.
/// `--dry-run` validates only. `--out-dir` receives `<event-id>.json` files.
pub fn ingest(cli: &Cli) -> Result<i32, String> {
    let src = cli.opt("in").unwrap_or_else(|| "-".into());
    let (text, _) = crate::read_input_text(&src)?;
    let out_dir = cli.req("out-dir")?;
    let dry_run = cli.has("dry-run");
    let skip_bad = cli.has("skip-bad");
    if !dry_run {
        std::fs::create_dir_all(&out_dir).map_err(|e| format!("ingest: mkdir {out_dir}: {e}"))?;
    }
    let mut ids = vec![];
    let mut skipped = vec![];
    let mut line_no = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        line_no += 1;
        // Both JSON syntax and record validation honor --skip-bad: with the
        // flag, malformed lines are listed in the manifest instead of
        // aborting the batch.
        let outcome = serde_json::from_str(line)
            .map_err(|e| format!("line {line_no}: bad JSON: {e}"))
            .and_then(|value| ingest_line(&value, line_no, &out_dir, dry_run, cli.quiet()));
        match outcome {
            Ok(id) => ids.push(id),
            Err(e) if skip_bad => skipped.push(e),
            Err(e) => return Err(format!("ingest: {e}")),
        }
    }
    let manifest = serde_json::json!({
        "ingested": ids.len(),
        "ids": ids,
        "skipped": skipped,
        "dry_run": dry_run,
    });
    match cli.opt("out") {
        None => println!(
            "{}",
            serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?
        ),
        Some(path) => write_json(&path, manifest)?,
    }
    Ok(crate::EXIT_OK)
}
