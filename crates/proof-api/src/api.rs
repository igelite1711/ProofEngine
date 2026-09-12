// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Request routing + verification for the reference API. Pure functions over
//! bytes (`route(method, path, body) -> (status, json)`), so the exact serve
//! path is unit-testable without sockets. No state, no cache, no clock reads:
//! every trust input arrives in the request body.

use proof_core::Limits;

/// `{...}` error envelope (status codes chosen by the caller).
pub fn err_json(message: &str) -> String {
    serde_json::json!({"error": message}).to_string()
}

fn limits() -> Limits {
    Limits::default()
}

/// Decode the `proof` field: `{"cbor_hex":…}` or a CLI artifact object
/// `{"kind":"proof","id":…,"cbor":…}`. Returns canonical bytes; claimed ids
/// are ignored here (the recomputed id in the report is authoritative).
fn proof_bytes(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let hex_str = v
        .get("cbor_hex")
        .or_else(|| v.get("cbor"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| "proof must carry `cbor_hex` (or artifact `cbor`)".to_string())?;
    hex_decode(hex_str).ok_or_else(|| "proof cbor hex is malformed".to_string())
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    if s.bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if bits > 0 && buf != 0 {
        return None;
    }
    Some(out)
}

fn u64_field(v: &serde_json::Value, name: &str, required: bool) -> Result<Option<u64>, String> {
    match v.get(name) {
        None if required => Err(format!("missing required field `{name}`")),
        None => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("`{name}` must be a u64")),
        Some(_) => Err(format!("`{name}` must be a u64")),
    }
}

fn str_list(v: &serde_json::Value, name: &str) -> Result<Vec<String>, String> {
    match v.get(name) {
        None => Ok(vec![]),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{name}` must be a string array"))
            })
            .collect(),
        Some(_) => Err(format!("`{name}` must be a string array")),
    }
}

/// Parse inline status objects `[{"issuer":…, "sign1_b64":…}]`, fully
/// re-verifying each (same rule as CLI status files).
fn parse_statuses(
    v: &serde_json::Value,
    limits: &Limits,
) -> Result<Vec<proof_crypto::SignedStatus>, String> {
    let mut out = vec![];
    let items = match v.get("status") {
        None => return Ok(out),
        Some(serde_json::Value::Array(items)) => items,
        Some(_) => return Err("`status` must be an array".into()),
    };
    for (i, item) in items.iter().enumerate() {
        let issuer = item
            .get("issuer")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("status[{i}]: missing `issuer`"))?;
        let sign1_b64 = item
            .get("sign1_b64")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("status[{i}]: missing `sign1_b64`"))?;
        let sign1 = b64u_decode(sign1_b64).ok_or_else(|| format!("status[{i}]: bad sign1_b64"))?;
        let content = proof_crypto::build::verify_status_object(
            &sign1,
            issuer,
            &proof_crypto::AllowedAlgs::default(),
            limits,
        )
        .map_err(|e| format!("status[{i}]: {e}"))?;
        out.push(proof_crypto::SignedStatus { content, sign1 });
    }
    Ok(out)
}

fn context_from(v: &serde_json::Value, limits: &Limits) -> Result<proof_verify::VerifyCtx, String> {
    Ok(proof_verify::VerifyCtx {
        verified_at: u64_field(v, "clock", true)?.unwrap_or(0),
        clock_skew_leeway: u64_field(v, "skew", false)?.unwrap_or(300),
        trusted_issuers: str_list(v, "trusted")?,
        status_objects: parse_statuses(v, limits)?,
        revocation_authorities: str_list(v, "authority")?,
        revocations_known_at: u64_field(v, "revocations_known_at", false)?,
        ..Default::default()
    })
}

fn report_json(report: &proof_verify::VerifyReport) -> serde_json::Value {
    serde_json::json!({
        "proof_id": report.proof_id,
        "cryptographic_validity": format!("{:?}", report.cryptographic_validity),
        "evidence_validity": format!("{:?}", report.evidence_validity),
        "policy_decision": format!("{:?}", report.policy_decision),
        "codes": report.failure_codes().iter().map(|c| format!("{c:?}")).collect::<Vec<_>>(),
        "lifecycle": report.lifecycle.iter().map(|l| serde_json::json!({
            "object": l.object, "status": format!("{:?}", l.status),
        })).collect::<Vec<_>>(),
        "referenced_proofs": report.referenced_proofs,
        "conflicts": report.conflicts.len(),
    })
}

/// Route one request. Returns `(http_status, json_body)`.
/// 400 = malformed request; 422 = well-formed but unverifiable by the
/// engine (caller-misuse inputs); verification verdicts themselves always
/// ride 200 with explicit validity fields (a FAIL is data, not an error).
pub fn route(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    if method == "GET" {
        return match path {
            "/v1/health" => (
                200,
                serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}).to_string(),
            ),
            "/v1/version" => (
                200,
                serde_json::json!({"name": "proof-api", "version": env!("CARGO_PKG_VERSION")})
                    .to_string(),
            ),
            _ => (404, err_json("unknown path")),
        };
    }
    if method != "POST" {
        return (405, err_json("method not allowed"));
    }
    let v: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return (400, err_json(&format!("bad JSON: {e}"))),
    };
    let limits = limits();
    match path {
        "/v1/verify" => {
            let bytes = match v.get("proof").map(proof_bytes).transpose() {
                Ok(Some(b)) => b,
                Ok(None) => return (400, err_json("missing `proof`")),
                Err(e) => return (400, err_json(&e)),
            };
            let ctx = match context_from(&v, &limits) {
                Ok(c) => c,
                Err(e) => return (400, err_json(&e)),
            };
            match proof_verify::verify_proof(&bytes, &ctx) {
                Ok(report) => (200, report_json(&report).to_string()),
                Err(e) => (422, err_json(&e.to_string())),
            }
        }
        "/v1/evaluate" | "/v1/explain" => evaluate_route(path, &v, &limits),
        "/v1/ingest" => ingest_route(&v, &limits),
        _ => (404, err_json("unknown path")),
    }
}

/// `POST /v1/ingest`: JSONL external event records → validated event ids +
/// manifest. Same fail-closed rules as the CLI `ingest` command (line
/// numbers, unknown-field rejection, optional `skip_bad` + `dry_run`);
/// queue pollers and webhook forwarders POST here. Returns 200 with the
/// manifest; malformed input is 400. Like the CLI, this is a normalization
/// boundary, not a trust boundary — every record still passes through
/// `create_event`, and output ids re-verify on load anywhere.
fn ingest_route(v: &serde_json::Value, limits: &proof_core::Limits) -> (u16, String) {
    let text = match v.get("records").and_then(|x| x.as_str()) {
        Some(t) => t,
        None => return (400, err_json("missing `records` (JSONL text)")),
    };
    if text.len() > 8 << 20 {
        return (400, err_json("`records` exceeds 8 MiB"));
    }
    let skip_bad = v.get("skip_bad").and_then(|x| x.as_bool()).unwrap_or(false);
    let dry_run = v.get("dry_run").and_then(|x| x.as_bool()).unwrap_or(false);
    let mut ids = vec![];
    let mut skipped = vec![];
    let mut line_no = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        line_no += 1;
        let outcome = serde_json::from_str(line)
            .map_err(|e| format!("line {line_no}: bad JSON: {e}"))
            .and_then(|value| ingest_record(&value, line_no, limits));
        match outcome {
            Ok(id) => ids.push(id),
            Err(e) if skip_bad => skipped.push(e),
            Err(e) => return (400, err_json(&format!("ingest: {e}"))),
        }
    }
    (
        200,
        serde_json::json!({
            "ingested": ids.len(), "ids": ids,
            "skipped": skipped, "dry_run": dry_run,
        })
        .to_string(),
    )
}

/// Validate one record object into an event id (dry-run always: the API
/// returns ids + manifest, never files — callers persist via envelopes).
fn ingest_record(
    value: &serde_json::Value,
    line_no: usize,
    limits: &proof_core::Limits,
) -> Result<String, String> {
    let label = format!("line {line_no}");
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{label}: must be a JSON object"))?;
    let str_field = |name: &str| {
        obj.get(name)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{label}: missing non-empty string field `{name}`"))
    };
    for key in obj.keys() {
        if !["type", "subject", "payload_hex", "effective_at", "meta"].contains(&key.as_str()) {
            return Err(format!("{label}: unknown field `{key}`"));
        }
    }
    let digest = obj
        .get("payload_hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{label}: missing `payload_hex`"))
        .and_then(|s| hex_decode(s).ok_or_else(|| format!("{label}: bad payload hex")))?;
    let alg = match digest.len() {
        32 => proof_core::HashAlgorithm::Sha256,
        48 => proof_core::HashAlgorithm::Sha384,
        _ => return Err(format!("{label}: digest must be 32 or 48 bytes")),
    };
    let mut metadata = vec![];
    if let Some(meta) = obj.get("meta") {
        let s = meta
            .as_str()
            .ok_or_else(|| format!("{label}: `meta` must be a string"))?;
        for pair in s.split(',') {
            let (k, val) = pair
                .split_once('=')
                .ok_or_else(|| format!("{label}: bad field `{pair}` (expected k=v)"))?;
            if k.is_empty() || val.is_empty() {
                return Err(format!("{label}: bad field `{pair}` (empty key or value)"));
            }
            metadata.push((
                k.to_string(),
                proof_core::model::MetaValue::Text(val.to_string()),
            ));
        }
    }
    let content = proof_core::model::EventContent {
        v: 1,
        event_type: proof_core::model::EventType::new(str_field("type")?),
        subject: str_field("subject")?,
        effective_at: obj
            .get("effective_at")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("{label}: missing u64 field `effective_at`"))?,
        payload_ref: proof_core::HashRef::new(alg, digest).map_err(|e| format!("{label}: {e}"))?,
        metadata,
    };
    proof_crypto::build::create_event(content, limits)
        .map(|c| c.id)
        .map_err(|e| format!("{label}: {e}"))
}

fn evaluate_route(path: &str, v: &serde_json::Value, limits: &proof_core::Limits) -> (u16, String) {
    {
        let bytes = match v.get("proof").map(proof_bytes).transpose() {
            Ok(Some(b)) => b,
            Ok(None) => return (400, err_json("missing `proof`")),
            Err(e) => return (400, err_json(&e)),
        };
        let policy_doc = match v.get("policy") {
            Some(p) => p,
            None => return (400, err_json("missing `policy`")),
        };
        let policy = match proof_policy::parse_policy(policy_doc, limits) {
            Ok(p) => p,
            Err(e) => return (400, err_json(&format!("policy: {e}"))),
        };
        let ctx = match context_from(v, limits) {
            Ok(c) => c,
            Err(e) => return (400, err_json(&e)),
        };
        let report = match proof_verify::verify_proof(&bytes, &ctx) {
            Ok(r) => r,
            Err(e) => return (422, err_json(&e.to_string())),
        };
        let state = match proof_of(&bytes, limits)
            .map_err(|e| e.to_string())
            .and_then(|proof| {
                proof_policy::state_from_report_and_proof(&report, &proof)
                    .map_err(|e| e.to_string())
            }) {
            Ok(s) => s,
            Err(e) => return (422, err_json(&e)),
        };
        // Trust inputs for policy come from the same explicit fields
        // (single context in, paired evaluation out — like
        // `verify_and_evaluate`, never divergent).
        let revoked: Vec<String> = str_list(v, "revoked").unwrap_or_default();
        let inputs = proof_policy::EvalInputs {
            trusted_issuers: str_list(v, "trusted").unwrap_or_default(),
            revocations: proof_policy::RevocationSet::new(revoked),
            verified_at: ctx.verified_at,
            skew_leeway: ctx.clock_skew_leeway,
        };
        let outcome = proof_policy::evaluate_policy(&state, &policy, &inputs);
        let mut out = serde_json::json!({
            "report": report_json(&report),
            "outcome": {
                "policy_id": outcome.policy_id,
                "decision": format!("{:?}", outcome.decision),
                "note": outcome.note,
                "results": outcome.results.iter().map(|r| serde_json::json!({
                    "requirement": r.requirement,
                    "passed": r.passed,
                    "message": r.message,
                })).collect::<Vec<_>>(),
            },
        });
        if path == "/v1/explain" {
            out["explanation"] =
                serde_json::Value::String(proof_policy::explain_full(&report, &outcome));
        }
        (200, out.to_string())
    }
}

/// Re-parse verified bytes for state projection (mirrors the one-shot
/// helper: bytes already verified above; failure here is engine-side,
/// returned as `Err`, never a panic).
fn proof_of(bytes: &[u8], limits: &Limits) -> Result<proof_core::model::Proof, String> {
    let value = proof_format::decode_strict(bytes, limits).map_err(|e| format!("re-parse: {e}"))?;
    proof_format::cbor_to_proof(&value, limits).map_err(|e| format!("re-project: {e}"))
}
