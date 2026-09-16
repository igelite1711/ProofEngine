// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verification-side output: proof loading, report emission, exit codes.
//! Exit code contract: 0 = PASS, 1 = FAIL/INDETERMINATE, 2 = error.

use proof_verify::Validity;
use proof_verify::{CheckRecord, VerifyReport};

/// A loaded proof artifact. The pipeline re-verifies every stage over the
/// canonical bytes (including the envelope id), so loading only needs to
/// extract schema-valid bytes; nothing here is trusted.
pub struct LoadedProof {
    pub canonical: Vec<u8>,
    #[allow(dead_code)]
    pub proof: proof_core::model::Proof,
}

/// Load a proof artifact file (JSON wrapper, canonical CBOR hex inside).
/// If path is "-", read from stdin. `quiet` suppresses the progress note
/// (`--quiet` must silence all nonessential stderr).
// PE-CLI-002: schema-decode only; pipeline re-verifies id/canonical/sigs.
//
// Envelope consistency (fail closed): when the wrapper carries an `id` it
// MUST name the same proof the canonical bytes bind. A wrapper whose `id`
// disagrees with the bytes is rejected here — never silently verified under
// a different identity. Wrappers without `id` (raw transports) load by bytes
// alone; the pipeline report's `proof_id` is authoritative either way.
//
// Strict wrapper (M-5, CLI-layer only): unknown top-level fields are
// rejected fail-closed (exit 2, names the field, e.g.
// `wrapper has unknown field "evil"`). Allowed keys are exactly what
// `build`/`compose`/`demo` write via `write_proof_file`
// (`cbor`,`id`,`kind`) plus the `container_version` compat key `convert`
// adds (and bare `cbor`+optional `id` raw transports keep working — the
// allowlist is a subset check, never a required-keys check).
pub fn load_proof(path: &str, quiet: bool) -> Result<LoadedProof, String> {
    let (text, label) = crate::read_input_text(path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))?;
    crate::artifact::reject_unknown_wrapper_fields(
        &v,
        &label,
        crate::artifact::PROOF_WRAPPER_ALLOWED,
    )?;
    // M1 (audit remediation, BUG): wrapper `kind` is authoritative for proof
    // envelopes. When present it MUST be exactly "proof"; any other string
    // (event/evil/unknown/...) is a wrapper-kind mismatch and fails closed.
    // Missing `kind` is allowed for raw transports (bare cbor+optional id);
    // bytes remain authoritative either way. Non-string `kind` is a malformed
    // wrapper (transport error, exit 2). Single interpretation: PROOF-ENGINE-SPEC §15.
    if let Some(kind_val) = v.get("kind") {
        match kind_val.as_str() {
            Some("proof") => {}
            Some(other) => {
                return Err(format!(
                    "{label}: envelope kind mismatch (wrapper says kind \"{other}\", expected \"proof\")"
                ));
            }
            None => {
                return Err(format!("{label}: wrapper `kind` must be a string"));
            }
        }
    }
    let hex_str = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{label}: missing `cbor`"))?;
    let bytes = hex::decode(hex_str).map_err(|e| format!("{label}: bad hex: {e}"))?;
    let limits = crate::limits();
    let value =
        proof_format::decode_strict(&bytes, &limits).map_err(|e| format!("{label}: {e}"))?;
    let proof = proof_format::schema::cbor_to_proof(&value, &limits)
        .map_err(|e| format!("{label}: {e}"))?;
    if let Some(claimed) = v.get("id").and_then(|x| x.as_str()) {
        if claimed != proof.proof_id {
            return Err(format!(
                "{label}: envelope id mismatch (wrapper says {claimed}, bytes bind {})",
                proof.proof_id
            ));
        }
    }
    if !quiet {
        eprintln!("loaded proof {} ({label})", proof.proof_id);
    }
    Ok(LoadedProof {
        canonical: bytes,
        proof,
    })
}

fn validity_str(v: Validity) -> &'static str {
    if v == Validity::Valid {
        "valid"
    } else {
        "invalid"
    }
}

/// Explicit JSON projection of the report (the report type is not Serialize;
/// the CLI owns its output format). Stable field order, machine-readable.
// PE-CLI-004 · PE-CLI-007: pub(crate) so `evaluate --json` can embed the
// pipeline report alongside the policy outcome.
pub fn report_json(r: &VerifyReport) -> serde_json::Value {
    serde_json::json!({
        "proof_id": r.proof_id,
        "cryptographic_validity": validity_str(r.cryptographic_validity),
        "evidence_validity": validity_str(r.evidence_validity),
        "policy_decision": r.policy_decision.as_str(),
        // Fix 1/3 split: bare `verify` VALID means historically valid.
        // Automation MUST check `currently_acceptable` (or use --production/
        // --strict-current for exit-1 enforcement) before treating VALID as
        // currently trustworthy. False on SUPERSEDED history or unverified
        // provenance hints; WITHDRAWN/COMPROMISED/REVOKED/EXPIRED already flip
        // evidence_invalid and need no extra gate.
        "currently_acceptable": is_currently_acceptable(r),
        "lifecycle_checked": r.lifecycle_checked,
        "status_inputs_valid": r.status_inputs_valid,
        "lifecycle": r
            .lifecycle
            .iter()
            .map(|l| {
                serde_json::json!({
                    "object": l.object,
                    "status": l.status.as_str(),
                    "code": l.code.map(|c| c.as_str()),
                    "message": l.message,
                })
            })
            .collect::<Vec<_>>(),
        "status_objects": r.status_objects,
        "withdrawn_ids": r.withdrawn_ids,
        "referenced_proofs": r.referenced_proofs,
        "vocabularies": r
            .vocabularies
            .iter()
            .map(|vd| {
                serde_json::json!({"ns": vd.ns, "version": vd.version})
            })
            .collect::<Vec<_>>(),
        "evidence_status": r
            .evidence_status
            .iter()
            .map(|e| {
                serde_json::json!({
                    "object": e.object,
                    "status": e.status.as_str(),
                    "code": e.code.map(|c| c.as_str()),
                    "message": e.message,
                })
            })
            .collect::<Vec<_>>(),
        "conflicts": r
            .conflicts
            .iter()
            .map(|c| {
                serde_json::json!({
                    "kind": c.kind.as_str(),
                    "claim_type": c.claim_type,
                    "subject": c.subject,
                    "attestation_ids": c.attestation_ids,
                })
            })
            .collect::<Vec<_>>(),
        "checks": r
            .checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "stage": c.stage,
                    "object": c.object,
                    "ok": c.ok,
                    "code": c.code.map(|c| c.as_str()),
                    "message": c.message,
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// Emit the report: stdout (machine-readable) when no `--out` is given,
/// otherwise written to the file with only a progress note on stderr.
/// If out is "-", write to stdout without progress message. `quiet`
/// suppresses the file-write progress note.
// PE-CLI-004: machine-readable stdout/file; progress stderr.
pub fn emit_report(report: &VerifyReport, out: Option<String>, quiet: bool) -> Result<(), String> {
    let v = report_json(report);
    let text = serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?;
    match out {
        Some(ref path) if path == "-" => {
            println!("{text}");
        }
        Some(path) => {
            std::fs::write(
                &path,
                text + "
",
            )
            .map_err(|e| format!("write {path}: {e}"))?;
            if !quiet {
                eprintln!("report  -> {path}");
            }
        }
        None => println!("{text}"),
    }
    Ok(())
}

/// Load raw proof bytes without CBOR validation (for fail-closed reporting).
/// Returns the canonical bytes from the `cbor` hex field, or the transport
/// error if the file cannot even be read as JSON/hex. Used by `verify` to
/// produce a machine-readable FAIL report (exit 1) for malformed proofs
/// instead of a prose-only engine error (exit 2). Transport failures
/// (missing file, bad JSON, missing `cbor`, bad hex) remain usage errors.
pub fn load_proof_bytes_raw(path: &str) -> Result<Vec<u8>, String> {
    let (text, label) = crate::read_input_text(path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))?;
    let hex_str = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{label}: missing `cbor`"))?;
    hex::decode(hex_str).map_err(|e| format!("{label}: bad hex: {e}"))
}

/// Build a fail-closed report for proofs that never parsed (M1 fix).
/// `stage` is PARSE or SCHEMA, `code` the stable wire code, `message` human
/// detail. crypto Invalid + evidence Invalid (early exit, lifecycle unchecked),
/// policy INDETERMINATE, status_inputs_valid true (feed not implicated).
/// stdout stays machine-readable; exit is FAIL (1), never engine error (2).
pub fn malformed_report(
    stage: &'static str,
    code: proof_core::ErrorCode,
    message: String,
) -> VerifyReport {
    VerifyReport {
        proof_id: None,
        cryptographic_validity: Validity::Invalid,
        evidence_validity: Validity::Invalid,
        policy_decision: proof_verify::PolicyDecision::Indeterminate,
        lifecycle_checked: false,
        lifecycle: vec![],
        status_objects: vec![],
        withdrawn_ids: vec![],
        referenced_proofs: vec![],
        vocabularies: vec![],
        evidence_status: vec![],
        conflicts: vec![],
        checks: vec![
            CheckRecord::fail(stage, "proof:bytes", code, message),
            CheckRecord::note(
                "POLICY",
                "proof:bytes",
                "policy decision is made by the caller via proof-policy::evaluate_policy; the pipeline reports INDETERMINATE (never PASS by default)",
            ),
        ],
        status_inputs_valid: true,
    }
}

/// Build a fail-closed report for envelope kind mismatch (M1 remediation).
/// Wrapper claims `kind` X but proof envelopes MUST carry "proof" when the
/// field is present. Reports SCHEMA/SCHEMA_VIOLATION, crypto Invalid +
/// evidence Invalid, exit FAIL (1) with JSON. Missing `kind` (raw transport)
/// never reaches here; non-string `kind` is a transport error (exit 2).
pub fn envelope_kind_mismatch_report(claimed: &str) -> VerifyReport {
    VerifyReport {
        proof_id: None,
        cryptographic_validity: Validity::Invalid,
        evidence_validity: Validity::Invalid,
        policy_decision: proof_verify::PolicyDecision::Indeterminate,
        lifecycle_checked: false,
        lifecycle: vec![],
        status_objects: vec![],
        withdrawn_ids: vec![],
        referenced_proofs: vec![],
        vocabularies: vec![],
        evidence_status: vec![],
        conflicts: vec![],
        checks: vec![
            CheckRecord::fail(
                "SCHEMA",
                "proof:bytes",
                proof_core::ErrorCode::SchemaViolation,
                format!(
                    "envelope kind mismatch (wrapper says kind \"{claimed}\", expected \"proof\")"
                ),
            ),
            CheckRecord::note(
                "POLICY",
                "proof:bytes",
                "policy decision is made by the caller via proof-policy::evaluate_policy; the pipeline reports INDETERMINATE (never PASS by default)",
            ),
        ],
        status_inputs_valid: true,
    }
}

/// Build a fail-closed report for envelope id mismatch (wrapper lies).
/// Bytes internally bind `actual`, wrapper claims `claimed`. Tamper evidence:
/// IDENTIFIERS ID_MISMATCH, exit FAIL (1) with JSON, not engine error (2).
pub fn envelope_mismatch_report(claimed: &str, actual: &str) -> VerifyReport {
    VerifyReport {
        proof_id: Some(actual.to_string()),
        cryptographic_validity: Validity::Invalid,
        evidence_validity: Validity::Invalid,
        policy_decision: proof_verify::PolicyDecision::Indeterminate,
        lifecycle_checked: false,
        lifecycle: vec![],
        status_objects: vec![],
        withdrawn_ids: vec![],
        referenced_proofs: vec![],
        vocabularies: vec![],
        evidence_status: vec![],
        conflicts: vec![],
        checks: vec![
            CheckRecord::fail(
                "IDENTIFIERS",
                format!("proof:{claimed}"),
                proof_core::ErrorCode::IdMismatch,
                format!("envelope id mismatch (wrapper says {claimed}, bytes bind {actual})"),
            ),
            CheckRecord::note(
                "POLICY",
                format!("proof:{actual}"),
                "policy decision is made by the caller via proof-policy::evaluate_policy; the pipeline reports INDETERMINATE (never PASS by default)",
            ),
        ],
        status_inputs_valid: true,
    }
}

/// M2: strict-currency check. Returns false (not current) when any
/// attestation is SUPERSEDED or UNKNOWN, or any evidence is SUPERSEDED /
/// UNKNOWN-hint. WITHDRAWN/COMPROMISED/REVOKED/EXPIRED already flip evidence
/// INVALID, so they need no extra gate (and stay currency-true: validity and
/// currency are orthogonal signals — callers combine both, as cmd_verify
/// does). UNKNOWN is the exception: unknown currency is itself not
/// acceptable, so it fails both.
pub fn is_currently_acceptable(report: &VerifyReport) -> bool {
    if report.lifecycle.iter().any(|l| {
        l.status == proof_core::LifecycleStatus::Superseded
            || l.status == proof_core::LifecycleStatus::Unknown
    }) {
        return false;
    }
    if report.evidence_status.iter().any(|e| {
        e.status == proof_core::model::EvidenceStatus::Superseded
            || (e.status == proof_core::model::EvidenceStatus::Unknown
                && e.message.contains("provenance hint unverified"))
    }) {
        return false;
    }
    true
}

/// `verify` exit code: PASS only when both crypto AND evidence are valid.
pub fn verdict_exit(report: &VerifyReport) -> i32 {
    if report.passed_crypto() && report.evidence_validity == Validity::Valid {
        crate::EXIT_OK
    } else {
        crate::EXIT_FAIL
    }
}

/// Unambiguous H-1 human verdict label (CLI-layer only; frozen verdicts
/// unchanged). Returns `HISTORICALLY_VALID (...)` when crypto+evidence are
/// valid but currency is not (SUPERSEDED/unverified-provenance history),
/// `VALID` when valid and current, `INVALID` otherwise. Never returns bare
/// `VALID` for not-current proofs. `pub` so integration tests assert the
/// exact label without scraping stderr.
pub fn human_verdict_label(report: &VerifyReport) -> String {
    let crypto_ok = report.passed_crypto();
    let evidence_ok = report.evidence_validity == Validity::Valid;
    if crypto_ok && evidence_ok {
        if is_currently_acceptable(report) {
            "VALID".to_string()
        } else {
            "HISTORICALLY_VALID (not currently acceptable; use --production/--strict-current or check currently_acceptable:false)".to_string()
        }
    } else {
        "INVALID".to_string()
    }
}

/// Shared warning text for `--no-require-status` empty feeds (H-2 footgun
/// guard). Backward compatible: the flag keeps working (genesis genuinely
/// needs it — no revocations can exist yet), but every explicitly-allowed
/// empty feed warns loudly so prod operators never copy-paste a genesis
/// invocation. Default stays fail-closed. Message names the risk and remedy.
pub fn no_require_status_warning(revocations_known_at: u64) -> String {
    format!(
        "WARNING: --no-require-status asserts caller-checked absence with 0 status objects (--revocations-known-at {revocations_known_at}): lifecycle ACTIVE is asserted, not feed-proved. NEVER use in production; supply --status feed files + --authority keys (see `help verify`; genesis/demo only)."
    )
}

/// Semantic verdict kind on the integrity axis (CLI-layer presentation only;
/// frozen verdicts and exit codes unchanged). Mirrors `human_verdict_label`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    /// Valid and currently acceptable (or strict mode not in play).
    Valid,
    /// Crypto+evidence valid but currency not established (SUPERSEDED /
    /// unverified provenance hint): historically true, not current.
    Historical,
    /// Verification failed on the integrity axis.
    Invalid,
}

/// Classify a report for the two-axis human presentation. `strict_fail`
/// (`--strict-current`/`--production` currency overlay) downgrades VALID
/// history to enforced-invalid, same as the human label logic.
pub fn verdict_kind(report: &VerifyReport) -> VerdictKind {
    let crypto_ok = report.passed_crypto();
    let evidence_ok = report.evidence_validity == Validity::Valid;
    if !(crypto_ok && evidence_ok) {
        return VerdictKind::Invalid;
    }
    if is_currently_acceptable(report) {
        VerdictKind::Valid
    } else {
        VerdictKind::Historical
    }
}

/// Human-readable verification summary on stderr. Derived purely from the
/// report (no independent decision logic). stdout stays machine-readable;
/// callers must respect `--quiet`.
///
/// UX pass: presentation moved to `ux::emit_summary` (two-axis verdict:
/// PROOF INTEGRITY vs CLAIM DECISION, layered answer→why→details). This
/// wrapper keeps the old entry point for callers/tests; default is the
/// concise Layer-1 view (no per-stage list — that is `--verbose` now).
pub fn emit_human_summary(report: &VerifyReport, strict_fail: bool) {
    crate::ux::emit_summary(report, strict_fail, false);
}

/// PE-CLI-007: stable JSON projection of the policy outcome for `evaluate
/// --json` (`proof-cli/src/make.rs`). Field set is the machine contract.
pub fn outcome_json(outcome: &proof_policy::PolicyOutcome) -> serde_json::Value {
    serde_json::json!({
        "policy_id": outcome.policy_id,
        "decision": outcome.decision.as_str(),
        "note": outcome.note,
        "results": outcome
            .results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "requirement": r.requirement,
                    "passed": r.passed,
                    "message": r.message,
                })
            })
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod currency_tests {
    use super::*;
    use proof_core::model::EvidenceStatus;
    use proof_core::LifecycleStatus;
    use proof_verify::report::{EvidenceStatusRecord, LifecycleRecord, Validity as V};

    fn base_report() -> proof_verify::VerifyReport {
        proof_verify::VerifyReport {
            proof_id: Some("prf:v1:x".into()),
            cryptographic_validity: V::Valid,
            evidence_validity: V::Valid,
            policy_decision: proof_verify::PolicyDecision::Indeterminate,
            lifecycle_checked: true,
            lifecycle: vec![],
            status_objects: vec![],
            withdrawn_ids: vec![],
            referenced_proofs: vec![],
            vocabularies: vec![],
            evidence_status: vec![],
            conflicts: vec![],
            checks: vec![],
            status_inputs_valid: true,
        }
    }

    #[test]
    fn active_lifecycle_is_currently_acceptable() {
        let mut r = base_report();
        r.lifecycle.push(LifecycleRecord {
            object: "att:x".into(),
            status: LifecycleStatus::Active,
            code: None,
            message: "active".into(),
        });
        assert!(is_currently_acceptable(&r));
    }

    #[test]
    fn superseded_lifecycle_fails_currency() {
        let mut r = base_report();
        r.lifecycle.push(LifecycleRecord {
            object: "att:x".into(),
            status: LifecycleStatus::Superseded,
            code: None,
            message: "superseded".into(),
        });
        assert!(!is_currently_acceptable(&r));
    }

    #[test]
    fn unverified_provenance_hint_fails_currency() {
        let mut r = base_report();
        r.evidence_status.push(EvidenceStatusRecord {
            object: "evd:x".into(),
            status: EvidenceStatus::Unknown,
            code: None,
            message: "backing attestation not verified in this proof — provenance hint unverified, validity preserved".into(),
        });
        assert!(!is_currently_acceptable(&r));
    }

    #[test]
    fn revoked_lifecycle_is_not_currency_gap() {
        // REVOKED already fails evidence_validity; `--strict-current` only
        // *additionally* rejects currency gaps on otherwise-valid proofs, so
        // is_currently_acceptable must not conflate the two (callers combine
        // verdict + strict flag, as cmd_verify does).
        let mut r = base_report();
        r.evidence_validity = V::Invalid;
        assert!(is_currently_acceptable(&r));
    }

    #[test]
    fn unknown_lifecycle_fails_currency() {
        // UNKNOWN currency (e.g. empty feed under the fail-closed default)
        // is itself not acceptable — unlike REVOKED, there is no validity
        // failure to lean on for currency purposes; the boolean must agree
        // with the exit code.
        let mut r = base_report();
        r.evidence_validity = V::Invalid;
        r.lifecycle.push(LifecycleRecord {
            object: "att:x".into(),
            status: LifecycleStatus::Unknown,
            code: Some(proof_core::ErrorCode::RevocationUnknown),
            message: "unknown".into(),
        });
        assert!(!is_currently_acceptable(&r));
    }
}
