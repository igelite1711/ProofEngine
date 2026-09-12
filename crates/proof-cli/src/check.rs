// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verification-side output: proof loading, report emission, exit codes.
//! Exit code contract: 0 = PASS, 1 = FAIL/INDETERMINATE, 2 = error.

use proof_verify::Validity;
use proof_verify::VerifyReport;

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
pub fn load_proof(path: &str, quiet: bool) -> Result<LoadedProof, String> {
    let (text, label) = crate::read_input_text(path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))?;
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
        "lifecycle_checked": r.lifecycle_checked,
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

/// `verify` exit code: PASS only when both crypto AND evidence are valid.
pub fn verdict_exit(report: &VerifyReport) -> i32 {
    if report.passed_crypto() && report.evidence_validity == Validity::Valid {
        crate::EXIT_OK
    } else {
        crate::EXIT_FAIL
    }
}

/// Human-readable verification summary on stderr. Derived purely from the
/// report (no independent decision logic). stdout stays machine-readable;
/// callers must respect `--quiet`.
pub fn emit_human_summary(report: &VerifyReport) {
    let id = report.proof_id.as_deref().unwrap_or("?");
    let crypto_ok = report.passed_crypto();
    let evidence_ok = report.evidence_validity == Validity::Valid;
    let (crypto_word, evidence_word) = (
        if crypto_ok {
            crate::green("valid")
        } else {
            crate::red("invalid")
        },
        if evidence_ok {
            crate::green("valid")
        } else {
            crate::red("invalid")
        },
    );
    eprintln!(
        "proof {} — crypto {crypto_word}, evidence {evidence_word}",
        crate::sanitize(id)
    );
    let mut pass = 0usize;
    for c in &report.checks {
        if c.ok {
            pass += 1;
        }
        let mark = if c.ok {
            crate::green("✓")
        } else {
            crate::red("✗")
        };
        eprintln!("  {mark} {} — {}", c.stage, crate::sanitize(&c.message));
    }
    let total = report.checks.len();
    let (result, code) = if crypto_ok && evidence_ok {
        (crate::green("VALID"), crate::EXIT_OK)
    } else {
        (crate::red("INVALID"), crate::EXIT_FAIL)
    };
    eprintln!("{pass}/{total} checks passed");
    eprintln!("RESULT {result} (exit {code})");
    for f in report.failure_codes() {
        eprintln!("  failure: {}", f.as_str());
    }
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
