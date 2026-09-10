// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VerifiedState: the exact, minimal view of a verified proof that policy
//! evaluation may consume. Derived from a `VerifyReport` plus the parsed
//! `Proof` it describes — never from databases, reputation, or prose.

use proof_core::{
    model::{EvidenceKind, Proof, RelType},
    ErrorCode, LifecycleStatus, ProofError,
};
use proof_verify::{Validity, VerifyReport};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct VerifiedState {
    pub proof_id: String,
    pub crypto_valid: bool,
    pub evidence_valid: bool,
    /// Issuers whose attestations carry verified signatures in this proof.
    pub verified_issuers: Vec<String>,
    /// Ids of signature-verified attestations (aligned with `attestation_times`).
    pub attestation_ids: Vec<String>,
    /// Objects the pipeline lifecycle marked SUPERSEDED (subset of
    /// `attestation_ids`). Historical records: valid, but stale.
    // PE-POLICY-006: lifecycle-derived currency view.
    pub superseded_ids: Vec<String>,
    /// (issued_at, expires_at) aligned with `attestation_ids`.
    pub attestation_times: Vec<(u64, Option<u64>)>,
    pub rel_types: Vec<RelType>,
    pub evidence_kinds: Vec<EvidenceKind>,
    /// The proof's created_at timestamp (informational, outside proof_id binding).
    /// Used by the `proof_fresh` policy requirement (V1.1).
    pub proof_created_at: u64,
}

impl VerifiedState {
    pub fn has_transparency(&self) -> bool {
        self.evidence_kinds
            .contains(&EvidenceKind::new(EvidenceKind::TRANSPARENCY_RECEIPT))
    }
}

/// Build the evaluation view. Fails (caller error, not a verdict) when the
/// report and proof do not belong together — evaluation must never run on a
/// mismatched pair.
pub fn state_from_report_and_proof(
    report: &VerifyReport,
    proof: &Proof,
) -> Result<VerifiedState, ProofError> {
    let rid = report.proof_id.as_deref().ok_or_else(|| {
        ErrorCode::SchemaViolation.err("no proof id in report: proof never parsed")
    })?;
    if rid != proof.proof_id {
        return Err(ErrorCode::SchemaViolation.err("report and proof describe different proofs"));
    }
    // Signature-verified attestation ids, read off the report's own records.
    let verified: HashSet<&str> = report
        .checks
        .iter()
        .filter(|c| c.ok && c.stage == "SIGNATURES")
        .filter_map(|c| c.object.strip_prefix("att:"))
        .collect();
    // PE-TRUST-004: embedded status attestations (revoke/supersede) must never satisfy
    // `issuer_trusted` / populate validity intervals: a revocation authority
    // is not (by signature alone) a statement issuer.
    let status_objects: HashSet<&str> = report.status_objects.iter().map(|s| s.as_str()).collect();
    let mut verified_issuers = vec![];
    let mut attestation_ids = vec![];
    let mut attestation_times = vec![];
    for a in &proof.attestations {
        let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(&a.content));
        let id = proof_crypto::id::attestation_id(&canon);
        if verified.contains(id.as_str()) && !status_objects.contains(id.as_str()) {
            verified_issuers.push(a.content.issuer.clone());
            attestation_times.push((a.content.issued_at, a.content.expires_at));
            attestation_ids.push(id);
        }
    }
    let superseded_ids = report
        .lifecycle
        .iter()
        .filter(|l| l.status == LifecycleStatus::Superseded)
        .filter_map(|l| l.object.strip_prefix("att:"))
        .map(str::to_string)
        .collect();
    Ok(VerifiedState {
        proof_id: rid.to_string(),
        crypto_valid: report.cryptographic_validity == Validity::Valid,
        evidence_valid: report.evidence_validity == Validity::Valid,
        verified_issuers,
        attestation_ids,
        attestation_times,
        superseded_ids,
        rel_types: proof
            .relationships
            .iter()
            .map(|r| r.rel_type.clone())
            .collect(),
        evidence_kinds: proof.evidence.iter().map(|e| e.kind.clone()).collect(),
        proof_created_at: proof.created_at,
    })
}
