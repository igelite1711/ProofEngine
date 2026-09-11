// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Batch verification (scale track).
//!
//! Verifies many proofs under one shared context in a single call. Each
//! member verifies **independently** with identical semantics to a lone
//! `verify_proof` call — batching amortizes invocation overhead (one
//! context, one report document), it never weakens verification: there is
//! no aggregate signature, no sampling, no short-circuit. A batch with one
//! invalid member still fully verifies every other member; independence is
//! pinned by test (`independence_holds_with_invalid_members`).
//!
//! Fail-closed: `complete == false` unless every member verified to a
//! report. `Err` only on caller misuse (the same conditions that make
//! `verify_proof` return `Err`) or an over-cap batch (`LIMIT_EXCEEDED`).

use crate::pipeline::{verify_proof, VerifyCtx};
use crate::report::VerifyReport;

/// One member result: index into the input slice, plus its report.
#[derive(Debug, Clone)]
pub struct BatchMember {
    pub index: usize,
    pub report: VerifyReport,
}

/// Batch outcome: per-member reports in input order plus aggregates.
/// `complete` is true only when every member produced a report.
#[derive(Debug, Clone)]
pub struct BatchReport {
    pub members: Vec<BatchMember>,
    /// Members with `cryptographic_validity == Valid`.
    pub crypto_valid_count: usize,
    /// Members with `evidence_validity == Valid`.
    pub evidence_valid_count: usize,
}

impl BatchReport {
    /// True when every input produced a report (members always cover all
    /// inputs on success — this is structural, use the counts for verdicts).
    pub fn complete(&self, inputs: usize) -> bool {
        self.members.len() == inputs
    }

    /// True when every member is crypto-Valid **and** evidence-Valid.
    /// Policy decisions stay caller-side per proof, as always.
    pub fn all_valid(&self) -> bool {
        !self.members.is_empty()
            && self.crypto_valid_count == self.members.len()
            && self.evidence_valid_count == self.members.len()
    }
}

/// Verify `canonicals` in order under the shared `ctx`, capped at
/// `max_batch_size` members (`LIMIT_EXCEEDED` beyond — bound the work
/// before doing it). Deterministic: member `i` equals `verify_proof`
/// of input `i` under the same context, byte-for-byte in the fields that
/// matter (pinned by `matches_sequential_verification`).
pub fn verify_batch(
    canonicals: &[Vec<u8>],
    ctx: &VerifyCtx,
    max_batch_size: usize,
) -> Result<BatchReport, proof_core::ProofError> {
    if canonicals.len() > max_batch_size {
        return Err(proof_core::ErrorCode::LimitExceeded.err(format!(
            "batch size {} > max_batch_size {}",
            canonicals.len(),
            max_batch_size
        )));
    }
    let mut members = Vec::with_capacity(canonicals.len());
    let mut crypto_valid_count = 0;
    let mut evidence_valid_count = 0;
    for (index, bytes) in canonicals.iter().enumerate() {
        // No short-circuit, no sampling: every member verifies fully even
        // when earlier members failed. `Err` propagates only on caller
        // misuse (identical ctx for all, so it would fail them all alike).
        let report = verify_proof(bytes, ctx)?;
        if report.cryptographic_validity == crate::report::Validity::Valid {
            crypto_valid_count += 1;
        }
        if report.evidence_validity == crate::report::Validity::Valid {
            evidence_valid_count += 1;
        }
        members.push(BatchMember { index, report });
    }
    Ok(BatchReport {
        members,
        crypto_valid_count,
        evidence_valid_count,
    })
}
