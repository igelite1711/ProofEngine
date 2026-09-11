// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transitive proof-linkage resolution (bundle layer, P4).
//!
//! The core pipeline validates linkage as topology only (shape, sortedness,
//! id binding, no self-reference) and reports every reference as REFERENCED:
//! referenced content contributes **nothing** to validity. This module is the
//! optional bundle-layer counterpart: given a root proof and an
//! [`ArtifactStore`], it fetches every transitively referenced proof,
//! re-verifies each from its own canonical bytes, and reports an explicit
//! availability matrix with depth accounting.
//!
//! Frozen-semantics guarantee: resolution never changes any verdict. The
//! root report is reproduced verbatim; this layer only *names* what the
//! linkage points at. Anything short of fully-resolved is `complete == false`
//! (fail closed for callers), never valid-by-assumption.
//!
//! Termination: content-addressed ids make genuine reference cycles
//! unconstructible (a cycle would require a hash preimage loop), and
//! self-references are refused by the core. A visited set additionally
//! dedupes diamond references, `max_transitive_depth` bounds chain length,
//! and a fan-out budget bounds total fetches — all fail closed, never
//! silent.

use std::collections::{HashSet, VecDeque};

use proof_core::{Limits, ProofError};
use proof_format::store::ArtifactStore;

use crate::pipeline::{verify_proof, VerifyCtx};
use crate::report::VerifyReport;

/// Why a referenced proof could not be produced as a verified report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReason {
    /// No bytes under this id in the store. Absence is data: callers must
    /// treat dependents as INDETERMINATE, never valid.
    Unavailable,
    /// Bytes were found but do not verify as the requested id (tamper or
    /// store equivocation: same id, different bytes). The found id (or
    /// `<unparseable>`) is carried for diagnostics.
    IdMismatch { found: String },
    /// The reference sits beyond `max_transitive_depth` from the root.
    /// Named, not fetched.
    DepthExceeded,
    /// The fan-out budget (`depth × max_referenced_proofs + 1` fetches) ran
    /// out first. Named, not fetched.
    OverBudget,
    /// The store itself errored (I/O, permissions). Transport failure is
    /// infrastructure, never a verdict — recorded, not hidden.
    Store(String),
}

/// A transitively referenced proof, fetched and re-verified.
#[derive(Debug, Clone)]
pub struct ResolvedProof {
    pub id: String,
    /// BFS distance from the root (direct references are depth 1).
    pub depth: usize,
    pub report: VerifyReport,
}

/// A reference that could not be resolved, with its depth and reason.
#[derive(Debug, Clone)]
pub struct UnresolvedRef {
    pub id: String,
    pub depth: usize,
    pub reason: UnresolvedReason,
}

/// The root report plus the transitive availability matrix.
#[derive(Debug, Clone)]
pub struct ResolutionReport {
    /// The root proof verified exactly as `verify_proof` reports it.
    pub root: VerifyReport,
    pub resolved: Vec<ResolvedProof>,
    pub unresolved: Vec<UnresolvedRef>,
}

impl ResolutionReport {
    /// True only when every transitively reachable reference resolved to a
    /// verified report. Anything else is fail-closed for callers — never
    /// valid-by-assumption. (Completeness is about *availability*, not
    /// about the fetched proofs' own validity: inspect each `report`.)
    pub fn complete(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// Resolve `root_canonical`'s transitive `referenced_proofs` against `store`.
///
/// * `ctx` is reused for every fetched proof (same clock, trust, status,
///   limits), so all reports are comparable.
/// * `max_transitive_depth`: how far from the root to follow (0 = root only;
///   direct references named `DepthExceeded`).
///
/// Returns `Err` only on caller misuse (the same conditions that make
/// `verify_proof` itself return `Err`, e.g. `allow_remote`). Every other
/// outcome — absence, mismatch, depth, budget, store failure — is recorded
/// in the report with `complete == false`.
pub fn resolve_proof_chain(
    root_canonical: &[u8],
    store: &impl ArtifactStore,
    ctx: &VerifyCtx,
    max_transitive_depth: usize,
) -> Result<ResolutionReport, ProofError> {
    let root = verify_proof(root_canonical, ctx)?;
    let budget = budget(ctx.limits, max_transitive_depth);
    let mut visited: HashSet<String> = HashSet::new();
    if let Some(id) = root.proof_id.clone() {
        visited.insert(id);
    }
    let mut queue: VecDeque<(String, usize)> = root
        .referenced_proofs
        .iter()
        .map(|id| (id.clone(), 1))
        .collect();
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    while let Some((id, depth)) = queue.pop_front() {
        if !visited.insert(id.clone()) {
            continue; // diamond reference: already recorded once
        }
        if depth > max_transitive_depth {
            unresolved.push(UnresolvedRef {
                id,
                depth,
                reason: UnresolvedReason::DepthExceeded,
            });
            continue;
        }
        if resolved.len() + unresolved.len() >= budget {
            unresolved.push(UnresolvedRef {
                id,
                depth,
                reason: UnresolvedReason::OverBudget,
            });
            continue;
        }
        let bytes = match store.get(&id) {
            Ok(opt) => opt,
            Err(e) => {
                unresolved.push(UnresolvedRef {
                    id,
                    depth,
                    reason: UnresolvedReason::Store(e),
                });
                continue;
            }
        };
        let bytes = match bytes {
            Some(b) => b,
            None => {
                unresolved.push(UnresolvedRef {
                    id,
                    depth,
                    reason: UnresolvedReason::Unavailable,
                });
                continue;
            }
        };
        // Same context, same rules: fetched proofs verify exactly as if
        // passed to verify_proof directly. Caller-misuse Err propagates
        // (it would equally fail the root call).
        let report = verify_proof(&bytes, ctx)?;
        if report.proof_id.as_deref() != Some(id.as_str()) {
            unresolved.push(UnresolvedRef {
                id,
                depth,
                reason: UnresolvedReason::IdMismatch {
                    found: report
                        .proof_id
                        .clone()
                        .unwrap_or_else(|| "<unparseable>".into()),
                },
            });
            continue;
        }
        for child in &report.referenced_proofs {
            queue.push_back((child.clone(), depth + 1));
        }
        resolved.push(ResolvedProof { id, depth, report });
    }

    Ok(ResolutionReport {
        root,
        resolved,
        unresolved,
    })
}

/// Total-fetch budget: worst-case fan-out times depth, plus the root.
/// Bounded before allocation-heavy work (DoS prevention); overflow fails
/// closed as `OverBudget`, never silent truncation.
fn budget(limits: Limits, max_transitive_depth: usize) -> usize {
    max_transitive_depth
        .saturating_mul(limits.max_referenced_proofs)
        .saturating_add(1)
        .max(1)
}
