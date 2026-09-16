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

    /// Transitive ancestry: every proof id reachable from the root through
    /// composition linkage, with shallowest depth, ordered by (depth, id).
    /// Includes named-but-unavailable references — ancestry is structural
    /// (the linkage names them), independent of availability.
    pub fn ancestors(&self) -> Vec<Ancestor> {
        use std::collections::BTreeMap;
        let mut depths: BTreeMap<&str, (usize, bool)> = BTreeMap::new();
        for r in &self.resolved {
            depths
                .entry(r.id.as_str())
                .and_modify(|e| {
                    e.0 = e.0.min(r.depth);
                    e.1 = true;
                })
                .or_insert((r.depth, true));
        }
        for u in &self.unresolved {
            depths.entry(u.id.as_str()).or_insert((u.depth, false));
        }
        let mut out: Vec<Ancestor> = depths
            .into_iter()
            .map(|(id, (depth, resolved))| Ancestor {
                id: id.to_string(),
                depth,
                resolved,
            })
            .collect();
        out.sort_by(|a, b| (a.depth, &a.id).cmp(&(b.depth, &b.id)));
        out
    }
}

/// One transitive ancestor: id, shallowest BFS depth from the root, and
/// whether bytes were fetched and verified (`false` = named in linkage but
/// unavailable/mismatched/too deep/over budget — see `unresolved`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub id: String,
    pub depth: usize,
    pub resolved: bool,
}

/// Reverse traversal: ids of `candidates` whose transitive composition
/// closure contains `target` (proper descendants only — a proof is never
/// its own descendant).
///
/// The candidate set is explicit because stores are not enumerable (the
/// `ArtifactStore` seam has no listing operation by design): callers pass
/// the sibling proofs under consideration (e.g. a bundle's members).
/// Each candidate verifies under `ctx` exactly as `resolve_proof_chain`
/// would verify it; candidates that fail to verify are skipped, never
/// assumed. Returns ids sorted ascending.
pub fn descendants_of(
    target: &str,
    candidates: &[Vec<u8>],
    store: &impl ArtifactStore,
    ctx: &VerifyCtx,
    max_transitive_depth: usize,
) -> Result<Vec<String>, ProofError> {
    use proof_format::store::MemoryStore;
    let mut mem = MemoryStore::new();
    let mut ids = Vec::new();
    for bytes in candidates {
        let report = verify_proof(bytes, ctx)?;
        if let Some(id) = report.proof_id.clone() {
            // MemoryStore rejects same-id-different-bytes (equivocation);
            // surface that as a caller error rather than silently picking.
            mem.put(&id, bytes.clone()).map_err(|e| {
                proof_core::ErrorCode::SchemaViolation.err(format!("descendants_of: {e}"))
            })?;
            ids.push(id);
        }
    }
    // Candidates may reference proofs outside the candidate set, which the
    // passed store may hold: resolve against the union, callers first.
    let union = UnionStore { a: &mem, b: store };
    let mut out = Vec::new();
    for id in &ids {
        if id == target {
            continue; // proper descendants only
        }
        let bytes = union.get(id).map_err(|e| {
            proof_core::ErrorCode::SchemaViolation.err(format!("descendants_of: {e}"))
        })?;
        let bytes = bytes.ok_or_else(|| {
            proof_core::ErrorCode::SchemaViolation
                .err("descendants_of: candidate vanished from union store")
        })?;
        let rep = resolve_proof_chain(&bytes, &union, ctx, max_transitive_depth)?;
        if rep.ancestors().iter().any(|a| a.id == target) {
            out.push(id.clone());
        }
    }
    out.sort();
    Ok(out)
}

/// Read union of two stores (first hit wins), with equivocation detection:
/// the same id held with different bytes under each side is corruption,
/// surfaced as a store error rather than a silent pick.
struct UnionStore<'a, A: ArtifactStore, B: ArtifactStore> {
    a: &'a A,
    b: &'a B,
}

impl<A: ArtifactStore, B: ArtifactStore> ArtifactStore for UnionStore<'_, A, B> {
    fn put(&mut self, _id: &str, _cbor: Vec<u8>) -> Result<(), String> {
        Err("union store is read-only".into())
    }

    fn get(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        let from_a = self.a.get(id)?;
        let from_b = self.b.get(id)?;
        match (from_a, from_b) {
            (Some(a), Some(b)) if a != b => Err(format!(
                "store equivocation: {id} held with different bytes on each side"
            )),
            (Some(a), _) => Ok(Some(a)),
            (None, b) => Ok(b),
        }
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
