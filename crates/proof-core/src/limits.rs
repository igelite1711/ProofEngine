// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Enforced resource limits (not advisory). All configurable downward.

/// All limits enforced in decoders, graph validation, and policy evaluation.
#[derive(Debug, Clone, Copy)]
// PE-SEC-001 · PE-FMT-006: enforced bounds, not advisories.
pub struct Limits {
    pub max_proof_size: usize,
    pub max_field_size: usize,
    pub max_depth: usize,
    pub max_array_items: usize,
    pub max_map_entries: usize,
    pub max_evidence_items: usize,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_sig_size: usize,
    pub max_policy_requirements: usize,
    // V1.1: VerifyCtx input vector bounds (DoS prevention)
    pub max_status_objects: usize,
    pub max_trusted_issuers: usize,
    pub max_revocation_authorities: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_proof_size: 1024 * 1024, // 1 MiB
            max_field_size: 64 * 1024,   // 64 KiB per text/bytes field
            max_depth: 16,
            max_array_items: 256,
            max_map_entries: 64,
            max_evidence_items: 64,
            max_nodes: 128,
            max_edges: 256,
            max_sig_size: 256,
            max_policy_requirements: 32,
            // V1.1: VerifyCtx input bounds
            max_status_objects: 64,
            max_trusted_issuers: 32,
            max_revocation_authorities: 16,
        }
    }
}
