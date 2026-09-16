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
    // Composition: bound on `referenced_proofs` entries per proof (DoS
    // prevention; each entry is a 50-char id string).
    pub max_referenced_proofs: usize,
    // Vocabulary declarations per proof (DoS prevention).
    pub max_vocabularies: usize,
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
            max_referenced_proofs: 16,
            max_vocabularies: 16,
        }
    }
}

impl Limits {
    /// Validate a custom limit set: all bounds must be non-zero and not
    /// exceed the compiled default (downward-only, DoS prevention). Returns
    /// the same limits on success so callers can write
    /// `Limits { max_nodes: 16, ..Default::default() }.checked()?`.
    pub fn checked(self) -> Result<Self, crate::ProofError> {
        let d = Self::default();
        let pairs = [
            ("max_proof_size", self.max_proof_size, d.max_proof_size),
            ("max_field_size", self.max_field_size, d.max_field_size),
            ("max_depth", self.max_depth, d.max_depth),
            ("max_array_items", self.max_array_items, d.max_array_items),
            ("max_map_entries", self.max_map_entries, d.max_map_entries),
            (
                "max_evidence_items",
                self.max_evidence_items,
                d.max_evidence_items,
            ),
            ("max_nodes", self.max_nodes, d.max_nodes),
            ("max_edges", self.max_edges, d.max_edges),
            ("max_sig_size", self.max_sig_size, d.max_sig_size),
            (
                "max_policy_requirements",
                self.max_policy_requirements,
                d.max_policy_requirements,
            ),
            (
                "max_status_objects",
                self.max_status_objects,
                d.max_status_objects,
            ),
            (
                "max_trusted_issuers",
                self.max_trusted_issuers,
                d.max_trusted_issuers,
            ),
            (
                "max_revocation_authorities",
                self.max_revocation_authorities,
                d.max_revocation_authorities,
            ),
            (
                "max_referenced_proofs",
                self.max_referenced_proofs,
                d.max_referenced_proofs,
            ),
            (
                "max_vocabularies",
                self.max_vocabularies,
                d.max_vocabularies,
            ),
        ];
        for (name, got, max) in pairs {
            if got == 0 || got > max {
                return Err(crate::ErrorCode::LimitExceeded
                    .err(format!("Limits::{name}={got} out of bounds (1..={max})")));
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_accepts_default_and_downward() {
        assert!(Limits::default().checked().is_ok());
        let tight = Limits {
            max_nodes: 16,
            ..Limits::default()
        };
        assert!(tight.checked().is_ok());
    }

    #[test]
    fn checked_rejects_zero_and_upward() {
        let zero = Limits {
            max_nodes: 0,
            ..Limits::default()
        };
        let err = zero.checked().unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::LimitExceeded);
        let huge = Limits {
            max_nodes: 10_000,
            ..Limits::default()
        };
        let err = huge.checked().unwrap_err();
        assert_eq!(err.code, crate::ErrorCode::LimitExceeded);
    }
}
