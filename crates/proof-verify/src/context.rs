// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unified verification context (PROOF-ENGINE-SPEC §14, AUDIT F6).
//!
//! V1 has two overlapping structs (`VerifyCtx` for the pipeline,
//! `EvalInputs` for policy). This value object is the single normative shape;
//! both existing structs become thin projections so no wire or API break
//! occurs. Context is echoed in reports, never stored, never trusted.

use proof_core::Limits;
use proof_crypto::{AllowedAlgs, SignedStatus};

use crate::pipeline::VerifyCtx;
use crate::status::StatusSource;

/// Single normative verification context.
///
/// A proof contains facts; the verifier supplies everything the verdict
/// depends on that is not in the proof bytes.
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Unix seconds from a caller-trustworthy clock. `0` = no trustworthy
    /// clock (fail-closed sentinel: every timeliness check fails).
    pub verified_at: u64,
    /// Honest clock drift budget (default 300s, saturating both bounds).
    pub clock_skew_leeway: u64,
    /// Closed algorithm registry switches.
    pub allowed_algs: AllowedAlgs,
    /// Issuer keyrefs trusted *by this verifier at this time*.
    pub trusted_issuers: Vec<String>,
    /// Keyrefs empowered to sign status over any target.
    pub revocation_authorities: Vec<String>,
    /// Caller-supplied signed revoke/supersede objects (never plain id lists).
    pub status_objects: Vec<SignedStatus>,
    /// When revocation info was obtained. `None` or stale ⇒ UNKNOWN ⇒ fail closed.
    pub revocations_known_at: Option<u64>,
    /// Resource bounds.
    pub limits: Limits,
    /// V1 is always false: the verifier performs zero network I/O.
    pub allow_remote: bool,
    /// Fail-collect vs fail-fast diagnostics.
    pub report_all_failures: bool,
    /// Accepted label vocabularies (namespace → max version). Empty default.
    pub accepted_vocabularies: Vec<proof_core::model::VocabularyAccept>,
    /// Extra trust-relevant edge types beyond the V1 `requires_grounding()`
    /// set. Empty (default) = V1 defaults. Future vocabularies declare their
    /// own trust-relevant kinds here without a core change (AUDIT §5).
    pub extra_grounded: Vec<String>,
    /// Provenance DAG profile (V1.1 F4, default false). When true the full
    /// member graph must be acyclic, not just SUPERSEDES.
    pub require_acyclic_provenance: bool,
    /// Fail-closed empty-feed gate (default true since pre-launch core
    /// audit). False only for explicit caller-asserted absence.
    pub require_status_feed: bool,
}

impl Default for VerificationContext {
    fn default() -> Self {
        Self {
            verified_at: 0,
            clock_skew_leeway: 300,
            allowed_algs: AllowedAlgs::strict(),
            trusted_issuers: vec![],
            revocation_authorities: vec![],
            status_objects: vec![],
            revocations_known_at: None,
            limits: Limits::default(),
            allow_remote: false,
            report_all_failures: false,
            accepted_vocabularies: vec![],
            extra_grounded: vec![],
            require_acyclic_provenance: false,
            require_status_feed: true,
        }
    }
}

impl VerificationContext {
    /// Thin projection: pipeline inputs.
    pub fn to_verify_ctx(&self) -> VerifyCtx {
        VerifyCtx {
            verified_at: self.verified_at,
            clock_skew_leeway: self.clock_skew_leeway,
            trusted_issuers: self.trusted_issuers.clone(),
            allow_remote: self.allow_remote,
            allowed_algs: self.allowed_algs,
            limits: self.limits,
            status_objects: self.status_objects.clone(),
            revocation_authorities: self.revocation_authorities.clone(),
            revocations_known_at: self.revocations_known_at,
            report_all_failures: self.report_all_failures,
            accepted_vocabularies: self.accepted_vocabularies.clone(),
            extra_grounded: self.extra_grounded.clone(),
            require_acyclic_provenance: self.require_acyclic_provenance,
            require_status_feed: self.require_status_feed,
        }
    }

    /// Populate signed status inputs from a `StatusSource` adapter
    /// (files, transparency logs, callbacks). The offline default is
    /// unchanged: callers that already supply `status_objects` directly
    /// never call this. Objects are still re-verified end-to-end by the
    /// pipeline; the source is never trusted.
    pub fn with_status_source<S: StatusSource>(
        mut self,
        source: &S,
    ) -> Result<Self, proof_core::ProofError> {
        let objects = source.status_at(self.verified_at)?;
        self.status_objects = objects;
        if self.revocations_known_at.is_none() {
            self.revocations_known_at = source.known_at();
        }
        Ok(self)
    }
}

impl From<&VerificationContext> for VerifyCtx {
    fn from(ctx: &VerificationContext) -> Self {
        ctx.to_verify_ctx()
    }
}
