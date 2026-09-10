// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verification report: three distinct outcomes, never collapsed.
//! Every record is derived from actual verification state (explainability basis).

use proof_core::{ErrorCode, LifecycleStatus};

/// One outcome dimension: valid or invalid. There is no "unknown-as-valid":
/// stages that cannot establish validity record `ok: false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Valid,
    Invalid,
}

/// Policy decision. Phase 4 always yields `Indeterminate` (no policy engine yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Pass,
    Fail,
    Indeterminate,
}

impl PolicyDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// One stage check. Machine-readable (`stage` + `code`) first, human text last.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    /// Pipeline stage, e.g. "SIGNATURES".
    pub stage: &'static str,
    /// Object the check concerns (`proof:<id>`, `att:<id>`, stage name if global).
    pub object: String,
    pub ok: bool,
    /// Stable code for failures; `None` for passing/informational records.
    pub code: Option<ErrorCode>,
    pub message: String,
}

impl CheckRecord {
    pub fn ok(stage: &'static str, object: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage,
            object: object.into(),
            ok: true,
            code: None,
            message: message.into(),
        }
    }

    pub fn fail(
        stage: &'static str,
        object: impl Into<String>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            object: object.into(),
            ok: false,
            code: Some(code),
            message: message.into(),
        }
    }

    /// Informational record: true statement about the run, not a check result.
    pub fn note(
        stage: &'static str,
        object: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            object: object.into(),
            ok: true,
            code: None,
            message: message.into(),
        }
    }
}

/// Per-attestation lifecycle outcome (TIME/REVOCATION stages). Exists so the
/// ACTIVE/EXPIRED/REVOKED/SUPERSEDED/UNKNOWN state machine is inspectable
/// without re-deriving it from check text.
#[derive(Debug, Clone)]
pub struct LifecycleRecord {
    /// Attestation id (`att:<id>`) the status concerns.
    pub object: String,
    pub status: LifecycleStatus,
    /// Failure code for `Expired`/`Revoked`/`Unknown`; `None` for `Active`
    /// and `Superseded` (historical note preserved).
    pub code: Option<ErrorCode>,
    pub message: String,
}

/// Full verification output.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Recomputed proof id, or `None` when the envelope never parsed.
    pub proof_id: Option<String>,
    /// "Is the cryptographic material internally valid?"
    pub cryptographic_validity: Validity,
    /// "Is the evidence consistent, connected, and timely?" — timeliness and
    /// revocation are stages TIME/REVOCATION (Phase 6): `Expired`/`Revoked`/
    /// `Unknown` flip this to `Invalid`; `Superseded` keeps it `Valid` with a
    /// historical note.
    pub evidence_validity: Validity,
    /// "Does the evidence satisfy the requested policy?" The pipeline never
    /// evaluates policy itself; it reports `Indeterminate` and the caller runs
    /// `proof-policy::evaluate_policy` on the verified state.
    pub policy_decision: PolicyDecision,
    /// True once stages TIME+REVOCATION ran (Phase 6). Early exits (parse/
    /// schema/canonical failures) leave it false.
    pub lifecycle_checked: bool,
    /// Per-attestation lifecycle status, one entry per signature-verified
    /// statement attestation.
    pub lifecycle: Vec<LifecycleRecord>,
    /// Ids of signature-verified embedded *status* attestations (revoke/
    /// supersede claims), in proof order. Caller-supplied status objects are
    /// not proof members and never appear here. Consumers (e.g. policy state
    /// projection) must never treat a status attestation as a statement.
    pub status_objects: Vec<String>,
    pub checks: Vec<CheckRecord>,
}

impl VerifyReport {
    /// All failure codes in stage order (convenience for tests and CLI).
    pub fn failure_codes(&self) -> Vec<ErrorCode> {
        self.checks
            .iter()
            .filter(|c| !c.ok)
            .filter_map(|c| c.code)
            .collect()
    }

    pub fn passed_crypto(&self) -> bool {
        self.cryptographic_validity == Validity::Valid
    }
}
