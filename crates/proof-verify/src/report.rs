// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verification report: three distinct outcomes, never collapsed.
//! Every record is derived from actual verification state (explainability basis).

use proof_core::model::{EvidenceStatus, VocabularyDecl};
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

/// Per-evidence status outcome (EVIDENCE stage). Derived from availability,
/// the backing attestation's lifecycle, withdrawals, and compromises.
/// Informational derivation: validity verdicts follow the same fail records
/// (WITHDRAWN/COMPROMISED/REVOKED/UNKNOWN flip evidence validity; SUPERSEDED
/// and EXPIRED preserve the attestation-level convention).
#[derive(Debug, Clone)]
pub struct EvidenceStatusRecord {
    /// Evidence id (`evd:<id>`) the status concerns.
    pub object: String,
    pub status: EvidenceStatus,
    /// Failure code for withdrawn/compromised/revoked/unknown; `None` for
    /// available (and superseded, history preserved). Mirrors the
    /// attestation-level `Expired`-is-ok quirk for expired backing.
    pub code: Option<ErrorCode>,
    pub message: String,
}

/// How a conflict was established. Divergent claims are detected
/// structurally; denials and contradictions are explicit assertions.
/// All three are representation only — policy adjudicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    /// Same `(claim.type, subject)`, differing fields, among verified
    /// statements. Corroboration (identical re-assertion) is excluded.
    DivergentClaims,
    /// A verified statement carries `denies: <attestation-id>` targeting
    /// another verified statement.
    Denial,
    /// A grounded `CONTRADICTS` edge connects two verified statements.
    Contradiction,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DivergentClaims => "divergent_claims",
            Self::Denial => "denial",
            Self::Contradiction => "contradiction",
        }
    }
}

/// Divergent assertions requiring caller adjudication (SPEC §17).
/// Two or more signature-verified *statement* attestations share the same
/// `(claim.type, subject)` but carry different claim fields. The core records
/// the divergence and arbitrates nothing: verification validity is unchanged,
/// and policy/context decides (preferred issuer, threshold, recency,
/// corroboration, human decision). Status attestations (revoke/supersede/
/// withdraw/compromise) are lifecycle, never conflicts. Cross-type semantic
/// contradictions (same fact encoded under different claim types) remain the
/// domain/policy's job — the core surfaces structural divergence only,
/// plus explicit `denies`/`CONTRADICTS` opposition as stated.
#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub kind: ConflictKind,
    pub claim_type: String,
    pub subject: String,
    /// `att:<id>` of each involved attestation, sorted ascending.
    pub attestation_ids: Vec<String>,
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
    /// supersede/withdraw/compromise claims), in proof order. Caller-supplied
    /// status objects are not proof members and never appear here. Consumers
    /// (e.g. policy state projection) must never treat a status attestation
    /// as a statement.
    pub status_objects: Vec<String>,
    /// Artifact ids covered by *applied* (authorized, timely) withdrawals.
    /// Policy uses this for evidence/adjudication decisions.
    pub withdrawn_ids: Vec<String>,
    /// Composition linkage carried by the verified proof (possibly empty).
    /// Linkage only: referenced content is never fetched and contributes
    /// nothing to validity. Empty when the envelope never parsed.
    pub referenced_proofs: Vec<String>,
    /// Declared vocabularies carried by the verified proof (possibly empty).
    /// Declaration is provenance, not permission; acceptance is policy.
    /// Empty when the envelope never parsed.
    pub vocabularies: Vec<VocabularyDecl>,
    /// Per-evidence derived status (possibly empty on early exit).
    pub evidence_status: Vec<EvidenceStatusRecord>,
    /// Structural divergence groups (possibly empty). Representation only:
    /// never changes validity by itself; policy adjudicates.
    pub conflicts: Vec<ConflictRecord>,
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

    /// Additive dimensioned projection (PROOF-ENGINE-SPEC §9.2, P2).
    /// The v1 triple is preserved; this derives per-dimension verdicts from
    /// existing stage records without changing any verification semantics.
    /// Aggregation: any INVALID in an applicable dimension ⇒ overall INVALID;
    /// any INDETERMINATE (and no INVALID) ⇒ overall INDETERMINATE;
    /// NOT_APPLICABLE never fails on its own.
    pub fn dimensions(&self) -> Vec<(Dimension, Verdict)> {
        let verdict_for = |stages: &[&str], empty_ok: bool, empty_verdict: Verdict| -> Verdict {
            let relevant: Vec<&CheckRecord> = self
                .checks
                .iter()
                .filter(|c| stages.contains(&c.stage))
                .collect();
            // No records and no lifecycle input for this dimension.
            if relevant.is_empty() {
                return if empty_ok {
                    Verdict::Valid
                } else {
                    empty_verdict
                };
            }
            if relevant.iter().any(|c| !c.ok) {
                // Distinguish hard failure from unknown-where-applicable:
                // REVOCATION/TIME unknowns surface as INDETERMINATE at the
                // overall layer via evidence_validity, but per-dimension they
                // are INVALID (a check failed). Callers needing the
                // unknown-vs-broken distinction inspect lifecycle/codes.
                return Verdict::Invalid;
            }
            Verdict::Valid
        };

        let structural = verdict_for(
            &["PARSE", "SCHEMA", "CANONICAL"],
            false,
            Verdict::Indeterminate,
        );
        let cryptographic = verdict_for(
            &["IDENTIFIERS", "SIGNATURES", "KEYS"],
            false,
            Verdict::Indeterminate,
        );
        let evidence = match self.evidence_validity {
            Validity::Valid => Verdict::Valid,
            Validity::Invalid => {
                // Missing lifecycle info (early exit) means we cannot
                // distinguish broken from unknown → INDETERMINATE, never Valid.
                if !self.lifecycle_checked {
                    Verdict::Indeterminate
                } else {
                    Verdict::Invalid
                }
            }
        };
        let provenance = {
            // Early exit (no lifecycle) means relationship/graph state is
            // unknown, not vacuously absent: report INDETERMINATE like the
            // evidence dimension above, never NOT_APPLICABLE.
            if !self.lifecycle_checked {
                Verdict::Indeterminate
            } else {
                let rel: Vec<&CheckRecord> = self
                    .checks
                    .iter()
                    .filter(|c| c.stage == "RELATIONSHIPS" || c.stage == "GRAPH")
                    .collect();
                if rel.is_empty() {
                    Verdict::NotApplicable
                } else if rel.iter().any(|c| !c.ok) {
                    Verdict::Invalid
                } else {
                    Verdict::Valid
                }
            }
        };
        let temporal = verdict_for(&["TIME"], false, Verdict::Indeterminate);
        let revocation = verdict_for(&["REVOCATION"], false, Verdict::Indeterminate);
        let policy = match self.policy_decision {
            PolicyDecision::Pass => Verdict::Valid,
            PolicyDecision::Fail => Verdict::Invalid,
            PolicyDecision::Indeterminate => Verdict::Indeterminate,
        };
        let overall = if [
            structural,
            cryptographic,
            evidence,
            provenance,
            temporal,
            revocation,
            policy,
        ]
        .contains(&Verdict::Invalid)
        {
            Verdict::Invalid
        } else if [
            structural,
            cryptographic,
            evidence,
            temporal,
            revocation,
            policy,
        ]
        .contains(&Verdict::Indeterminate)
        {
            // NOT_APPLICABLE provenance never forces INDETERMINATE alone.
            Verdict::Indeterminate
        } else {
            Verdict::Valid
        };

        vec![
            (Dimension::Structural, structural),
            (Dimension::Cryptographic, cryptographic),
            (Dimension::Evidence, evidence),
            (Dimension::Provenance, provenance),
            (Dimension::Temporal, temporal),
            (Dimension::Revocation, revocation),
            (Dimension::Policy, policy),
            (Dimension::Overall, overall),
        ]
    }
}

/// Verification dimension (PROOF-ENGINE-SPEC §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dimension {
    Structural,
    Cryptographic,
    Evidence,
    Provenance,
    Temporal,
    Revocation,
    Policy,
    Overall,
}

impl Dimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Cryptographic => "cryptographic",
            Self::Evidence => "evidence",
            Self::Provenance => "provenance",
            Self::Temporal => "temporal",
            Self::Revocation => "revocation",
            Self::Policy => "policy",
            Self::Overall => "overall",
        }
    }
}

/// Per-dimension verdict. v1 triple maps: Valid/Invalid directly;
/// pipeline-only INDETERMINATE (policy never evaluated by pipeline);
/// NOT_APPLICABLE when a dimension has no input (e.g. provenance with no
/// edges) and must not itself fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    Valid,
    Invalid,
    Indeterminate,
    NotApplicable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Indeterminate => "indeterminate",
            Self::NotApplicable => "not_applicable",
        }
    }
}
