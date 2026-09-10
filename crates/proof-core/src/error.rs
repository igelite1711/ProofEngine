// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stable machine-readable error codes. Human messages may change; codes must not.
use thiserror::Error;

/// Stable error codes (V0.1). Codes are append-only once V0.1 ships; the three
/// graph codes below were added in Phase 3, before any release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Input was not deterministically encoded (re-encode mismatch).
    NonCanonical,
    /// CBOR map contained a duplicate key.
    DuplicateMapKey,
    /// Forbidden CBOR construct (float, tag, indefinite, bignum, reserved ai).
    ForbiddenCborConstruct,
    /// Recomputed object id did not match stated id.
    IdMismatch,
    /// COSE signature did not verify.
    SignatureInvalid,
    /// Algorithm number unknown to this verifier.
    UnknownAlgorithm,
    /// Algorithm known but deprecated (e.g. COSE -8/-7). Fail closed.
    DeprecatedAlgorithm,
    /// Object/proof/policy version not supported.
    UnsupportedVersion,
    /// A configured resource limit was exceeded.
    LimitExceeded,
    /// Structurally malformed (truncated, trailing bytes, bad UTF-8, odd map).
    Malformed,
    /// Base64url id component invalid.
    InvalidBase64Url,
    /// COSE header contained an unexpected label/value.
    UnexpectedHeaderParam,
    /// Key algorithm does not match attestation algorithm.
    AlgorithmConfusion,
    /// Schema violation (unknown enum variant, unknown field, missing field).
    SchemaViolation,
    /// Trust-relevant relationship lacks backing evidence/attestation.
    RelationshipUngrounded,
    /// Relationship endpoint or reference points at an unknown object.
    DanglingReference,
    /// Forbidden cycle detected (SUPERSEDES subgraph must be acyclic).
    CycleDetected,
    /// Policy file invalid (syntax, unknown requirement, bad version).
    /// Returned before any evaluation; never evaluated partially.
    PolicyInvalid,
    /// Attestation outside its validity window at the verifier clock
    /// (`issued_at > now+skew` or `now > expires_at+skew`).
    Expired,
    /// Attestation covered by a valid signed revocation (claim.type="revoke").
    Revoked,
    /// Revocation status cannot be established: no or stale revocation
    /// information was supplied. Fail closed, never PASS.
    RevocationUnknown,
    /// Signed status object (revoke/supersede) whose signer has no authority
    /// over its target (not the original issuer, not in `revocation_authorities`).
    UnauthorizedStatus,
}

impl ErrorCode {
    /// Stable wire string. Used in reports and golden vectors.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NonCanonical => "NON_CANONICAL",
            Self::DuplicateMapKey => "DUPLICATE_MAP_KEY",
            Self::ForbiddenCborConstruct => "FORBIDDEN_CBOR_CONSTRUCT",
            Self::IdMismatch => "ID_MISMATCH",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::UnknownAlgorithm => "UNKNOWN_ALGORITHM",
            Self::DeprecatedAlgorithm => "DEPRECATED_ALGORITHM",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::Malformed => "MALFORMED",
            Self::InvalidBase64Url => "INVALID_BASE64URL",
            Self::UnexpectedHeaderParam => "UNEXPECTED_HEADER_PARAM",
            Self::AlgorithmConfusion => "ALGORITHM_CONFUSION",
            Self::SchemaViolation => "SCHEMA_VIOLATION",
            Self::RelationshipUngrounded => "RELATIONSHIP_UNGROUNDED",
            Self::DanglingReference => "DANGLING_REFERENCE",
            Self::CycleDetected => "CYCLE_DETECTED",
            Self::PolicyInvalid => "POLICY_INVALID",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::RevocationUnknown => "REVOCATION_UNKNOWN",
            Self::UnauthorizedStatus => "UNAUTHORIZED_STATUS",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("[{code}] {message}")]
pub struct ProofError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProofError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }
}

impl ErrorCode {
    pub fn err(self, message: impl Into<String>) -> ProofError {
        ProofError::new(self, message)
    }
}
