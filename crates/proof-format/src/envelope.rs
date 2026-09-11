// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Portable artifact envelope (PROOF-ENGINE-SPEC §15, P3).
//!
//! Standardizes the ad-hoc CLI `{"kind","id","cbor":hex}` JSON so all
//! languages exchange the same files. JSON is transport only — never signed,
//! never canonical. Consumers MUST re-derive `id` (and `sign1` where present)
//! from `cbor`; advisory fields are never trusted.

use proof_core::{ErrorCode, Limits, ProofError};

/// Envelope container version (independent from object `v`).
pub const CONTAINER_VERSION: u32 = 1;

/// Artifact kinds carried by the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Event,
    Attestation,
    Evidence,
    Relationship,
    Proof,
    Status,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Attestation => "attestation",
            Self::Evidence => "evidence",
            Self::Relationship => "relationship",
            Self::Proof => "proof",
            Self::Status => "status",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "event" => Some(Self::Event),
            "attestation" => Some(Self::Attestation),
            "evidence" => Some(Self::Evidence),
            "relationship" => Some(Self::Relationship),
            "proof" => Some(Self::Proof),
            "status" => Some(Self::Status),
            _ => None,
        }
    }
}

/// Portable envelope. `id`/`sign1_b64u` are advisory.
#[derive(Debug, Clone)]
pub struct ArtifactEnvelope {
    pub container_version: u32,
    pub kind: ArtifactKind,
    pub id: String,
    /// Lowercase hex of canonical CBOR bytes.
    pub cbor_hex: String,
    /// Attestations/status only: base64url COSE_Sign1 (advisory).
    pub sign1_b64u: Option<String>,
}

impl ArtifactEnvelope {
    pub fn new(
        kind: ArtifactKind,
        id: impl Into<String>,
        cbor: &[u8],
        sign1_b64u: Option<String>,
    ) -> Self {
        Self {
            container_version: CONTAINER_VERSION,
            kind,
            id: id.into(),
            cbor_hex: hex::encode(cbor),
            sign1_b64u,
        }
    }

    pub fn cbor_bytes(&self, limits: &Limits) -> Result<Vec<u8>, ProofError> {
        let raw = hex::decode(self.cbor_hex.trim())
            .map_err(|_| ErrorCode::Malformed.err("envelope cbor_hex is not hex"))?;
        if raw.len() > limits.max_proof_size {
            return Err(ErrorCode::LimitExceeded.err("envelope cbor exceeds max_proof_size"));
        }
        if raw.is_empty() {
            return Err(ErrorCode::Malformed.err("envelope cbor is empty"));
        }
        Ok(raw)
    }
}
