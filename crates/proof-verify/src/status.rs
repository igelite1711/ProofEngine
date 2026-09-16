// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Status sources (P3/P7): registry contract for revocation/transparency
//! adapters. The offline default (caller-supplied `Vec<SignedStatus>`) is
//! unchanged; adapters implement this trait to serve status from files,
//! transparency logs, or callbacks without changing core semantics.

use proof_core::ProofError;
use proof_crypto::SignedStatus;

/// A source of signed status objects (revoke/supersede attestations).
/// Implementations must return only signature-bearing objects; unsigned lists
/// are never trusted (pipeline re-verifies every object end-to-end).
pub trait StatusSource {
    /// Status objects known at `as_of` (Unix seconds), if the source tracks time.
    fn status_at(&self, as_of: u64) -> Result<Vec<SignedStatus>, ProofError>;

    /// When this source's information was last refreshed, if known.
    /// `None` means freshness unknown ⇒ pipeline reports UNKNOWN (fail closed).
    fn known_at(&self) -> Option<u64> {
        None
    }
}

/// In-memory source: the V1 offline default.
#[derive(Debug, Clone, Default)]
pub struct VecStatusSource {
    pub objects: Vec<SignedStatus>,
    pub known_at: Option<u64>,
}

impl VecStatusSource {
    pub fn new(objects: Vec<SignedStatus>, known_at: Option<u64>) -> Self {
        Self { objects, known_at }
    }
}

impl StatusSource for VecStatusSource {
    fn status_at(&self, _as_of: u64) -> Result<Vec<SignedStatus>, ProofError> {
        Ok(self.objects.clone())
    }

    fn known_at(&self) -> Option<u64> {
        self.known_at
    }
}
