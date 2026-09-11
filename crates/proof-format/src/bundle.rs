// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bundle convention (SPEC §8): the portable unit of exchange.
//!
//! A bundle carries proofs plus the external bytes their digests name, so a
//! proof can travel with its evidence without changing the core: digests stay
//! mandatory, blobs are *also* carried. Nothing here is signed or canonical;
//! every blob is authenticated by digest comparison before use, and every
//! proof re-verifies from its own canonical bytes. V1 defines the JSON
//! convention only (envelopes + hex blobs); a binary sealed container is V2.

use proof_core::{ErrorCode, HashRef, ProofError};

use crate::envelope::{ArtifactEnvelope, CONTAINER_VERSION};

/// An external content blob, authenticated by `digest` before use.
#[derive(Debug, Clone)]
pub struct BundleBlob {
    pub digest: HashRef,
    pub bytes: Vec<u8>,
}

/// Portable bundle: proofs plus optional blobs and a version marker.
#[derive(Debug, Clone, Default)]
pub struct Bundle {
    pub container_version: u32,
    pub proofs: Vec<ArtifactEnvelope>,
    pub blobs: Vec<BundleBlob>,
}

impl Bundle {
    pub fn new() -> Self {
        Self {
            container_version: CONTAINER_VERSION,
            proofs: vec![],
            blobs: vec![],
        }
    }

    pub fn with_proof(mut self, env: ArtifactEnvelope) -> Self {
        self.proofs.push(env);
        self
    }

    pub fn with_blob(mut self, digest: HashRef, bytes: Vec<u8>) -> Self {
        self.blobs.push(BundleBlob { digest, bytes });
        self
    }

    /// Find a blob authenticating `want` (digest equality over raw bytes).
    /// `None` means unavailable: callers report REFERENCED/UNAVAILABLE, and
    /// verification depending on it yields INDETERMINATE — never valid.
    pub fn find_blob(&self, want: &HashRef) -> Option<&[u8]> {
        self.blobs.iter().find_map(|b| {
            if b.digest == *want {
                Some(b.bytes.as_slice())
            } else {
                None
            }
        })
    }
}

/// Authenticate raw `bytes` against an expected content digest.
/// Dispatches on `HashRef.alg` (SHA-256 / SHA-384) and enforces exact digest
/// length — the same rule the pipeline applies to evidence digests.
/// Mismatch is `ID_MISMATCH` (tamper/equivocation signal), never silent.
pub fn check_blob_against_digest(bytes: &[u8], want: &HashRef) -> Result<(), ProofError> {
    use proof_core::HashAlgorithm;
    use sha2::Digest as _;
    if bytes.is_empty() {
        return Err(ErrorCode::Malformed.err("bundle blob is empty"));
    }
    let computed: Vec<u8> = match want.alg {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
    };
    if computed.len() != want.digest.len() || computed != want.digest {
        return Err(ErrorCode::IdMismatch.err("bundle blob digest mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_core::{HashAlgorithm, HashRef};

    fn sha256_ref(bytes: &[u8]) -> HashRef {
        use sha2::Digest as _;
        HashRef::new(HashAlgorithm::Sha256, sha2::Sha256::digest(bytes).to_vec()).unwrap()
    }

    #[test]
    fn blob_authenticates_and_finds() {
        let content = b"invoice-pdf-bytes";
        let digest = sha256_ref(content);
        let b = Bundle::new().with_blob(digest.clone(), content.to_vec());
        assert_eq!(b.find_blob(&digest), Some(content.as_slice()));
        assert!(check_blob_against_digest(content, &digest).is_ok());
        // Tampered bytes fail with ID_MISMATCH, never silent acceptance.
        let err = check_blob_against_digest(b"forged", &digest).unwrap_err();
        assert_eq!(err.code, ErrorCode::IdMismatch);
        // Unknown digest is absence (callers report UNAVAILABLE).
        let other = sha256_ref(b"something-else");
        assert_eq!(b.find_blob(&other), None);
        assert!(check_blob_against_digest(b"", &digest).is_err());
    }
}
