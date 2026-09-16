// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SHA-256 / SHA-384 helpers (FIPS 180-4).
use sha2::{Digest, Sha256, Sha384};

use proof_core::{ErrorCode, ProofError};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

/// Verify that `content` bytes match the given digest with the specified algorithm.
/// This is the canonical way to check external evidence content against a HashRef.
///
/// # Arguments
/// * `content` - The raw bytes to verify
/// * `alg` - The hash algorithm (0 = SHA-256, 1 = SHA-384)
/// * `expected_digest` - The expected digest bytes
///
/// # Errors
/// Returns `ErrorCode::IdMismatch` if the computed digest doesn't match.
pub fn verify_content_digest(
    content: &[u8],
    alg: u64,
    expected_digest: &[u8],
) -> Result<(), ProofError> {
    let computed = match alg {
        0 => {
            let digest = sha256(content);
            digest.to_vec()
        }
        1 => {
            let digest = sha384(content);
            digest.to_vec()
        }
        _ => {
            return Err(ErrorCode::UnknownAlgorithm.err(format!("unknown hash algorithm: {alg}")));
        }
    };

    if computed.as_slice() != expected_digest {
        return Err(
            ErrorCode::IdMismatch.err("content digest does not match expected (tampered content?)")
        );
    }

    Ok(())
}

/// Compute the digest for given content using the specified algorithm.
/// Returns the raw digest bytes.
pub fn compute_digest(content: &[u8], alg: u64) -> Result<Vec<u8>, ProofError> {
    match alg {
        0 => Ok(sha256(content).to_vec()),
        1 => Ok(sha384(content).to_vec()),
        _ => Err(ErrorCode::UnknownAlgorithm.err(format!("unknown hash algorithm: {alg}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_content_digest_sha256() {
        let content = b"hello world";
        let digest = sha256(content);
        assert!(verify_content_digest(content, 0, &digest).is_ok());
    }

    #[test]
    fn verify_content_digest_sha256_tampered() {
        let content = b"hello world";
        let wrong_digest = sha256(b"different content");
        let result = verify_content_digest(content, 0, &wrong_digest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::IdMismatch);
    }

    #[test]
    fn verify_content_digest_sha384() {
        let content = b"test data for sha384";
        let digest = sha384(content);
        assert!(verify_content_digest(content, 1, &digest).is_ok());
    }

    #[test]
    fn verify_content_digest_unknown_alg() {
        let result = verify_content_digest(b"data", 99, &[0u8; 32]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::UnknownAlgorithm);
    }

    #[test]
    fn compute_digest_round_trip() {
        let content = b"test content";
        let digest = compute_digest(content, 0).unwrap();
        assert_eq!(digest.len(), 32);
        assert!(verify_content_digest(content, 0, &digest).is_ok());
    }
}
