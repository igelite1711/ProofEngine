// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hash abstraction: versioned, agile. V1 allows SHA-256 and SHA-384 only.
use crate::error::ErrorCode;

/// Closed set of hash algorithms (V1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    /// Engine-local CBOR enum value (NOT the COSE number; mapping is explicit in crypto).
    pub fn cbor_enum(self) -> u64 {
        match self {
            Self::Sha256 => 0,
            Self::Sha384 => 1,
        }
    }

    pub fn from_cbor_enum(v: u64) -> Result<Self, crate::ProofError> {
        match v {
            0 => Ok(Self::Sha256),
            1 => Ok(Self::Sha384),
            _ => Err(ErrorCode::UnknownAlgorithm.err(format!("unknown hash alg enum {v}"))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
        }
    }

    pub fn from_name(s: &str) -> Result<Self, crate::ProofError> {
        match s {
            "sha-256" => Ok(Self::Sha256),
            "sha-384" => Ok(Self::Sha384),
            _ => Err(ErrorCode::UnknownAlgorithm.err(format!("unknown hash name {s}"))),
        }
    }

    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// Versioned hash reference. Digest is always over canonical CBOR bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashRef {
    pub v: u8,
    pub alg: HashAlgorithm,
    pub digest: Vec<u8>,
}

impl HashRef {
    // PE-CRYPTO-008: digest length bound to the algorithm (32/48).
    pub fn new(alg: HashAlgorithm, digest: Vec<u8>) -> Result<Self, crate::ProofError> {
        if digest.len() != alg.digest_len() {
            return Err(ErrorCode::Malformed.err(format!(
                "digest len {} != {} for {}",
                digest.len(),
                alg.digest_len(),
                alg.name()
            )));
        }
        Ok(Self { v: 1, alg, digest })
    }

    /// Display form: `hash:v1,<alg>:<lowerhex>`.
    pub fn display(&self) -> String {
        format!(
            "hash:v{},{}:{}",
            self.v,
            self.alg.name(),
            hex::encode(&self.digest)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PE-CRYPTO-008: digest length bound to the algorithm (32/48); unknown
    /// enum names/values rejected (closed agility, no silent downgrade).
    #[test]
    fn digest_lengths_enforced() {
        assert!(HashRef::new(HashAlgorithm::Sha256, vec![0u8; 32]).is_ok());
        assert!(HashRef::new(HashAlgorithm::Sha384, vec![0u8; 48]).is_ok());
        assert!(HashRef::new(HashAlgorithm::Sha256, vec![0u8; 48]).is_err());
        assert!(HashRef::new(HashAlgorithm::Sha384, vec![0u8; 32]).is_err());
        assert!(HashRef::new(HashAlgorithm::Sha256, vec![]).is_err());
        assert!(matches!(
            HashAlgorithm::from_name("sha-256"),
            Ok(HashAlgorithm::Sha256)
        ));
        assert!(HashAlgorithm::from_name("md5").is_err());
        assert!(matches!(
            HashAlgorithm::from_cbor_enum(1),
            Ok(HashAlgorithm::Sha384)
        ));
        assert!(HashAlgorithm::from_cbor_enum(7).is_err());
        let h = HashRef::new(HashAlgorithm::Sha256, vec![0xabu8; 32]).unwrap();
        assert!(h.display().starts_with("hash:v1,sha-256:"));
    }
}
