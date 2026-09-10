// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// PE-LONG-002: signature algorithm migration / hybrid bridging (docs/LONGEVITY.md
// §4): new algs enter the same closed registry, default off, additive keyref
// prefixes, dual-sign windows -- never a silent core rewrite.
//! COSE algorithm numbers (verified 2026-09-06 vs IANA + RFC 9864).
//! Fully-specified only. Deprecated polymorphic ids are rejected, never negotiated.

/// EdDSA with Ed25519 (RFC 8032 §5.1). REQUIRED. IANA Recommended: Yes.
pub const COSE_ED25519: i64 = -19;
/// ECDSA P-256 + SHA-256 (fully-specified). OPTIONAL, default off. Recommended: Yes.
pub const COSE_ESP256: i64 = -9;

/// Deprecated polymorphic ids (RFC 9864 §4.2.2). MUST fail closed.
pub const DEPRECATED: &[i64] = &[-8, -7, -35, -36];

/// Verifier algorithm policy.
#[derive(Debug, Clone, Copy)]
pub struct AllowedAlgs {
    /// Always true in V0.1 (Ed25519 required).
    pub ed25519: bool,
    /// Default false. Enable explicitly per deployment.
    pub esp256: bool,
}

impl Default for AllowedAlgs {
    fn default() -> Self {
        Self {
            ed25519: true,
            esp256: false,
        }
    }
}

impl AllowedAlgs {
    /// Ed25519-only (V0.1 default).
    pub fn strict() -> Self {
        Self::default()
    }

    pub fn with_esp256(mut self) -> Self {
        self.esp256 = true;
        self
    }

    pub fn is_allowed(&self, alg: i64) -> bool {
        match alg {
            x if x == COSE_ED25519 => self.ed25519,
            x if x == COSE_ESP256 => self.esp256,
            _ => false,
        }
    }

    pub fn is_deprecated(alg: i64) -> bool {
        DEPRECATED.contains(&alg)
    }
}
