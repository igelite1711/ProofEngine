// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The SCITT-side record: a signed statement envelope in its canonical JSON
//! form plus the detached Ed25519 signature over those exact bytes.
//!
//! Canonical form is the struct field order serialized compactly
//! (`{"v":1,"feed":…,"cti":…,"payload_sha256":…,"issued_at":…}`); the digest
//! binding is `sha256(canonical_json)`. Byte-identity round-trips are the
//! outbound differential: `to_json → parse → to_json` must be identical.

use proof_core::{ErrorCode, ProofError};

/// A SCITT-style signed statement: who issued what payload, when, in which
/// feed. `payload_sha256` is the hex of the statement payload digest;
/// `kid` is either a `key:*` keyref (verifiable here) or an external
/// identifier (X.509 fingerprint, DID — mapped only, never verified here).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScittStatement {
    pub v: u8,
    pub feed: String,
    pub cti: String,
    pub payload_sha256: String,
    pub issued_at: u64,
    pub kid: String,
}

/// Detached Ed25519 signature over [`ScittStatement::canonical_json`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedStatement {
    pub statement: ScittStatement,
    pub signature_b64u: String,
}

impl ScittStatement {
    /// Validate shapes (not signatures): version, non-empty bounded feed/cti,
    /// 32-byte hex digest, `issued_at` present. Failures are `SCHEMA_VIOLATION`
    /// (stable code, never approximate).
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.v != 1 {
            return Err(ErrorCode::UnsupportedVersion.err("scitt statement v must be 1"));
        }
        if self.feed.is_empty() || self.feed.len() > 128 {
            return Err(ErrorCode::SchemaViolation.err("scitt feed length out of bounds"));
        }
        if self.cti.is_empty() || self.cti.len() > 256 {
            return Err(ErrorCode::SchemaViolation.err("scitt cti length out of bounds"));
        }
        let raw = hex_decode(&self.payload_sha256).ok_or_else(|| {
            ErrorCode::SchemaViolation.err("scitt payload_sha256 must be lowercase hex")
        })?;
        if raw.len() != 32 {
            return Err(ErrorCode::SchemaViolation.err("scitt payload_sha256 must be 32 bytes"));
        }
        if self.kid.is_empty() {
            return Err(ErrorCode::SchemaViolation.err("scitt kid must not be empty"));
        }
        Ok(())
    }

    /// Canonical bytes: compact JSON in struct field order (deterministic:
    /// serde emits struct fields in declaration order).
    pub fn canonical_json(&self) -> Result<Vec<u8>, ProofError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|e| ErrorCode::Malformed.err(format!("scitt statement unrestrictable: {e}")))
    }

    /// `sha256(canonical_json)`: the binding that survives the mapping into
    /// `Evidence` digests in both directions.
    pub fn digest(&self) -> Result<[u8; 32], ProofError> {
        let bytes = self.canonical_json()?;
        let out = proof_crypto::hash::compute_digest(&bytes, 0)?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        Ok(digest)
    }

    /// Opaque subject string for the mapped attestation. Convention only
    /// (subjects are opaque to the core): `scitt:<feed>:<cti>`.
    pub fn subject(&self) -> String {
        format!("scitt:{}:{}", self.feed, self.cti)
    }
}

impl SignedStatement {
    /// Verify the Ed25519 signature for `key:*` kids and return the
    /// validated statement. Non-`key:*` kids (X.509, DID) are unmappable
    /// here: stable `SCHEMA_VIOLATION`, never approximate, never silent.
    pub fn verify(&self) -> Result<ScittStatement, ProofError> {
        let st = self.statement.clone();
        st.validate()?;
        if !proof_crypto::keys::is_supported_keyref(&st.kid) {
            return Err(ErrorCode::SchemaViolation.err(
                "scitt kid is not a verifiable key:* keyref (x5chain/did out of adapter scope)",
            ));
        }
        let bytes = st.canonical_json()?;
        let sig = b64u_decode(&self.signature_b64u)
            .ok_or_else(|| ErrorCode::SchemaViolation.err("scitt signature must be base64url"))?;
        if sig.len() != 64 {
            return Err(ErrorCode::SignatureInvalid.err("scitt signature must be 64 bytes"));
        }
        // Same verification rule as the core COSE path (cose.rs): raw
        // 32-byte pubkey from the keyref, strict Ed25519 verify.
        let raw = proof_crypto::keys::parse_ed25519_keyref(&st.kid)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        verify_ed25519(&raw, &bytes, &sig_arr)?;
        Ok(st)
    }
}

fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), ProofError> {
    use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| ErrorCode::Malformed.err(format!("scitt kid pubkey invalid: {e}")))?;
    let signature = EdSig::from_bytes(sig);
    vk.verify(msg, &signature)
        .map_err(|_| ErrorCode::SignatureInvalid.err("scitt statement signature invalid"))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Lowercase canonical: uppercase hex is non-canonical here.
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    // Canonical base64url without padding over the standard alphabet.
    if s.bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if bits > 0 && buf != 0 {
        // Non-canonical trailing bits (pad-bit analogue): reject.
        return None;
    }
    Some(out)
}
