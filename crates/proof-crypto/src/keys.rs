// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key types + KeyRef strings.
//! Ed25519: `key:ed25519:<b64u(32B pubkey)>`. P-256: `key:p256:<b64u(64B X||Y)>`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use proof_core::{ErrorCode, ProofError};

use crate::id::b64u_decode;

/// Keyref prefixes the verifier implements, in preference order.
/// THE identity plug-point: a future key type (DID method, PQ algorithm)
/// adds one prefix here, one verification op behind `AllowedAlgs`, and one
/// policy acceptance — never a redesign. Anything else is not a keyref.
pub const KEYREF_PREFIXES: &[&str] = &["key:ed25519:", "key:p256:"];

/// True iff `s` carries a supported `key:*` prefix AND a non-empty body
/// (shape pre-filter; cryptographic binding is checked separately by the
/// parse/verify path). F12: empty bodies (`key:ed25519:`) now fail here —
/// they are never valid keyrefs, and callers gating trust on this function
/// alone previously got a wider pre-filter than expected.
pub fn is_supported_keyref(s: &str) -> bool {
    KEYREF_PREFIXES
        .iter()
        .any(|p| s.starts_with(p) && s.len() > p.len())
}

/// Deterministic Ed25519 key from a 32-byte seed (test vectors use fixed seeds).
/// Debug is redacted: secret key material must never hit logs (audit P2).
/// Note (F12): in-memory signing keys are demo-grade — production deployments
/// must use HSM/KMS-backed signers and `--seed-file` (never `--seed` in argv;
/// see SECURITY.md). CLI stack seed copies are scrubbed after use.
#[derive(Clone)]
pub struct Ed25519Key {
    signing: SigningKey,
}

impl std::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Key(redacted)")
    }
}

impl Ed25519Key {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn key_ref(&self) -> String {
        format!(
            "key:ed25519:{}",
            URL_SAFE_NO_PAD.encode(self.pubkey_bytes())
        )
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

/// Parse `key:ed25519:<b64u>` → 32B pubkey. Rejects wrong prefix/length/alphabet.
// PE-SEC-005 (canonical keyref shapes).
pub fn parse_ed25519_keyref(key_ref: &str) -> Result<[u8; 32], ProofError> {
    let rest = key_ref
        .strip_prefix("key:ed25519:")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("issuer must be key:ed25519:<b64u>"))?;
    let raw = b64u_decode(rest)?;
    if crate::id::b64u_nopad(&raw) != rest {
        return Err(ErrorCode::SchemaViolation.err("ed25519 keyref is not canonical base64url"));
    }
    if raw.len() != 32 {
        return Err(ErrorCode::SchemaViolation.err("ed25519 pubkey must be 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// P-256 key (ESP256, optional). Raw pubkey form is 64B X||Y big-endian.
/// Debug is redacted: secret key material must never hit logs (audit P2).
/// Note (F12): `p256::ecdsa::SigningKey` has no `Zeroize` impl in the pinned
/// 0.13 feature set, so Drop cannot scrub it here — demo-grade keys only.
/// Production deployments must use HSM/KMS-backed signers (see SECURITY.md);
/// the Ed25519 path above does scrub on Drop, and CLI stack seeds are scrubbed
/// in `load_key_material`.
#[derive(Clone)]
pub struct P256Key {
    signing: p256::ecdsa::SigningKey,
}

impl std::fmt::Debug for P256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("P256Key(redacted)")
    }
}

impl P256Key {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, ProofError> {
        let sk = p256::ecdsa::SigningKey::from_bytes(seed.into())
            .map_err(|e| ErrorCode::Malformed.err(format!("bad p256 seed: {e}")))?;
        Ok(Self { signing: sk })
    }

    pub fn pubkey_xy(&self) -> Result<[u8; 64], ProofError> {
        let vk = self.signing.verifying_key();
        let pt = vk.to_encoded_point(false);
        let x = pt
            .x()
            .ok_or_else(|| ErrorCode::Malformed.err("p256 public point has no x coordinate"))?;
        let y = pt
            .y()
            .ok_or_else(|| ErrorCode::Malformed.err("p256 public point has no y coordinate"))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(ErrorCode::Malformed.err("p256 coordinates must be 32 bytes each"));
        }
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(x);
        out[32..].copy_from_slice(y);
        Ok(out)
    }

    pub fn key_ref(&self) -> Result<String, ProofError> {
        Ok(format!(
            "key:p256:{}",
            URL_SAFE_NO_PAD.encode(self.pubkey_xy()?)
        ))
    }
}

pub fn parse_p256_keyref(key_ref: &str) -> Result<[u8; 64], ProofError> {
    let rest = key_ref
        .strip_prefix("key:p256:")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("issuer must be key:p256:<b64u>"))?;
    let raw = b64u_decode(rest)?;
    if crate::id::b64u_nopad(&raw) != rest {
        return Err(ErrorCode::SchemaViolation.err("p256 keyref is not canonical base64url"));
    }
    if raw.len() != 64 {
        return Err(ErrorCode::SchemaViolation.err("p256 pubkey must be 64 bytes X||Y"));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyref_prefix_registry_accepts_shapes() {
        // THE identity plug-point: supported shapes pass, everything else
        // (DIDs, URLs, bare names) fails closed here and in policy.
        assert!(is_supported_keyref(
            "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(is_supported_keyref("key:p256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_supported_keyref(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ));
        assert!(!is_supported_keyref("key:ml-dsa:AAAA"));
        // F12: empty body fails here (never a valid keyref); full
        // length/canonical checks still live in the parse path (layered).
        assert!(!is_supported_keyref("key:ed25519:"));
        assert!(!is_supported_keyref("key:p256:"));
        assert!(!is_supported_keyref("mallory"));
        assert!(!is_supported_keyref(""));
        assert_eq!(KEYREF_PREFIXES.len(), 2);
    }

    #[test]
    fn secret_key_material_never_surfaces_in_debug() {
        // PE-SEC: key Debug impls must be redacted — seed bytes, their hex,
        // and their base64url must never appear in logs or panic messages.
        let seed = [0x42u8; 32];
        let ed = Ed25519Key::from_seed(&seed);
        let dbg = format!("{ed:?}");
        assert_eq!(dbg, "Ed25519Key(redacted)");
        assert!(!dbg.contains("42"));
        assert!(!dbg.contains("Qk"));
        let p256 = P256Key::from_seed(&seed).unwrap();
        let dbg_p = format!("{p256:?}");
        assert_eq!(dbg_p, "P256Key(redacted)");
        assert!(!dbg_p.contains("42"));
    }
}
