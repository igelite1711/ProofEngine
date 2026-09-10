// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! COSE_Sign1 (RFC 9052 §4.2) with fully-specified algs only.
//! Protected header: {1: alg, 4: kid} — nothing else. Unprotected MUST be empty.
//! external_aad defaults to h'504531' ("PE1") but is configurable per-verifier
//! for cross-domain isolation (V1.1).

use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
use proof_core::{ErrorCode, Limits, ProofError};
use proof_format::{decode_strict, encode_canonical, CborValue};

use crate::alg::{AllowedAlgs, COSE_ED25519, COSE_ESP256};
use crate::keys::{parse_ed25519_keyref, parse_p256_keyref};

/// Default domain separation ("PE1"). Used when no custom AAD is specified.
pub const EXTERNAL_AAD: &[u8] = b"PE1";

fn protected_bytes(alg: i64, kid_raw: &[u8]) -> Vec<u8> {
    let alg_val = if alg >= 0 {
        CborValue::Uint(alg as u64)
    } else {
        CborValue::Nint(alg)
    };
    let inner = CborValue::Map(vec![
        (CborValue::Uint(1), alg_val),
        (CborValue::Uint(4), CborValue::Bytes(kid_raw.to_vec())),
    ]);
    encode_canonical(&inner)
}

fn sig_structure_with_aad(protected: &[u8], aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let v = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(aad.to_vec()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    encode_canonical(&v)
}

/// Build the Sig_structure with default domain separation ("PE1").
/// This is the canonical signing input for ProofEngine V1.
pub fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    sig_structure_with_aad(protected, EXTERNAL_AAD, payload)
}

/// Build a COSE_Sign1 for `payload_canonical` with an Ed25519 key.
/// Returns the outer COSE bytes (deterministically encoded).
/// Uses the default domain separation ("PE1").
// PE-CRYPTO-002 (header) · PE-CRYPTO-003 (aad) · PE-CRYPTO-004 (Sig_structure).
pub fn sign_ed25519(payload_canonical: &[u8], key: &crate::keys::Ed25519Key) -> Vec<u8> {
    sign_ed25519_with_aad(payload_canonical, key, EXTERNAL_AAD)
}

/// Build a COSE_Sign1 with custom domain separation.
/// Use this for cross-domain isolation (different domains use different AAD).
pub fn sign_ed25519_with_aad(
    payload_canonical: &[u8],
    key: &crate::keys::Ed25519Key,
    external_aad: &[u8],
) -> Vec<u8> {
    let kid = key.pubkey_bytes();
    let prot = protected_bytes(COSE_ED25519, &kid);
    let tbs = sig_structure_with_aad(&prot, external_aad, payload_canonical);
    let sig = key.sign(&tbs);
    let outer = CborValue::Array(vec![
        CborValue::Bytes(prot),
        CborValue::Map(vec![]),
        CborValue::Bytes(payload_canonical.to_vec()),
        CborValue::Bytes(sig.to_vec()),
    ]);
    encode_canonical(&outer)
}

/// Build a COSE_Sign1 with ESP256 (P-256). Requires allow-list at verify time.
/// Uses the default domain separation ("PE1").
pub fn sign_esp256(
    payload_canonical: &[u8],
    key: &crate::keys::P256Key,
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    sign_esp256_with_aad(payload_canonical, key, signing_key, EXTERNAL_AAD)
}

/// Build a COSE_Sign1 with ESP256 and custom domain separation.
pub fn sign_esp256_with_aad(
    payload_canonical: &[u8],
    key: &crate::keys::P256Key,
    signing_key: &p256::ecdsa::SigningKey,
    external_aad: &[u8],
) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let kid = key.pubkey_xy();
    let prot = protected_bytes(COSE_ESP256, &kid);
    let tbs = sig_structure_with_aad(&prot, external_aad, payload_canonical);
    let sig: p256::ecdsa::Signature = signing_key.sign(&tbs);
    let outer = CborValue::Array(vec![
        CborValue::Bytes(prot),
        CborValue::Map(vec![]),
        CborValue::Bytes(payload_canonical.to_vec()),
        CborValue::Bytes(sig.to_bytes().to_vec()),
    ]);
    encode_canonical(&outer)
}

/// Parsed (verified-shape) Sign1 components. Crypto verification is separate.
#[derive(Debug, Clone)]
pub struct ParsedSign1 {
    pub alg: i64,
    pub kid: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub protected_raw: Vec<u8>,
}

/// Parse + shape-check a COSE_Sign1 (no crypto). Enforces canonical form,
/// closed headers, empty unprotected, embedded payload.
pub fn parse_sign1(bytes: &[u8], limits: &Limits) -> Result<ParsedSign1, ProofError> {
    if bytes.len() > limits.max_proof_size {
        return Err(ErrorCode::LimitExceeded.err("sign1 exceeds max_proof_size"));
    }
    let outer = decode_strict(bytes, limits)?;
    // Outer must already be canonical.
    if encode_canonical(&outer) != bytes {
        return Err(ErrorCode::NonCanonical.err("COSE_Sign1 not deterministic"));
    }
    let items = match outer {
        CborValue::Array(a) => a,
        _ => return Err(ErrorCode::Malformed.err("COSE_Sign1 must be array")),
    };
    if items.len() != 4 {
        return Err(ErrorCode::Malformed.err("COSE_Sign1 must have 4 elements"));
    }
    let protected_raw = match &items[0] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(ErrorCode::Malformed.err("protected must be bstr")),
    };
    match &items[1] {
        CborValue::Map(m) if m.is_empty() => {}
        _ => {
            return Err(
                ErrorCode::UnexpectedHeaderParam.err("unprotected header must be empty in V0.1")
            )
        }
    }
    let payload = match &items[2] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(ErrorCode::Malformed.err("detached payload (nil) not supported in V0.1")),
    };
    if payload.len() > limits.max_proof_size {
        return Err(ErrorCode::LimitExceeded.err("payload too large"));
    }
    let signature = match &items[3] {
        CborValue::Bytes(b) => b.clone(),
        _ => return Err(ErrorCode::Malformed.err("signature must be bstr")),
    };
    if signature.len() > limits.max_sig_size {
        return Err(ErrorCode::LimitExceeded.err("signature exceeds max_sig_size"));
    }

    // Inner protected header.
    let inner = decode_strict(&protected_raw, limits)?;
    if encode_canonical(&inner) != protected_raw {
        return Err(ErrorCode::NonCanonical.err("protected header not deterministic"));
    }
    let pairs = match inner {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::Malformed.err("protected must be map")),
    };
    if pairs.len() != 2 {
        return Err(ErrorCode::UnexpectedHeaderParam.err("protected must have exactly {1,4}"));
    }
    let mut alg: Option<i64> = None;
    let mut kid: Option<Vec<u8>> = None;
    for (k, v) in &pairs {
        match k {
            CborValue::Uint(1) => match v {
                CborValue::Nint(n) => alg = Some(*n),
                CborValue::Uint(n) => {
                    if *n > i64::MAX as u64 {
                        return Err(ErrorCode::UnknownAlgorithm.err("alg out of range"));
                    }
                    alg = Some(*n as i64);
                }
                _ => return Err(ErrorCode::UnexpectedHeaderParam.err("alg must be int")),
            },
            CborValue::Uint(4) => match v {
                CborValue::Bytes(b) => kid = Some(b.clone()),
                _ => return Err(ErrorCode::UnexpectedHeaderParam.err("kid must be bstr")),
            },
            _ => {
                return Err(
                    ErrorCode::UnexpectedHeaderParam.err("only header labels 1 and 4 allowed")
                )
            }
        }
    }
    let alg = alg.ok_or_else(|| ErrorCode::UnexpectedHeaderParam.err("missing alg (1)"))?;
    let kid = kid.ok_or_else(|| ErrorCode::UnexpectedHeaderParam.err("missing kid (4)"))?;
    // kid length must match a known alg shape, else confusion.
    match alg {
        x if x == COSE_ED25519 && kid.len() != 32 => {
            return Err(ErrorCode::AlgorithmConfusion.err("Ed25519 kid must be 32 bytes"));
        }
        x if x == COSE_ESP256 && kid.len() != 64 => {
            return Err(ErrorCode::AlgorithmConfusion.err("P-256 kid must be 64 bytes X||Y"));
        }
        _ => {}
    }
    Ok(ParsedSign1 {
        alg,
        kid,
        payload,
        signature,
        protected_raw,
    })
}

/// Full verification: shape + alg policy + key binding + crypto.
/// `expected_issuer` (e.g. "key:ed25519:…") must correspond to `kid`.
/// Uses the default domain separation ("PE1").
// PE-CRYPTO-001 (closed algs) · PE-CRYPTO-005 (key binding) · PE-TRUST-002.
pub fn verify_sign1(
    bytes: &[u8],
    expected_issuer: &str,
    allowed: &AllowedAlgs,
    limits: &Limits,
) -> Result<ParsedSign1, ProofError> {
    verify_sign1_with_aad(bytes, expected_issuer, allowed, limits, EXTERNAL_AAD)
}

/// Full verification with custom domain separation.
/// Use this when the signature was created with a non-default AAD.
pub fn verify_sign1_with_aad(
    bytes: &[u8],
    expected_issuer: &str,
    allowed: &AllowedAlgs,
    limits: &Limits,
    external_aad: &[u8],
) -> Result<ParsedSign1, ProofError> {
    let p = parse_sign1(bytes, limits)?;

    if crate::alg::AllowedAlgs::is_deprecated(p.alg) {
        return Err(ErrorCode::DeprecatedAlgorithm
            .err(format!("deprecated COSE alg {} (use -19/-9)", p.alg)));
    }
    if !allowed.is_allowed(p.alg) {
        // Distinguish unknown vs known-but-disabled.
        if p.alg == COSE_ED25519 || p.alg == COSE_ESP256 {
            return Err(ErrorCode::UnexpectedHeaderParam
                .err(format!("alg {} not allowed by verifier policy", p.alg)));
        }
        return Err(ErrorCode::UnknownAlgorithm.err(format!("unknown COSE alg {}", p.alg)));
    }
    if p.signature.len() != 64 {
        return Err(ErrorCode::SignatureInvalid.err("signature must be 64 bytes"));
    }

    // Key binding: kid must equal the expected issuer pubkey.
    match p.alg {
        x if x == COSE_ED25519 => {
            let expect = parse_ed25519_keyref(expected_issuer)?;
            if expect.as_slice() != p.kid.as_slice() {
                return Err(ErrorCode::SignatureInvalid.err("kid does not match issuer key"));
            }
            let vk = VerifyingKey::from_bytes(&expect)
                .map_err(|e| ErrorCode::Malformed.err(format!("bad ed25519 key: {e}")))?;
            let sig = EdSig::from_bytes(
                &p.signature
                    .clone()
                    .try_into()
                    .map_err(|_| ErrorCode::SignatureInvalid.err("bad ed25519 sig length"))?,
            );
            let tbs = sig_structure_with_aad(&p.protected_raw, external_aad, &p.payload);
            vk.verify(&tbs, &sig)
                .map_err(|_| ErrorCode::SignatureInvalid.err("Ed25519 verification failed"))?;
        }
        x if x == COSE_ESP256 => {
            let expect = parse_p256_keyref(expected_issuer)?;
            if expect.as_slice() != p.kid.as_slice() {
                return Err(ErrorCode::SignatureInvalid.err("kid does not match issuer key"));
            }
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256_verify_key(&expect)?;
            let sig = p256::ecdsa::Signature::from_slice(&p.signature)
                .map_err(|e| ErrorCode::SignatureInvalid.err(format!("bad p256 signature: {e}")))?;
            let tbs = sig_structure_with_aad(&p.protected_raw, external_aad, &p.payload);
            vk.verify(&tbs, &sig)
                .map_err(|_| ErrorCode::SignatureInvalid.err("ESP256 verification failed"))?;
        }
        _ => return Err(ErrorCode::UnknownAlgorithm.err("unreachable")),
    }
    Ok(p)
}

fn p256_verify_key(xy: &[u8; 64]) -> Result<p256::ecdsa::VerifyingKey, ProofError> {
    use p256::EncodedPoint;
    let mut unc = [0u8; 65];
    unc[0] = 0x04;
    unc[1..].copy_from_slice(xy);
    let pt = EncodedPoint::from_bytes(&unc[..])
        .map_err(|e| ErrorCode::Malformed.err(format!("bad p256 point: {e}")))?;
    p256::ecdsa::VerifyingKey::from_encoded_point(&pt)
        .map_err(|e| ErrorCode::Malformed.err(format!("bad p256 key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Ed25519Key, P256Key};
    use proof_core::Limits;

    fn lim() -> Limits {
        Limits::default()
    }

    /// Fixed test seed (NOT a production key). All vectors derive from it.
    pub const TEST_SEED: [u8; 32] = [9u8; 32];

    fn payload() -> Vec<u8> {
        b"attestation-content-canonical-placeholder".to_vec()
    }

    #[test]
    fn external_aad_is_pe1() {
        assert_eq!(EXTERNAL_AAD, b"PE1");
    }

    #[test]
    fn sign_verify_round_trip_ed25519() {
        let key = Ed25519Key::from_seed(&TEST_SEED);
        let issuer = key.key_ref();
        let bytes = sign_ed25519(&payload(), &key);
        let p = verify_sign1(&bytes, &issuer, &AllowedAlgs::strict(), &lim()).unwrap();
        assert_eq!(p.alg, COSE_ED25519);
        assert_eq!(p.kid, key.pubkey_bytes().to_vec());
        assert_eq!(p.payload, payload());
    }

    #[test]
    fn tampered_payload_fails() {
        let key = Ed25519Key::from_seed(&TEST_SEED);
        let issuer = key.key_ref();
        let bytes = sign_ed25519(&payload(), &key);
        // Flip one payload byte inside the outer encoding by re-parsing shapes:
        // simplest robust tamper: flip last byte of the whole message (inside sig).
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        let e = verify_sign1(&bad, &issuer, &AllowedAlgs::strict(), &lim()).unwrap_err();
        // Either canonical mismatch (if structure broke) or signature invalid.
        assert!(matches!(
            e.code,
            ErrorCode::SignatureInvalid | ErrorCode::NonCanonical | ErrorCode::Malformed
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let key = Ed25519Key::from_seed(&TEST_SEED);
        let other = Ed25519Key::from_seed(&[7u8; 32]);
        let bytes = sign_ed25519(&payload(), &key);
        let e = verify_sign1(&bytes, &other.key_ref(), &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
    }

    #[test]
    fn deprecated_alg_8_rejected() {
        // Hand-build outer with alg=-8 but a valid-shape 64B sig of zeros.
        // Parser accepts shape; verifier must reject as deprecated before crypto.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(-8)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let issuer = Ed25519Key::from_seed(&TEST_SEED).key_ref();
        let e = verify_sign1(&bytes, &issuer, &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::DeprecatedAlgorithm);
    }

    #[test]
    fn unknown_alg_rejected() {
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(-999)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let issuer = Ed25519Key::from_seed(&TEST_SEED).key_ref();
        let e = verify_sign1(&bytes, &issuer, &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnknownAlgorithm);
    }

    #[test]
    fn non_empty_unprotected_rejected() {
        let key = Ed25519Key::from_seed(&TEST_SEED);
        let kid = key.pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ED25519)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        // Unprotected carries smuggled {0: 1}.
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![(CborValue::Uint(0), CborValue::Uint(1))]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let e = parse_sign1(&bytes, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnexpectedHeaderParam);
    }

    #[test]
    fn header_label_6_rejected() {
        // Label 6 is Partial IV — must never appear in Sign1 protected header.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ED25519)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
                (
                    CborValue::Uint(6),
                    CborValue::Text("proof-engine/v1".into()),
                ),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let e = parse_sign1(&bytes, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnexpectedHeaderParam);
    }

    // PE-CRYPTO-010 (deterministic-signature contract — LONGEVITY.md §4):
    // Ed25519 (RFC 8032) and ECDSA P-256 (RFC 6979 deterministic nonce) must
    // sign byte-identically for the same key+message, so the same caller inputs
    // reproduce the same report byte-for-byte. Cross-checked by the interop
    // verifier (golden-21..23) and encode tests in `pengine.py`.
    #[test]
    fn signing_is_deterministic_ed25519_and_esp256() {
        let seed = [3u8; 32];
        let msg = b"deterministic-vector-payload";
        // Ed25519 (RFC 8032 — deterministic by construction).
        let ek = Ed25519Key::from_seed(&seed);
        let a = sign_ed25519(msg, &ek);
        let b = sign_ed25519(msg, &ek);
        assert_eq!(a, b, "Ed25519 must be byte-deterministic (RFC 8032)");
        // ECDSA P-256 (RFC 6979 nonce derivation — relies on the ecdsa crate).
        let sk = p256::ecdsa::SigningKey::from_bytes(seed.as_slice().into()).unwrap();
        let pk = P256Key::from_seed(&seed).unwrap();
        let c = sign_esp256(msg, &pk, &sk);
        let d = sign_esp256(msg, &pk, &sk);
        assert_eq!(c, d, "ECDSA P-256 must be byte-deterministic (RFC 6979)");
        // Determinism must not be monotonicity-with-structure: different payload
        // -> different bytes.
        let e = sign_esp256(b"other-payload", &pk, &sk);
        assert_ne!(c, e);
        assert_ne!(a, sign_ed25519(b"other-payload", &ek));
    }

    #[test]
    fn esp256_tampered_payload_fails() {
        let seed = [3u8; 32];
        let sk = p256::ecdsa::SigningKey::from_bytes(seed.as_slice().into()).unwrap();
        let pk = P256Key::from_seed(&seed).unwrap();
        let bytes = sign_esp256(&payload(), &pk, &sk);
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        let e = verify_sign1(
            &bad,
            &pk.key_ref(),
            &AllowedAlgs::strict().with_esp256(),
            &lim(),
        )
        .unwrap_err();
        assert!(matches!(
            e.code,
            ErrorCode::SignatureInvalid | ErrorCode::NonCanonical | ErrorCode::Malformed
        ));
    }

    #[test]
    fn esp256_wrong_key_fails() {
        let seed = [3u8; 32];
        let sk = p256::ecdsa::SigningKey::from_bytes(seed.as_slice().into()).unwrap();
        let pk = P256Key::from_seed(&seed).unwrap();
        let other = P256Key::from_seed(&[7u8; 32]).unwrap();
        let bytes = sign_esp256(&payload(), &pk, &sk);
        let e = verify_sign1(
            &bytes,
            &other.key_ref(),
            &AllowedAlgs::strict().with_esp256(),
            &lim(),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
    }

    #[test]
    fn esp256_gated_by_policy() {
        use p256::ecdsa::signature::Signer as _;
        let seed = [3u8; 32];
        let sk = p256::ecdsa::SigningKey::from_bytes(seed.as_slice().into()).unwrap();
        let key = P256Key::from_seed(&seed).unwrap();
        let payload = payload();
        let kid = key.pubkey_xy();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ESP256)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let tbs = {
            let v = CborValue::Array(vec![
                CborValue::Text("Signature1".into()),
                CborValue::Bytes(prot.clone()),
                CborValue::Bytes(EXTERNAL_AAD.to_vec()),
                CborValue::Bytes(payload.clone()),
            ]);
            encode_canonical(&v)
        };
        let sig: p256::ecdsa::Signature = sk.sign(&tbs);
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload),
            CborValue::Bytes(sig.to_bytes().to_vec()),
        ]);
        let bytes = encode_canonical(&outer);
        // Strict (default) policy rejects even a *valid* ESP256 sig.
        let e = verify_sign1(&bytes, &key.key_ref(), &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnexpectedHeaderParam);
        // Explicit opt-in verifies.
        verify_sign1(
            &bytes,
            &key.key_ref(),
            &AllowedAlgs::strict().with_esp256(),
            &lim(),
        )
        .unwrap();
    }

    // --- Post-Quantum crypto-agility tests (LONGEVITY.md §4) ---
    //
    // These tests verify the architecture handles PQ algorithm numbers correctly.
    // ML-DSA-44 (NIST FIPS 204) would use COSE alg -45; SLH-DSA-128s (FIPS 205)
    // would use COSE alg -18. Neither is implemented yet. The architecture must:
    //   1. Parse COSE_Sign1 with any valid alg number (shape-level)
    //   2. Reject unknown algs with UNKNOWN_ALGORITHM (policy-level)
    //   3. Accept known algs when explicitly allowed (policy-level)
    // This proves crypto-agility: adding PQ = new alg entry + key prefix, not
    // a core rewrite. See LONGEVITY.md §4 for the full migration contract.

    /// ML-DSA-44 (NIST FIPS 204) — hypothetical COSE alg number.
    /// IANA assignment may differ; this uses -45 as a placeholder for testing.
    const COSE_ML_DSA_44: i64 = -45;
    /// SLH-DSA-128s (NIST FIPS 205) — hypothetical COSE alg number.
    const COSE_SLH_DSA_128S: i64 = -18;

    #[test]
    fn pq_mldsa44_unknown_alg_rejected() {
        // Construct a COSE_Sign1 with alg=-45 (ML-DSA-44 placeholder).
        // The shape is valid: protected header {1: -45, 4: kid}, empty
        // unprotected, embedded payload, 64-byte signature placeholder.
        // The verifier must reject with UNKNOWN_ALGORITHM because -45 is
        // not in the AllowedAlgs registry — proving the architecture
        // handles PQ algorithm numbers without crashing or misrouting.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ML_DSA_44)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let issuer = Ed25519Key::from_seed(&TEST_SEED).key_ref();
        let e = verify_sign1(&bytes, &issuer, &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnknownAlgorithm);
        // Error message identifies the algorithm number for debugging.
        assert!(e.message.contains("-45"));
    }

    #[test]
    fn pq_slhdsa128s_unknown_alg_rejected() {
        // Same pattern for SLH-DSA-128s (alg=-18 placeholder).
        // The parser accepts the shape; the verifier rejects the algorithm.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_SLH_DSA_128S)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let issuer = Ed25519Key::from_seed(&TEST_SEED).key_ref();
        let e = verify_sign1(&bytes, &issuer, &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UnknownAlgorithm);
        assert!(e.message.contains("-18"));
    }

    #[test]
    fn pq_algorithm_header_is_parsed_correctly() {
        // Verify that parse_sign1 correctly extracts the PQ algorithm number
        // from the protected header. This proves the parser is algorithm-neutral:
        // it doesn't care what the alg number is, only that the shape is valid.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();
        let prot = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ML_DSA_44)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };
        let outer = CborValue::Array(vec![
            CborValue::Bytes(prot),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let bytes = encode_canonical(&outer);
        let p = parse_sign1(&bytes, &lim()).unwrap();
        // Parser correctly extracted the PQ algorithm number.
        assert_eq!(p.alg, COSE_ML_DSA_44);
        assert_eq!(p.kid, kid.to_vec());
        assert_eq!(p.payload, payload());
        // 64-byte signature placeholder passes shape check.
        assert_eq!(p.signature.len(), 64);
    }

    #[test]
    fn pq_and_classical_same_structure() {
        // Both PQ and classical COSE_Sign1 use the same wire structure.
        // This proves a future PQ implementation only needs to add:
        //   1. A new COSE alg constant (e.g., const COSE_ML_DSA_44: i64 = -45)
        //   2. A new key-ref prefix (e.g., "key:ml-dsa-44:")
        //   3. A new entry in AllowedAlgs (e.g., mldsa44: bool)
        //   4. Sign/verify functions for the new algorithm
        // The proof format, ID construction, verification pipeline, and
        // policy engine remain unchanged. This is crypto-agility by construction.
        let kid = Ed25519Key::from_seed(&TEST_SEED).pubkey_bytes();

        // Classical (Ed25519)
        let prot_classical = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ED25519)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };

        // PQ (ML-DSA-44 placeholder)
        let prot_pq = {
            let inner = CborValue::Map(vec![
                (CborValue::Uint(1), CborValue::Nint(COSE_ML_DSA_44)),
                (CborValue::Uint(4), CborValue::Bytes(kid.to_vec())),
            ]);
            encode_canonical(&inner)
        };

        // Both parse successfully (same structure, different alg numbers).
        let outer_classical = CborValue::Array(vec![
            CborValue::Bytes(prot_classical),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);
        let outer_pq = CborValue::Array(vec![
            CborValue::Bytes(prot_pq),
            CborValue::Map(vec![]),
            CborValue::Bytes(payload()),
            CborValue::Bytes(vec![0u8; 64]),
        ]);

        let bytes_classical = encode_canonical(&outer_classical);
        let bytes_pq = encode_canonical(&outer_pq);

        let p1 = parse_sign1(&bytes_classical, &lim()).unwrap();
        let p2 = parse_sign1(&bytes_pq, &lim()).unwrap();

        // Same structure, different alg numbers.
        assert_eq!(p1.alg, COSE_ED25519);
        assert_eq!(p2.alg, COSE_ML_DSA_44);
        assert_eq!(p1.kid, p2.kid); // Same key, different algorithm
        assert_eq!(p1.payload, p2.payload);
    }
}
