// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! SCITT ↔ Proof Engine mapping (both directions, binding-preserving).
//!
//! Inbound (`SignedStatement` → model) verifies the Ed25519 statement
//! signature and projects three artifacts: the statement attestation
//! content, the registration evidence (digest-bound to the statement), and
//! — once the caller attests the log checkpoint — the receipt evidence
//! bound to that checkpoint. Outbound (`attestation content` → statement
//! JSON) inverts the projection byte-identically (differential fixtures in
//! `fixtures/` pin both directions).

use proof_core::model::{AttestationContent, Claim, Evidence, EvidenceKind, MetaValue};
use proof_core::{ErrorCode, HashAlgorithm, HashRef, Limits, ProofError};

use crate::statement::{ScittStatement, SignedStatement};

/// Claim type for mapped SCITT statements (open statement space; no
/// lifecycle effect).
pub const CLAIM_SCITT_STATEMENT: &str = "scitt.statement";

/// Inbound: verify `signed` and project the statement attestation content.
/// Issuer = statement signer; subject = `scitt:<feed>:<cti>`; both the
/// payload hash (for outbound reconstruction) and the statement digest
/// (the binding, inspectable without recomputation) ride as fields.
pub fn statement_content(
    signed: &SignedStatement,
    issued_at: u64,
    expires_at: Option<u64>,
    limits: &Limits,
) -> Result<AttestationContent, ProofError> {
    let st = signed.verify()?;
    let digest = st.digest()?;
    let content = AttestationContent {
        v: 1,
        issuer: st.kid.clone(),
        subject: st.subject(),
        claim: Claim {
            claim_type: CLAIM_SCITT_STATEMENT.into(),
            // Pre-sorted (canonical CBOR sorts map keys; builders reject
            // round-trip mismatches, so domain maps must sort first).
            fields: vec![
                ("cti".into(), MetaValue::Text(st.cti.clone())),
                ("feed".into(), MetaValue::Text(st.feed.clone())),
                (
                    "payload_sha256".into(),
                    MetaValue::Text(st.payload_sha256.clone()),
                ),
                ("statement_digest".into(), MetaValue::Text(hex_of(&digest))),
            ],
        },
        issued_at,
        expires_at,
        evidence_ref: None,
    };
    // Shape-check through the shared builder path would sign; here we only
    // need schema acceptance (signing happens via `attest` by the caller).
    let _ = limits;
    Ok(content)
}

/// Inbound: registration evidence for a verified statement. Digest-bound to
/// `sha256(canonical statement JSON)` — the binding that survives mapping.
pub fn registration_evidence(st: &ScittStatement, limits: &Limits) -> Result<Evidence, ProofError> {
    let digest = st.digest()?;
    proof_crypto::build::make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSPARENCY_REGISTRATION),
        HashRef::new(HashAlgorithm::Sha256, digest.to_vec())?,
        None,
        None,
        limits,
    )
    .map(|e| e.content)
}

/// Checkpoint attestation content for the log `log_keyref` covering this
/// statement feed at `sequence`. Ordinary attestation: the log's own
/// validity window, revocation, and compromise semantics apply unchanged.
/// `log` field mirrors the convention `transparency.checkpoint` documents.
#[allow(clippy::too_many_arguments)]
pub fn checkpoint_content(
    log_keyref: &str,
    log_name: &str,
    sequence: u64,
    subject: &str,
    issued_at: u64,
    expires_at: Option<u64>,
) -> Result<AttestationContent, ProofError> {
    if !proof_crypto::keys::is_supported_keyref(log_keyref) {
        return Err(ErrorCode::SchemaViolation.err("scitt log must be a key:* keyref"));
    }
    if log_name.is_empty() || log_name.len() > 128 {
        return Err(ErrorCode::SchemaViolation.err("scitt log name length out of bounds"));
    }
    Ok(AttestationContent {
        v: 1,
        issuer: log_keyref.into(),
        subject: subject.into(),
        claim: Claim {
            claim_type: proof_crypto::claim::CLAIM_TRANSPARENCY_CHECKPOINT.into(),
            fields: vec![
                ("log".into(), MetaValue::Text(log_name.into())),
                ("sequence".into(), MetaValue::Uint(sequence)),
            ],
        },
        issued_at,
        expires_at,
        evidence_ref: None,
    })
}

/// Inbound: transparency receipt evidence binding a statement digest to a
/// checkpoint attestation id. Together with an ACTIVE checkpoint by `log`,
/// policy `transparency_inclusion{log}` passes; wrong-log fails.
pub fn receipt_evidence(
    st: &ScittStatement,
    checkpoint_attestation_id: &str,
    limits: &Limits,
) -> Result<Evidence, ProofError> {
    let digest = st.digest()?;
    proof_crypto::build::make_evidence(
        EvidenceKind::new(EvidenceKind::TRANSPARENCY_RECEIPT),
        HashRef::new(HashAlgorithm::Sha256, digest.to_vec())?,
        Some(checkpoint_attestation_id.to_string()),
        None,
        limits,
    )
    .map(|e| e.content)
}

/// Outbound: project attestation content back to the canonical SCITT JSON
/// for a `scitt.statement` claim. Byte-identity with the inbound canonical
/// form is the round-trip differential (fixtures pin it). Non-statement
/// claims are unmappable: stable `SCHEMA_VIOLATION`, never approximate.
pub fn statement_json(content: &AttestationContent) -> Result<Vec<u8>, ProofError> {
    if content.claim.claim_type != CLAIM_SCITT_STATEMENT {
        return Err(
            ErrorCode::SchemaViolation.err("only scitt.statement claims map back to SCITT JSON")
        );
    }
    let field = |name: &str| {
        content
            .claim
            .fields
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| match v {
                MetaValue::Text(t) => Some(t.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                ErrorCode::SchemaViolation.err(format!("scitt.statement lacks text field {name}"))
            })
    };
    let feed = field("feed")?;
    let cti = field("cti")?;
    let payload_sha256 = field("payload_sha256")?;
    let st = ScittStatement {
        v: 1,
        feed,
        cti,
        payload_sha256,
        issued_at: content.issued_at,
        kid: content.issuer.clone(),
    };
    // The carried statement digest must reproduce: the mapping is
    // self-checking (a hand-built claim with a forged digest fails here).
    let stated = field("statement_digest")?;
    if stated != hex_of(&st.digest()?) {
        return Err(ErrorCode::SchemaViolation
            .err("scitt.statement digest field does not match recomputed digest"));
    }
    // The payload bytes stay outside (digest-only, like all evidence in
    // this system); only the digest travels.
    // Subject must match the convention or the content did not come from
    // this adapter (fail closed, never re-derive silently).
    if content.subject != st.subject() {
        return Err(
            ErrorCode::SchemaViolation.err("subject does not match scitt feed/cti convention")
        );
    }
    st.canonical_json()
}

/// Hex helper (lowercase, canonical).
fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
