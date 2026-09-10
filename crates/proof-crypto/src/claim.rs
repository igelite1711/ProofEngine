// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Status claims (FORMAT §4.7): `revoke` and `supersede` are attestation
//! sub-shapes distinguished by `claim.type`. Everything else is a plain
//! statement claim and untouched by lifecycle machinery.
//!
//! Wire shape (inside every Attestation's `claim` map):
//! - revoke:    `{ "type": "revoke", "target": <id>, "reason": <text>? }`
//! - supersede: `{ "type": "supersede", "old": <id>, "new": <id> }`
//!
//! These claims are always signed (a status object is a full COSE_Sign1
//! attestation). Unsigned status lists are never trusted (FORMAT §4.7).

use proof_core::model::{AttestationContent, Claim, MetaValue};
use proof_core::{ErrorCode, ProofError};

/// Closed claim-kind classifier. Unknown claim types are `Statement` — the
/// open statement space from Phase 2 stays open; only revoke/supersede are
/// reserved words with lifecycle semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    Statement,
    Revoke,
    Supersede,
}

/// Reserved claim types (FORMAT §4.7).
pub const CLAIM_REVOKE: &str = "revoke";
pub const CLAIM_SUPERSEDE: &str = "supersede";

impl ClaimKind {
    /// True for claims consumed by lifecycle stages (never an issuer statement).
    pub fn is_status(self) -> bool {
        matches!(self, Self::Revoke | Self::Supersede)
    }
}

/// Classify an attestation's claim. Never fails: unknown types are statements.
pub fn claim_kind(content: &AttestationContent) -> ClaimKind {
    match content.claim.claim_type.as_str() {
        CLAIM_REVOKE => ClaimKind::Revoke,
        CLAIM_SUPERSEDE => ClaimKind::Supersede,
        _ => ClaimKind::Statement,
    }
}

/// Read a text field from a claim map (claim fields are flat text→scalar).
fn claim_text<'a>(claim: &'a Claim, key: &str) -> Option<&'a str> {
    claim.fields.iter().find_map(|(k, v)| {
        if k == key {
            match v {
                MetaValue::Text(s) => Some(s.as_str()),
                // A non-text value for a lifecycle key is a schema error; the
                // caller decides how to fail (revocation_target does).
                _ => None,
            }
        } else {
            None
        }
    })
}

/// Extract the target id of a revoke claim. Fails if the claim is not a
/// revoke or lacks a text `target`.
pub fn revocation_target(content: &AttestationContent) -> Result<&str, ProofError> {
    if claim_kind(content) != ClaimKind::Revoke {
        return Err(ErrorCode::SchemaViolation.err("revoke claim expected (claim.type=\"revoke\")"));
    }
    claim_text(&content.claim, "target")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("revoke claim missing text field target"))
}

/// Extract the (old, new) id pair of a supersede claim.
pub fn supersession_pair(content: &AttestationContent) -> Result<(&str, &str), ProofError> {
    if claim_kind(content) != ClaimKind::Supersede {
        return Err(
            ErrorCode::SchemaViolation.err("supersede claim expected (claim.type=\"supersede\")")
        );
    }
    let old = claim_text(&content.claim, "old")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("supersede claim missing text field old"))?;
    let new = claim_text(&content.claim, "new")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("supersede claim missing text field new"))?;
    if old == new {
        return Err(ErrorCode::SchemaViolation.err("supersede old == new"));
    }
    Ok((old, new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_core::model::{AttestationContent, Claim};

    fn revoke_content() -> AttestationContent {
        AttestationContent {
            v: 1,
            issuer: "key:ed25519:x".into(),
            subject: "att:v1:t".into(),
            claim: Claim {
                claim_type: "revoke".into(),
                fields: vec![
                    ("target".into(), MetaValue::Text("att:v1:t".into())),
                    ("reason".into(), MetaValue::Text("fraud".into())),
                ],
            },
            issued_at: 1_700_000_000,
            expires_at: None,
            evidence_ref: None,
        }
    }

    #[test]
    fn classifies_claims_closed() {
        assert_eq!(claim_kind(&revoke_content()), ClaimKind::Revoke);
        let mut s = revoke_content();
        s.claim.claim_type = "supersede".into();
        assert_eq!(claim_kind(&s), ClaimKind::Supersede);
        s.claim.claim_type = "payment.created-observed".into();
        assert_eq!(claim_kind(&s), ClaimKind::Statement);
        assert!(ClaimKind::Revoke.is_status());
        assert!(ClaimKind::Supersede.is_status());
        assert!(!ClaimKind::Statement.is_status());
    }

    #[test]
    fn revoke_target_extracted_or_rejected() {
        assert_eq!(revocation_target(&revoke_content()).unwrap(), "att:v1:t");
        let mut missing = revoke_content();
        missing.claim.fields.clear();
        let e = revocation_target(&missing).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
        let mut not_revoke = revoke_content();
        not_revoke.claim.claim_type = "statement".into();
        let e = revocation_target(&not_revoke).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn supersession_pair_extracted() {
        let mut c = revoke_content();
        c.claim.claim_type = "supersede".into();
        c.claim.fields = vec![
            ("old".into(), MetaValue::Text("att:v1:A".into())),
            ("new".into(), MetaValue::Text("att:v1:B".into())),
        ];
        let (old, new) = supersession_pair(&c).unwrap();
        assert_eq!((old, new), ("att:v1:A", "att:v1:B"));
        // Identity supersede is nonsensical.
        c.claim.fields[1].1 = MetaValue::Text("att:v1:A".into());
        assert_eq!(
            supersession_pair(&c).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }
}
