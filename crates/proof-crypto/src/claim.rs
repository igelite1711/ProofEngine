// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Status claims (FORMAT §4.7): `revoke`, `supersede`, `withdraw`, and
//! `compromise` are attestation sub-shapes distinguished by `claim.type`.
//! Everything else is a plain statement claim and untouched by lifecycle
//! machinery.
//!
//! Wire shape (inside every Attestation's `claim` map):
//! - revoke:    `{ "type": "revoke", "target": <id>, "reason": <text>? }`
//! - supersede: `{ "type": "supersede", "old": <id>, "new": <id> }`
//! - withdraw:  `{ "type": "withdraw", "target": <id>, "reason": <text>? }`
//! - compromise:`{ "type": "compromise", "target": <keyref|id>, "at_time": <uint>, "reason": <text>? }`
//!
//! Reserved statement-level conventions (no lifecycle effect; projected into
//! policy state for adjudication):
//! - `delegate`: `{ "type": "delegate", "scope": <text>? }`, subject = grantee
//!   identity. The issuer delegates authority; validity window and revocation
//!   are the attestation's own. Chains resolve in policy, never in the core.
//! - `identity.bind`: `{ "type": "identity.bind", "equivalent": <text> }`,
//!   subject = canonical identity. Asserts subject ≡ equivalent *as far as
//!   this issuer is concerned*; honored only from trusted asserters.
//! - `evidence_digest`: reserved claim FIELD (not type) for opt-in semantic
//!   binding (Fix 5). When a statement claim carries
//!   `evidence_digest: <64|96 hex>` alongside the attestation's `evidence_ref`,
//!   the pipeline verifies the hex equals the bound evidence digest;
//!   mismatch/missing-ref/malformed-hex fails EVIDENCE closed
//!   (`ID_MISMATCH`/`DANGLING_REFERENCE`/`SCHEMA_VIOLATION`). Absent field =
//!   no check (backward compatible). Use to cryptographically tie an attested
//!   value (e.g. `value=23`) to the dataset digest supporting it.
//! - `transparency.checkpoint`: `{ "type": "transparency.checkpoint",
//!   "log": <text>, "sequence": <uint>?, ... }`, issuer = log identity.
//! - `denies`: any statement claim may carry a `denies: <attestation-id>`
//!   field asserting opposition to that attestation's claim. Unresolvable
//!   targets are external denials (noted, not failed); resolvable verified
//!   pairs feed conflict records. Policy adjudicates.
//!
//! These claims are always signed (a status object is a full COSE_Sign1
//! attestation). Unsigned status lists are never trusted (FORMAT §4.7).

use proof_core::model::{AttestationContent, Claim, MetaValue};
use proof_core::{ErrorCode, ProofError};

/// Closed claim-kind classifier. Unknown claim types are `Statement` — the
/// open statement space stays open; only the reserved words below carry
/// lifecycle semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    Statement,
    Revoke,
    Supersede,
    Withdraw,
    Compromise,
}

/// Reserved claim types (FORMAT §4.7).
pub const CLAIM_REVOKE: &str = "revoke";
pub const CLAIM_SUPERSEDE: &str = "supersede";
pub const CLAIM_WITHDRAW: &str = "withdraw";
pub const CLAIM_COMPROMISE: &str = "compromise";
/// Reserved statement-level conventions (no lifecycle effect).
pub const CLAIM_DELEGATE: &str = "delegate";
pub const CLAIM_IDENTITY_BIND: &str = "identity.bind";
pub const CLAIM_TRANSPARENCY_CHECKPOINT: &str = "transparency.checkpoint";
/// Reserved claim field asserting opposition to an attestation id.
pub const CLAIM_FIELD_DENIES: &str = "denies";
/// Reserved claim field for opt-in semantic binding: when a statement claim
/// carries `evidence_digest` (hex) alongside the attestation's `evidence_ref`,
/// verifiers check the hex equals the bound evidence digest (EVIDENCE stage,
/// fail-closed). Absent field = no check (backward compatible).
pub const CLAIM_FIELD_EVIDENCE_DIGEST: &str = "evidence_digest";

/// Why an asserted `evidence_digest` field is unusable (never silently
/// ignored — present-but-malformed fails closed at EVIDENCE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestClaimError {
    /// Field value is not text (numbers/bools cannot encode hex).
    NonText,
    /// Text value is not 64 (sha-256) or 96 (sha-384) hex chars.
    Malformed { len: usize },
}

/// Normalized `evidence_digest` hex from a claim, if asserted.
/// `None` = absent (no binding asserted). `Some(Ok)` = well-formed lowercase
/// hex (`0x`-prefixed spellings accepted, like everywhere digests are read).
/// `Some(Err)` = present but unusable — fail closed, never skip.
/// Single home for the normalization so the pipeline EVIDENCE stage and the
/// policy-state projection cannot drift apart.
pub fn evidence_digest_hex(claim: &Claim) -> Option<Result<String, DigestClaimError>> {
    for (k, v) in &claim.fields {
        if k != CLAIM_FIELD_EVIDENCE_DIGEST {
            continue;
        }
        let s = match v {
            MetaValue::Text(s) => s,
            _ => return Some(Err(DigestClaimError::NonText)),
        };
        let normalized = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s)
            .to_lowercase();
        if !((normalized.len() == 64 || normalized.len() == 96)
            && normalized.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Some(Err(DigestClaimError::Malformed {
                len: normalized.len(),
            }));
        }
        return Some(Ok(normalized));
    }
    None
}

impl ClaimKind {
    /// True for claims consumed by lifecycle stages (never an issuer statement).
    pub fn is_status(self) -> bool {
        matches!(
            self,
            Self::Revoke | Self::Supersede | Self::Withdraw | Self::Compromise
        )
    }
}

/// Classify an attestation's claim. Never fails: unknown types are statements.
pub fn claim_kind(content: &AttestationContent) -> ClaimKind {
    match content.claim.claim_type.as_str() {
        CLAIM_REVOKE => ClaimKind::Revoke,
        CLAIM_SUPERSEDE => ClaimKind::Supersede,
        CLAIM_WITHDRAW => ClaimKind::Withdraw,
        CLAIM_COMPROMISE => ClaimKind::Compromise,
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
/// revoke or lacks a non-empty text `target`. Target must be an attestation
/// id (`att:v1:`) — revocation ends currency of attestations (F10: shape
/// validated here so garbage targets fail closed at STATUS, not silently).
pub fn revocation_target(content: &AttestationContent) -> Result<&str, ProofError> {
    if claim_kind(content) != ClaimKind::Revoke {
        return Err(ErrorCode::SchemaViolation.err("revoke claim expected (claim.type=\"revoke\")"));
    }
    let t = claim_text(&content.claim, "target")
        .ok_or_else(|| ErrorCode::SchemaViolation.err("revoke claim missing text field target"))?;
    if t.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("revoke claim target must not be empty"));
    }
    if !t.starts_with("att:v1:") {
        return Err(
            ErrorCode::SchemaViolation.err(format!("revoke target {t} must start with att:v1:"))
        );
    }
    Ok(t)
}

/// Extract the target id of a withdraw claim (any artifact id: evidence,
/// attestation, event, or relationship). Must be a shaped artifact id
/// (`evt:/att:/evd:/rel:/prf:` with version) — bare labels fail closed.
pub fn withdrawal_target(content: &AttestationContent) -> Result<&str, ProofError> {
    if claim_kind(content) != ClaimKind::Withdraw {
        return Err(
            ErrorCode::SchemaViolation.err("withdraw claim expected (claim.type=\"withdraw\")")
        );
    }
    let t = claim_text(&content.claim, "target").ok_or_else(|| {
        ErrorCode::SchemaViolation.err("withdraw claim missing text field target")
    })?;
    if t.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("withdraw claim target must not be empty"));
    }
    let shaped = t.starts_with("evt:v")
        || t.starts_with("att:v")
        || t.starts_with("evd:v")
        || t.starts_with("rel:v")
        || t.starts_with("prf:v");
    if !shaped || !t.contains(':') {
        return Err(ErrorCode::SchemaViolation.err(format!(
            "withdraw target {t} must be a shaped artifact id (evt:/att:/evd:/rel:/prf:)"
        )));
    }
    Ok(t)
}

/// Extract a compromise marking: (target identity, compromise instant).
/// Statements by `target` at/after `at_time` are tainted (COMPROMISED);
/// earlier statements keep their prior status — compromise is not retroactive
/// beyond the declared instant, and the instant itself is an assertion.
pub fn compromise_mark(content: &AttestationContent) -> Result<(&str, u64), ProofError> {
    if claim_kind(content) != ClaimKind::Compromise {
        return Err(
            ErrorCode::SchemaViolation.err("compromise claim expected (claim.type=\"compromise\")")
        );
    }
    let target = claim_text(&content.claim, "target").ok_or_else(|| {
        ErrorCode::SchemaViolation.err("compromise claim missing text field target")
    })?;
    if target.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("compromise claim target must not be empty"));
    }
    // Target is an identity: a keyref (`key:ed25519:/key:p256:`) or an
    // attestation/artifact id under compromise. Bare labels fail closed.
    let ok = target.starts_with("key:")
        || target.starts_with("att:v")
        || target.starts_with("evt:v")
        || target.starts_with("evd:v")
        || target.starts_with("rel:v")
        || target.starts_with("did:");
    if !ok {
        return Err(ErrorCode::SchemaViolation.err(format!(
            "compromise target {target} must be a keyref or shaped id"
        )));
    }
    let at_time = content
        .claim
        .fields
        .iter()
        .find_map(|(k, v)| {
            if k == "at_time" {
                match v {
                    MetaValue::Uint(n) => Some(*n),
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or_else(|| {
            ErrorCode::SchemaViolation.err("compromise claim missing uint field at_time")
        })?;
    Ok((target, at_time))
}

/// Extract a `denies` opposition target, if the claim carries one.
pub fn denial_target(content: &AttestationContent) -> Option<&str> {
    claim_text(&content.claim, CLAIM_FIELD_DENIES)
}

/// Extract the (old, new) id pair of a supersede claim. Both must be
/// attestation ids (`att:v1:`); garbage `new` values fail closed here (F10)
/// instead of silently marking `old` historical with misleading lineage.
/// Existence of `new` is NOT required (it may live outside this proof) —
/// shape is authenticated, content resolution is the bundle layer's job.
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
    if old.is_empty() || new.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("supersede old/new must not be empty"));
    }
    if old == new {
        return Err(ErrorCode::SchemaViolation.err("supersede old == new"));
    }
    for (label, v) in [("old", old), ("new", new)] {
        if !v.starts_with("att:v1:") {
            return Err(ErrorCode::SchemaViolation
                .err(format!("supersede {label} {v} must start with att:v1:")));
        }
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
    fn empty_lifecycle_targets_rejected() {
        let mut empty = revoke_content();
        empty.claim.fields = vec![("target".into(), MetaValue::Text("".into()))];
        assert_eq!(
            revocation_target(&empty).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
        let mut w = revoke_content();
        w.claim.claim_type = "withdraw".into();
        w.claim.fields = vec![("target".into(), MetaValue::Text("".into()))];
        assert_eq!(
            withdrawal_target(&w).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
        let mut s = revoke_content();
        s.claim.claim_type = "supersede".into();
        s.claim.fields = vec![
            ("old".into(), MetaValue::Text("".into())),
            ("new".into(), MetaValue::Text("att:v1:B".into())),
        ];
        assert_eq!(
            supersession_pair(&s).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
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
