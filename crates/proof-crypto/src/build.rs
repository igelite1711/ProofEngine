// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase 2 builders: create and verify signed artifacts.
//! Every builder round-trips through canonical CBOR + schema so malformed
//! domain objects can never reach signing or id assignment.

use proof_core::{
    model::{
        AttestationContent, Claim, EventContent, Evidence, EvidenceKind, MetaValue, Relationship,
    },
    ErrorCode, HashRef, Limits, ProofError,
};
use proof_format::{
    attestation_to_cbor, cbor_to_attestation, cbor_to_event, cbor_to_evidence,
    cbor_to_relationship, decode_and_check_canonical, encode_canonical, event_to_cbor,
    evidence_to_cbor, relationship_to_cbor,
};

use crate::alg::AllowedAlgs;
use crate::claim::{claim_kind, CLAIM_COMPROMISE, CLAIM_REVOKE, CLAIM_SUPERSEDE, CLAIM_WITHDRAW};
use crate::cose::{sign_ed25519, verify_sign1};
use crate::id::{attestation_id, event_id, evidence_id, relationship_id, verify_id};
use crate::keys::Ed25519Key;

/// Fixed test seed. NEVER use in production. All fixtures derive from it.
pub const TEST_SEED: [u8; 32] = [9u8; 32];

/// A created event: validated content, canonical bytes, deterministic id.
#[derive(Debug, Clone)]
pub struct CreatedEvent {
    pub content: EventContent,
    pub canonical: Vec<u8>,
    pub id: String,
}

/// Validate `content` (schema + canonical round-trip) and assign its id.
pub fn create_event(content: EventContent, limits: &Limits) -> Result<CreatedEvent, ProofError> {
    if content.v != 1 {
        return Err(ErrorCode::UnsupportedVersion.err("only event v=1 supported"));
    }
    let value = event_to_cbor(&content)?;
    let canonical = encode_canonical(&value);
    // Round-trip: what we verify later must equal what we built now.
    let back = cbor_to_event(&decode_and_check_canonical(&canonical, limits)?, limits)?;
    if back != content {
        return Err(ErrorCode::SchemaViolation.err("event did not survive canonical round-trip"));
    }
    let id = event_id(&canonical);
    Ok(CreatedEvent {
        content,
        canonical,
        id,
    })
}

/// Verify event bytes: canonical form + schema + id binding.
/// If `expected_id` is given, the recomputed id must match it (tamper check).
pub fn verify_event(
    canonical: &[u8],
    expected_id: Option<&str>,
    limits: &Limits,
) -> Result<(EventContent, String), ProofError> {
    let value = decode_and_check_canonical(canonical, limits)?;
    let content = cbor_to_event(&value, limits)?;
    let id = event_id(canonical);
    if let Some(expect) = expected_id {
        verify_id(proof_core::model::id_prefix::EVENT, expect, canonical)?;
    }
    Ok((content, id))
}

/// A created attestation: validated content, canonical bytes, id, COSE_Sign1.
#[derive(Debug, Clone)]
pub struct CreatedAttestation {
    pub content: AttestationContent,
    pub canonical: Vec<u8>,
    pub id: String,
    pub sign1: Vec<u8>,
}

/// Validate `content`, bind it to `key` (issuer MUST equal the key's KeyRef),
/// assign its id, and sign. Fail closed on any mismatch — never sign bytes
/// the issuer field disowns.
// PE-CRYPTO-005 · PE-TRUST-002 (issuer bound to key, never from attacker bytes).
pub fn attest(
    content: AttestationContent,
    key: &Ed25519Key,
    limits: &Limits,
) -> Result<CreatedAttestation, ProofError> {
    if content.v != 1 {
        return Err(ErrorCode::UnsupportedVersion.err("only attestation v=1 supported"));
    }
    if content.issuer != key.key_ref() {
        return Err(ErrorCode::SchemaViolation.err("issuer does not match signing key"));
    }
    let value = attestation_to_cbor(&content);
    let canonical = encode_canonical(&value);
    let back = cbor_to_attestation(&decode_and_check_canonical(&canonical, limits)?, limits)?;
    if back != content {
        return Err(
            ErrorCode::SchemaViolation.err("attestation did not survive canonical round-trip")
        );
    }
    let id = attestation_id(&canonical);
    let sign1 = sign_ed25519(&canonical, key);
    Ok(CreatedAttestation {
        content,
        canonical,
        id,
        sign1,
    })
}

/// Verify a signed attestation artifact: shape + alg policy + key binding +
/// crypto, then schema + id. Returns the authenticated content and its id.
pub fn verify_attestation(
    sign1: &[u8],
    expected_issuer: &str,
    allowed: &AllowedAlgs,
    limits: &Limits,
) -> Result<(AttestationContent, String), ProofError> {
    let parsed = verify_sign1(sign1, expected_issuer, allowed, limits)?;
    let value = decode_and_check_canonical(&parsed.payload, limits)?;
    let content = cbor_to_attestation(&value, limits)?;
    // The payload is authenticated; the id binds it. Recompute, don't trust.
    let id = attestation_id(&parsed.payload);
    if content.issuer != expected_issuer {
        return Err(ErrorCode::SignatureInvalid.err("payload issuer differs from expected issuer"));
    }
    Ok((content, id))
}

/// Signed lifecycle status object: a full COSE_Sign1 attestation whose claim
/// is `revoke` or `supersede` (FORMAT §4.7). A caller-supplied revocation set
/// is a list of these — never plain id lists.
#[derive(Debug, Clone)]
pub struct SignedStatus {
    pub content: AttestationContent,
    pub sign1: Vec<u8>,
}

/// Build a signed `revoke` status object: `claim.type="revoke"`,
/// `target=<id>`, optional `reason`. `subject` mirrors `target`.
pub fn revoke_attestation(
    target: &str,
    reason: Option<&str>,
    by: &Ed25519Key,
    issued_at: u64,
    limits: &Limits,
) -> Result<CreatedAttestation, ProofError> {
    if target.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("revoke target must not be empty"));
    }
    // CBOR map keys sort bytewise; keep `fields` in sorted order so the
    // canonical round-trip in `attest` is order-stable ("reason" < "target").
    let mut fields = vec![];
    if let Some(r) = reason {
        if r.is_empty() {
            return Err(ErrorCode::SchemaViolation.err("revoke reason must not be empty"));
        }
        fields.push(("reason".into(), MetaValue::Text(r.into())));
    }
    fields.push(("target".into(), MetaValue::Text(target.into())));
    attest(
        AttestationContent {
            v: 1,
            issuer: by.key_ref(),
            subject: target.into(),
            claim: Claim {
                claim_type: CLAIM_REVOKE.into(),
                fields,
            },
            issued_at,
            expires_at: None,
            evidence_ref: None,
        },
        by,
        limits,
    )
}

/// Build a signed `supersede` status object: `claim.type="supersede"`,
/// `old=<id>`, `new=<id>`. `subject` mirrors `old`.
pub fn supersede_attestation(
    old: &str,
    new: &str,
    by: &Ed25519Key,
    issued_at: u64,
    limits: &Limits,
) -> Result<CreatedAttestation, ProofError> {
    if old.is_empty() || new.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("supersede old/new must not be empty"));
    }
    if old == new {
        return Err(ErrorCode::SchemaViolation.err("supersede old == new"));
    }
    // Sorted-by-key order keeps the canonical round-trip stable ("new" < "old").
    attest(
        AttestationContent {
            v: 1,
            issuer: by.key_ref(),
            subject: old.into(),
            claim: Claim {
                claim_type: CLAIM_SUPERSEDE.into(),
                fields: vec![
                    ("new".into(), MetaValue::Text(new.into())),
                    ("old".into(), MetaValue::Text(old.into())),
                ],
            },
            issued_at,
            expires_at: None,
            evidence_ref: None,
        },
        by,
        limits,
    )
}

/// Build a signed `withdraw` status object: `claim.type="withdraw"`,
/// `target=<any artifact id>`, optional `reason`. `subject` mirrors `target`.
/// Withdrawal is administrative cease-reliance (history preserved); compromise
/// taint is separate (see `compromise_attestation`).
pub fn withdraw_attestation(
    target: &str,
    reason: Option<&str>,
    by: &Ed25519Key,
    issued_at: u64,
    limits: &Limits,
) -> Result<CreatedAttestation, ProofError> {
    if target.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("withdraw target must not be empty"));
    }
    let mut fields = vec![];
    if let Some(r) = reason {
        if r.is_empty() {
            return Err(ErrorCode::SchemaViolation.err("withdraw reason must not be empty"));
        }
        fields.push(("reason".into(), MetaValue::Text(r.into())));
    }
    fields.push(("target".into(), MetaValue::Text(target.into())));
    attest(
        AttestationContent {
            v: 1,
            issuer: by.key_ref(),
            subject: target.into(),
            claim: Claim {
                claim_type: CLAIM_WITHDRAW.into(),
                fields,
            },
            issued_at,
            expires_at: None,
            evidence_ref: None,
        },
        by,
        limits,
    )
}

/// Build a signed `compromise` status object: `claim.type="compromise"`,
/// `target=<keyref|id>`, `at_time=<uint compromise instant>`, optional
/// `reason`. `subject` mirrors `target`. Statements by `target` issued
/// at/after `at_time` verify as COMPROMISED (tainted, history not preserved);
/// earlier statements keep their prior status.
pub fn compromise_attestation(
    target: &str,
    at_time: u64,
    reason: Option<&str>,
    by: &Ed25519Key,
    issued_at: u64,
    limits: &Limits,
) -> Result<CreatedAttestation, ProofError> {
    if target.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("compromise target must not be empty"));
    }
    // Sorted-by-encoded-key order keeps the canonical round-trip stable:
    // CBOR text keys sort bytewise on (major+length, bytes), so "reason"
    // (0x66…) < "target" (0x66 0x74…) < "at_time" (0x67…).
    let mut fields = vec![];
    if let Some(r) = reason {
        if r.is_empty() {
            return Err(ErrorCode::SchemaViolation.err("compromise reason must not be empty"));
        }
        fields.push(("reason".into(), MetaValue::Text(r.into())));
    }
    fields.push(("target".into(), MetaValue::Text(target.into())));
    fields.push(("at_time".into(), MetaValue::Uint(at_time)));
    attest(
        AttestationContent {
            v: 1,
            issuer: by.key_ref(),
            subject: target.into(),
            claim: Claim {
                claim_type: CLAIM_COMPROMISE.into(),
                fields,
            },
            issued_at,
            expires_at: None,
            evidence_ref: None,
        },
        by,
        limits,
    )
}

/// Verify a caller-supplied signed status object: signature + alg policy +
/// issuer binding + claim shape. Returns the authenticated content.
/// The caller states who must have signed it (`expected_issuer`); trust is
/// never derived from the attacker-controlled COSE kid (audit P2). Authority
/// over the target is decided later by the pipeline, never here.
/// Structurally bad or non-status claims are errors — a status object MUST be
/// a revoke, supersede, withdraw, or compromise, never a statement smuggled
/// through this path.
pub fn verify_status_object(
    sign1: &[u8],
    expected_issuer: &str,
    allowed: &AllowedAlgs,
    limits: &Limits,
) -> Result<AttestationContent, ProofError> {
    let (content, id) = verify_attestation(sign1, expected_issuer, allowed, limits)?;
    if !claim_kind(&content).is_status() {
        return Err(ErrorCode::SchemaViolation.err(format!(
            "status object {id} has claim.type not in revoke|supersede|withdraw|compromise"
        )));
    }
    Ok(content)
}

/// Convert a created status object into the verification-facing wrapper.
pub fn to_signed_status(created: &CreatedAttestation) -> Result<SignedStatus, ProofError> {
    claim_kind(&created.content)
        .is_status()
        .then_some(())
        .ok_or_else(|| ErrorCode::SchemaViolation.err("not a status object"))?;
    Ok(SignedStatus {
        content: created.content.clone(),
        sign1: created.sign1.clone(),
    })
}

/// A created evidence object: validated content, canonical bytes, id.
#[derive(Debug, Clone)]
pub struct CreatedEvidence {
    pub content: Evidence,
    pub canonical: Vec<u8>,
    pub id: String,
}

/// Validate evidence fields and assign its id. Evidence carries no signature
/// itself; tamper-evidence comes from the id binding (and from the referenced
/// attestation, when present).
// PE-EVID-001 (schema before id).
pub fn make_evidence(
    kind: EvidenceKind,
    digest: HashRef,
    attestation_ref: Option<String>,
    hint: Option<String>,
    limits: &Limits,
) -> Result<CreatedEvidence, ProofError> {
    if let Some(r) = &attestation_ref {
        if r.is_empty() || r.len() > 1024 {
            return Err(ErrorCode::SchemaViolation.err("bad attestation_ref"));
        }
        if !r.starts_with("att:v1:") {
            return Err(ErrorCode::SchemaViolation
                .err(format!("attestation_ref {r} must start with att:v1:")));
        }
    }
    let content = Evidence {
        v: 1,
        kind,
        digest,
        attestation_ref,
        hint,
    };
    let value = evidence_to_cbor(&content);
    let canonical = encode_canonical(&value);
    let back = cbor_to_evidence(&decode_and_check_canonical(&canonical, limits)?, limits)?;
    if back != content {
        return Err(ErrorCode::SchemaViolation.err("evidence did not survive canonical round-trip"));
    }
    let id = evidence_id(&canonical);
    Ok(CreatedEvidence {
        content,
        canonical,
        id,
    })
}

/// Verify evidence bytes: canonical form + schema + id binding.
pub fn verify_evidence(
    canonical: &[u8],
    expected_id: Option<&str>,
    limits: &Limits,
) -> Result<(Evidence, String), ProofError> {
    let value = decode_and_check_canonical(canonical, limits)?;
    let content = cbor_to_evidence(&value, limits)?;
    let id = evidence_id(canonical);
    if let Some(expect) = expected_id {
        verify_id(proof_core::model::id_prefix::EVIDENCE, expect, canonical)?;
    }
    Ok((content, id))
}

/// A created relationship: validated content, canonical bytes, id.
/// Grounding (backing evidence for trust-relevant types) is NOT checked here —
/// that is topology validation in `proof-graph`. This function only binds bytes to id.
#[derive(Debug, Clone)]
pub struct CreatedRelationship {
    pub content: Relationship,
    pub canonical: Vec<u8>,
    pub id: String,
}

pub fn make_relationship(
    content: Relationship,
    limits: &Limits,
) -> Result<CreatedRelationship, ProofError> {
    if content.v != 1 {
        return Err(ErrorCode::UnsupportedVersion.err("only relationship v=1 supported"));
    }
    let value = relationship_to_cbor(&content);
    let canonical = encode_canonical(&value);
    let back = cbor_to_relationship(&decode_and_check_canonical(&canonical, limits)?, limits)?;
    if back != content {
        return Err(
            ErrorCode::SchemaViolation.err("relationship did not survive canonical round-trip")
        );
    }
    let id = relationship_id(&canonical);
    Ok(CreatedRelationship {
        content,
        canonical,
        id,
    })
}

/// Verify relationship bytes: canonical form + schema + id binding.
pub fn verify_relationship(
    canonical: &[u8],
    expected_id: Option<&str>,
    limits: &Limits,
) -> Result<(Relationship, String), ProofError> {
    let value = decode_and_check_canonical(canonical, limits)?;
    let content = cbor_to_relationship(&value, limits)?;
    let id = relationship_id(canonical);
    if let Some(expect) = expected_id {
        verify_id(proof_core::model::id_prefix::REL, expect, canonical)?;
    }
    Ok((content, id))
}

/// Shared fixed fixtures (deterministic; also used by golden vectors 06–08).
pub mod fixtures {
    use super::*;
    use proof_core::model::{Claim, EventType, MetaValue};
    use proof_core::{HashAlgorithm, HashRef};

    pub fn test_key() -> Ed25519Key {
        Ed25519Key::from_seed(&TEST_SEED)
    }

    pub fn fixed_event_content() -> EventContent {
        EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: "acct:merchant-01".into(),
            effective_at: 1_700_000_000,
            // Fixed 32-byte digest always satisfies Sha256 length: direct
            // construction keeps even fixture helpers panic-free (PE-SEC-004).
            payload_ref: HashRef {
                v: 1,
                alg: HashAlgorithm::Sha256,
                digest: vec![0xABu8; 32],
            },
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        }
    }

    pub fn fixed_attestation_content(issuer: &str, subject: &str) -> AttestationContent {
        AttestationContent {
            v: 1,
            issuer: issuer.into(),
            subject: subject.into(),
            claim: Claim {
                claim_type: "payment.created-observed".into(),
                fields: vec![("order".into(), MetaValue::Text("ord-1".into()))],
            },
            issued_at: 1_700_000_100,
            expires_at: Some(1_800_000_000),
            evidence_ref: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use proof_core::model::{Claim, MetaValue};

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn event_create_verify_ok() {
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        assert!(ev.id.starts_with("evt:v1:"));
        let (content, id) = verify_event(&ev.canonical, Some(&ev.id), &lim()).unwrap();
        assert_eq!(content, ev.content);
        assert_eq!(id, ev.id);
        // No expected id also works (self-consistent recompute).
        let (_, id2) = verify_event(&ev.canonical, None, &lim()).unwrap();
        assert_eq!(id2, ev.id);
    }

    #[test]
    fn event_mutation_breaks_id() {
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let mut mutated = ev.content.clone();
        mutated.metadata = vec![("order".into(), MetaValue::Text("ord-2".into()))];
        let bad = create_event(mutated, &lim()).unwrap();
        assert_ne!(bad.id, ev.id);
        // Old id against new bytes must fail.
        let e = verify_event(&bad.canonical, Some(&ev.id), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::IdMismatch);
    }

    #[test]
    fn attestation_sign_verify_ok() {
        let key = test_key();
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let at = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        assert!(at.id.starts_with("att:v1:"));
        let (content, id) =
            verify_attestation(&at.sign1, &key.key_ref(), &AllowedAlgs::strict(), &lim()).unwrap();
        assert_eq!(content, at.content);
        assert_eq!(id, at.id);
    }

    #[test]
    fn attestation_one_byte_tamper_fails() {
        let key = test_key();
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let at = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let mut bad = at.sign1.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01; // inside signature bytes: structure stays valid.
        let e =
            verify_attestation(&bad, &key.key_ref(), &AllowedAlgs::strict(), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
    }

    #[test]
    fn attestation_wrong_key_fails() {
        let key = test_key();
        let other = Ed25519Key::from_seed(&[7u8; 32]);
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let at = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let e = verify_attestation(&at.sign1, &other.key_ref(), &AllowedAlgs::strict(), &lim())
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
    }

    #[test]
    fn attest_refuses_foreign_issuer() {
        let key = test_key();
        let other = Ed25519Key::from_seed(&[7u8; 32]);
        // Content names `other` but is signed with `key`: must refuse to sign.
        let content = fixed_attestation_content(&other.key_ref(), "evt:v1:x");
        let e = attest(content, &key, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn attest_refuses_bad_time_order() {
        let key = test_key();
        let mut content = fixed_attestation_content(&key.key_ref(), "evt:v1:x");
        content.issued_at = 200;
        content.expires_at = Some(100);
        let e = attest(content, &key, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn attest_refuses_empty_claim_type() {
        let key = test_key();
        let mut content = fixed_attestation_content(&key.key_ref(), "evt:v1:x");
        content.claim = Claim {
            claim_type: "".into(),
            fields: vec![],
        };
        let e = attest(content, &key, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn evidence_create_verify_ok_and_tamper_fails() {
        use proof_core::{HashAlgorithm, HashRef};
        let digest = HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap();
        let ev = make_evidence(
            EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
            digest,
            Some("att:v1:ref".into()),
            None,
            &lim(),
        )
        .unwrap();
        assert!(ev.id.starts_with("evd:v1:"));
        let (content, id) = verify_evidence(&ev.canonical, Some(&ev.id), &lim()).unwrap();
        assert_eq!(content, ev.content);
        assert_eq!(id, ev.id);
        // Flip a digest byte: structure stays valid CBOR, id must mismatch.
        let mut tampered = ev.content.clone();
        tampered.digest = HashRef::new(HashAlgorithm::Sha256, vec![0xEFu8; 32]).unwrap();
        let bad = make_evidence(
            tampered.kind,
            tampered.digest,
            tampered.attestation_ref,
            tampered.hint,
            &lim(),
        )
        .unwrap();
        let e = verify_evidence(&bad.canonical, Some(&ev.id), &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::IdMismatch);
    }

    #[test]
    fn revoke_attestation_signs_status_object() {
        let key = test_key();
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let at = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let rev = revoke_attestation(&at.id, Some("fraud"), &key, 1_700_000_300, &lim()).unwrap();
        assert!(rev.content.claim.claim_type == "revoke");
        assert_eq!(rev.content.subject, at.id);
        // Round-trip: the pipeline-facing verifier accepts it as a status object.
        let content =
            verify_status_object(&rev.sign1, &key.key_ref(), &AllowedAlgs::strict(), &lim())
                .unwrap();
        assert_eq!(content, rev.content);
        assert_eq!(crate::claim::revocation_target(&content).unwrap(), at.id);
    }

    #[test]
    fn supersede_attestation_signs_status_object() {
        let key = test_key();
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let a = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let b = attest(
            proof_core::model::AttestationContent {
                issued_at: 1_700_000_101,
                ..fixed_attestation_content(&key.key_ref(), &ev.id)
            },
            &key,
            &lim(),
        )
        .unwrap();
        let sup = supersede_attestation(&a.id, &b.id, &key, 1_700_000_300, &lim()).unwrap();
        let content =
            verify_status_object(&sup.sign1, &key.key_ref(), &AllowedAlgs::strict(), &lim())
                .unwrap();
        let (old, new) = crate::claim::supersession_pair(&content).unwrap();
        assert_eq!((old, new), (a.id.as_str(), b.id.as_str()));
    }

    #[test]
    fn status_builders_refuse_garbage() {
        let key = test_key();
        let e = revoke_attestation("", None, &key, 1, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
        let e = supersede_attestation("same", "same", &key, 1, &lim()).unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
        // A statement attestation must never pass the status-object verifier.
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let s = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let e = verify_status_object(&s.sign1, &key.key_ref(), &AllowedAlgs::strict(), &lim())
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn status_object_tamper_detected() {
        let key = test_key();
        let ev = create_event(fixed_event_content(), &lim()).unwrap();
        let at = attest(
            fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let rev = revoke_attestation(&at.id, None, &key, 1_700_000_300, &lim()).unwrap();
        // Re-sign the SAME canonical payload with a different key: the kid-bound
        // issuer (other) differs from the payload issuer (key) → MUST fail.
        let other = Ed25519Key::from_seed(&[7u8; 32]);
        let forged_sign1 = sign_ed25519(&rev.canonical, &other);
        // Expected signer is the payload issuer (key); the forgery was signed by
        // other, so kid binding fails — trust never follows the attacker kid.
        let e = verify_status_object(
            &forged_sign1,
            &key.key_ref(),
            &AllowedAlgs::strict(),
            &lim(),
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
        // A valid status object stated under the WRONG expected signer also
        // fails: the caller names who must have signed, full stop.
        let e = verify_status_object(&rev.sign1, &other.key_ref(), &AllowedAlgs::strict(), &lim())
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::SignatureInvalid);
    }
}
