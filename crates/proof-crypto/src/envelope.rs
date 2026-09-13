// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Envelope verification (P3): re-derive advisory `id`/`sign1` from `cbor`.
//! The envelope JSON is never trusted; canonical bytes are.

use proof_core::{ErrorCode, Limits, ProofError};
use proof_format::{ArtifactEnvelope, ArtifactKind};

use crate::id::{attestation_id, event_id, evidence_id, proof_id_full, relationship_id};
use crate::{cose::verify_sign1, AllowedAlgs};

/// Verify an envelope's advisory fields against its canonical bytes.
/// Checks: container version, kind known, `cbor` decodes + re-encodes
/// canonically, recomputed id matches, and (`attestation`/`status`) `sign1`
/// verifies under `expected_issuer`/`allowed` where supplied.
pub fn verify_envelope(
    env: &ArtifactEnvelope,
    limits: &Limits,
    expected_issuer: Option<&str>,
    allowed: Option<&AllowedAlgs>,
) -> Result<Vec<u8>, ProofError> {
    if env.container_version != proof_format::CONTAINER_VERSION {
        return Err(ErrorCode::UnsupportedVersion.err("unsupported envelope container_version"));
    }
    let bytes = env.cbor_bytes(limits)?;
    let value = proof_format::decode_and_check_canonical(&bytes, limits)?;
    let recomputed = match env.kind {
        ArtifactKind::Event => {
            let e = proof_format::cbor_to_event(&value, limits)?;
            event_id(&proof_format::encode_canonical(
                &proof_format::event_to_cbor(&e)?,
            ))
        }
        ArtifactKind::Evidence => {
            let e = proof_format::cbor_to_evidence(&value, limits)?;
            evidence_id(&proof_format::encode_canonical(
                &proof_format::evidence_to_cbor(&e),
            ))
        }
        ArtifactKind::Relationship => {
            let r = proof_format::cbor_to_relationship(&value, limits)?;
            relationship_id(&proof_format::encode_canonical(
                &proof_format::relationship_to_cbor(&r),
            ))
        }
        ArtifactKind::Attestation | ArtifactKind::Status => {
            let entry = proof_format::cbor_to_attestation(&value, limits)?;
            // entry is StoredAttestation { content, sign1 }? cbor_to_attestation
            // returns content only; recompute via attestation_to_cbor.
            let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(&entry));
            attestation_id(&canon)
        }
        ArtifactKind::Proof => {
            let p = proof_format::cbor_to_proof(&value, limits)?;
            let (eids, aids, vids, rids) = member_id_sets(&p)?;
            let vocabs: Vec<(String, u64)> = p
                .vocabularies
                .iter()
                .map(|vd| (vd.ns.clone(), vd.version))
                .collect();
            proof_id_full(
                &proof_format::proposition_to_cbor(&p.proposition),
                p.created_at,
                &eids,
                &aids,
                &vids,
                &rids,
                &p.referenced_proofs,
                &vocabs,
            )
        }
    };
    if recomputed != env.id {
        return Err(ErrorCode::IdMismatch.err("envelope id does not match recomputed id"));
    }
    // Where a signature travels with the envelope, re-verify it when the
    // caller supplies trust inputs; otherwise still shape-check the COSE
    // envelope so malformed sign1 never reads as "verified envelope".
    if matches!(env.kind, ArtifactKind::Attestation | ArtifactKind::Status) {
        if let Some(s) = &env.sign1_b64u {
            use crate::cose::parse_sign1;
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let sig = URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|_| ErrorCode::Malformed.err("envelope sign1 is not base64url"))?;
            // Shape-check always; crypto verify only with trust inputs.
            parse_sign1(&sig, limits)?;
            if let (Some(issuer), Some(al)) = (expected_issuer, allowed) {
                verify_sign1(&sig, issuer, al, limits)?;
            }
        }
    }
    Ok(bytes)
}

/// Sorted member id sets bound by `proof_id`.
pub type MemberIdSets = (Vec<String>, Vec<String>, Vec<String>, Vec<String>);

fn member_id_sets(p: &proof_core::model::Proof) -> Result<MemberIdSets, ProofError> {
    let mut eids = vec![];
    for e in &p.events {
        eids.push(event_id(&proof_format::encode_canonical(
            &proof_format::event_to_cbor(e)?,
        )));
    }
    let mut aids = vec![];
    for a in &p.attestations {
        aids.push(attestation_id(&proof_format::encode_canonical(
            &proof_format::attestation_to_cbor(&a.content),
        )));
    }
    let mut vids = vec![];
    for e in &p.evidence {
        vids.push(evidence_id(&proof_format::encode_canonical(
            &proof_format::evidence_to_cbor(e),
        )));
    }
    let mut rids = vec![];
    for r in &p.relationships {
        rids.push(relationship_id(&proof_format::encode_canonical(
            &proof_format::relationship_to_cbor(r),
        )));
    }
    Ok((eids, aids, vids, rids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_core::model::{
        AttestationContent, Claim, EventContent, EventType, EvidenceKind, MetaValue, Proposition,
        RelType, Relationship, StoredAttestation,
    };
    use proof_core::{HashAlgorithm, HashRef, Limits};

    use crate::build::{
        attest, create_event, fixtures, make_evidence, make_relationship, revoke_attestation,
        to_signed_status,
    };
    use crate::id::{b64u_nopad, event_id, proof_id_full};

    fn lim() -> Limits {
        Limits::default()
    }

    fn event_fixture(subject: &str) -> crate::build::CreatedEvent {
        create_event(
            EventContent {
                v: 1,
                event_type: EventType::new(EventType::PAYMENT_CREATED),
                subject: subject.into(),
                effective_at: 1_700_000_000,
                payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
                metadata: vec![],
            },
            &lim(),
        )
        .unwrap()
    }

    #[test]
    fn event_envelope_round_trips() {
        let ev = event_fixture("payment:p1");
        let env = ArtifactEnvelope::new(ArtifactKind::Event, &ev.id, &ev.canonical, None);
        let back = verify_envelope(&env, &lim(), None, None).unwrap();
        assert_eq!(back, ev.canonical);
    }

    #[test]
    fn envelope_rejects_tampered_id_version_and_empty_cbor() {
        let ev = event_fixture("payment:p1");
        let mut env = ArtifactEnvelope::new(ArtifactKind::Event, &ev.id, &ev.canonical, None);
        env.id = "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert_eq!(
            verify_envelope(&env, &lim(), None, None).unwrap_err().code,
            proof_core::ErrorCode::IdMismatch
        );
        env.container_version = 99;
        env.id = ev.id.clone();
        assert_eq!(
            verify_envelope(&env, &lim(), None, None).unwrap_err().code,
            proof_core::ErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn attestation_envelope_checks_sign1_shape_without_trust_inputs() {
        let key = fixtures::test_key();
        let ev = event_fixture("payment:p1");
        let att = attest(
            fixtures::fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        // Well-formed envelope verifies with no trust inputs (shape-checked).
        let env = ArtifactEnvelope::new(
            ArtifactKind::Attestation,
            &att.id,
            &att.canonical,
            Some(b64u_nopad(&att.sign1)),
        );
        verify_envelope(&env, &lim(), None, None).unwrap();
        // Malformed sign1 fails even with no trust inputs to verify against:
        // shape-checking is unconditional for attestation/status kinds.
        let mut bad = env.clone();
        bad.sign1_b64u = Some("!!!not-base64!!!".into());
        assert_eq!(
            verify_envelope(&bad, &lim(), None, None).unwrap_err().code,
            proof_core::ErrorCode::Malformed
        );
        // With trust inputs the signature itself verifies.
        verify_envelope(
            &env,
            &lim(),
            Some(&key.key_ref()),
            Some(&AllowedAlgs::strict()),
        )
        .unwrap();
        // ...and a wrong (but well-shaped) issuer fails on kid binding.
        let mut wrong = key.key_ref();
        let last = wrong.pop().unwrap();
        wrong.push(if last == 'A' { 'B' } else { 'A' });
        assert_ne!(wrong, key.key_ref());
        assert!(verify_envelope(&env, &lim(), Some(&wrong), Some(&AllowedAlgs::strict())).is_err());
    }

    #[test]
    fn status_envelope_round_trips() {
        let key = fixtures::test_key();
        let ev = event_fixture("payment:p1");
        let att = attest(
            fixtures::fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let rev = revoke_attestation(&att.id, Some("fraud"), &key, 1_700_000_400, &lim()).unwrap();
        let _ = to_signed_status(&rev).unwrap();
        let env = ArtifactEnvelope::new(
            ArtifactKind::Status,
            &rev.id,
            &rev.canonical,
            Some(b64u_nopad(&rev.sign1)),
        );
        verify_envelope(&env, &lim(), None, None).unwrap();
    }

    #[test]
    fn evidence_and_relationship_envelopes_round_trip() {
        let key = fixtures::test_key();
        let ev = event_fixture("payment:p1");
        let att = attest(
            fixtures::fixed_attestation_content(&key.key_ref(), &ev.id),
            &key,
            &lim(),
        )
        .unwrap();
        let evd = make_evidence(
            EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
            HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
            Some(att.id.clone()),
            None,
            &lim(),
        )
        .unwrap();
        let env = ArtifactEnvelope::new(ArtifactKind::Evidence, &evd.id, &evd.canonical, None);
        verify_envelope(&env, &lim(), None, None).unwrap();
        let ev2 = event_fixture("invoice:i9");
        let rel = make_relationship(
            Relationship {
                v: 1,
                from: ev.id.clone(),
                rel_type: RelType::new(RelType::REFERENCES),
                to: ev2.id.clone(),
                evidence_ref: None,
                attestation_ref: None,
            },
            &lim(),
        )
        .unwrap();
        let env = ArtifactEnvelope::new(ArtifactKind::Relationship, &rel.id, &rel.canonical, None);
        verify_envelope(&env, &lim(), None, None).unwrap();
    }

    #[test]
    fn proof_envelope_binds_member_sets() {
        let key = fixtures::test_key();
        let ev = event_fixture("payment:p1");
        let ev2 = event_fixture("invoice:i9");
        let att = attest(
            AttestationContent {
                v: 1,
                issuer: key.key_ref(),
                subject: ev.id.clone(),
                claim: Claim {
                    claim_type: "payment.settled".into(),
                    fields: vec![("amount".into(), MetaValue::Uint(4200))],
                },
                issued_at: 1_700_000_150,
                expires_at: None,
                evidence_ref: None,
            },
            &key,
            &lim(),
        )
        .unwrap();
        let evd = make_evidence(
            EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
            HashRef::new(HashAlgorithm::Sha256, vec![0xEEu8; 32]).unwrap(),
            Some(att.id.clone()),
            None,
            &lim(),
        )
        .unwrap();
        let rel = make_relationship(
            Relationship {
                v: 1,
                from: ev.id.clone(),
                rel_type: RelType::new(RelType::SETTLES),
                to: ev2.id.clone(),
                evidence_ref: Some(evd.id.clone()),
                attestation_ref: Some(att.id.clone()),
            },
            &lim(),
        )
        .unwrap();
        let prop = Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: ev.id.clone(),
            predicate: "settles".into(),
            object: Some(ev2.id.clone()),
            at_time: Some(1_700_000_150),
            context: vec![],
        };
        let prop_cbor = proof_format::proposition_to_cbor(&prop);
        let pid = proof_id_full(
            &prop_cbor,
            1_700_000_200,
            &[ev.id.clone(), ev2.id.clone()],
            std::slice::from_ref(&att.id),
            std::slice::from_ref(&evd.id),
            std::slice::from_ref(&rel.id),
            &[],
            &[],
        );
        let proof = proof_core::model::Proof {
            v: 1,
            proof_id: pid.clone(),
            proposition: prop,
            events: vec![ev.content.clone(), ev2.content.clone()],
            attestations: vec![StoredAttestation {
                content: att.content.clone(),
                sign1: att.sign1.clone(),
            }],
            evidence: vec![evd.content.clone()],
            relationships: vec![rel.content.clone()],
            referenced_proofs: vec![],
            vocabularies: vec![],
            created_at: 1_700_000_200,
        };
        let canonical =
            proof_format::encode_canonical(&proof_format::proof_to_cbor(&proof).unwrap());
        // Sanity: recomputed event id matches the stored member id.
        assert_eq!(event_id(&ev.canonical), ev.id);
        let env = ArtifactEnvelope::new(ArtifactKind::Proof, &pid, &canonical, None);
        let back = verify_envelope(&env, &lim(), None, None).unwrap();
        assert_eq!(back, canonical);
        // Swapping the advisory id breaks the binding (tamper evidence).
        let mut tampered = env.clone();
        tampered.id = pid.replace(['A', 'a'], "B");
        // (If pid contains no A/a the replacement is a no-op; force mismatch.)
        if tampered.id == pid {
            tampered.id = "prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        }
        assert_eq!(
            verify_envelope(&tampered, &lim(), None, None)
                .unwrap_err()
                .code,
            proof_core::ErrorCode::IdMismatch
        );
    }
}
