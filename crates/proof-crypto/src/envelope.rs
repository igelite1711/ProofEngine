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
    // caller supplies trust inputs; otherwise only shape-check presence.
    if matches!(env.kind, ArtifactKind::Attestation | ArtifactKind::Status) {
        if let (Some(issuer), Some(al)) = (expected_issuer, allowed) {
            if let Some(s) = &env.sign1_b64u {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                let sig = URL_SAFE_NO_PAD
                    .decode(s)
                    .map_err(|_| ErrorCode::Malformed.err("envelope sign1 is not base64url"))?;
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
