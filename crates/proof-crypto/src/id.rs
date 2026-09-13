// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic object ids: `<prefix>:v1:<b64uNoPad(sha256(canonical))>`.
//! Uses SHA-256 for ids in V0.1 (hash agility via `v` for future algs).
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use proof_format::{encode_canonical, CborValue};

use crate::hash::sha256;

pub fn b64u_nopad(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>, proof_core::ProofError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| proof_core::ErrorCode::InvalidBase64Url.err(format!("bad base64url: {e}")))
}

// PE-LONG-001: identifier digest migration window (docs/LONGEVITY.md §3):
// new digest algorithms arrive via a new id version (`:v1:` → `:v2:`), dual-
// verify window, then retirement; unknown versions fail closed today.
fn id_with(prefix: &str, canonical: &[u8]) -> String {
    format!("{prefix}:v1:{}", b64u_nopad(&sha256(canonical)))
}

// PE-CRYPTO-006 (deterministic sha256 ids) · PE-EVID-004.
pub fn event_id(canonical_event_content: &[u8]) -> String {
    id_with(proof_core::model::id_prefix::EVENT, canonical_event_content)
}

pub fn attestation_id(canonical_att_content: &[u8]) -> String {
    id_with(
        proof_core::model::id_prefix::ATTESTATION,
        canonical_att_content,
    )
}

pub fn evidence_id(canonical_evidence: &[u8]) -> String {
    id_with(proof_core::model::id_prefix::EVIDENCE, canonical_evidence)
}

/// Relationship id binds the FULL canonical content (from, type, to, AND both
/// refs). NOTE: this deliberately covers `attestation_ref` too — an early draft
/// hashed only `{from,type,to,evidence_ref}`, which would let an attacker
/// re-ground an edge to a different attestation without changing its id.
pub fn relationship_id(canonical_rel: &[u8]) -> String {
    id_with(proof_core::model::id_prefix::REL, canonical_rel)
}

/// Proof id binds the proposition plus the exact sorted member id sets and the
/// creation timestamp. Byte-precise construction: canonical CBOR of
/// `{"v":1, "proposition":<prop>, "created_at":<uint>, "events":[ids…],
/// "attestations":[ids…], "evidence":[ids…], "relationships":[ids…]}` (each
/// id list sorted ascending), hashed with SHA-256. `created_at` IS covered by
/// the binding (PE-LI-…): a holder-rewritable timestamp would make
/// `proof_fresh` forgeable, so it is authenticated like every other member.
/// See [`proof_id_with_refs`] for the composition extension: when
/// `referenced_proofs` is empty the binding — and every id it produces — is
/// byte-identical to this function.
// PE-CRYPTO-007 (member-set binding; created_at bound).
pub fn proof_id(
    proposition: &CborValue,
    created_at: u64,
    event_ids: &[String],
    attestation_ids: &[String],
    evidence_ids: &[String],
    relationship_ids: &[String],
) -> String {
    proof_id_with_refs(
        proposition,
        created_at,
        event_ids,
        attestation_ids,
        evidence_ids,
        relationship_ids,
        &[],
    )
}

/// Proof id with composition linkage. `referenced_proofs` MUST already be
/// sorted ascending and deduped (builders and schema parsing enforce this).
/// An empty set encodes the identical binding map as [`proof_id`]: existing
/// V1 proofs keep byte-identical ids. A non-empty set adds one sorted
/// `"referenced_proofs"` key to the binding map, so linkage is tamper-evident
/// (dropping or swapping a reference changes the id).
pub fn proof_id_with_refs(
    proposition: &CborValue,
    created_at: u64,
    event_ids: &[String],
    attestation_ids: &[String],
    evidence_ids: &[String],
    relationship_ids: &[String],
    referenced_proofs: &[String],
) -> String {
    proof_id_full(
        proposition,
        created_at,
        event_ids,
        attestation_ids,
        evidence_ids,
        relationship_ids,
        referenced_proofs,
        &[],
    )
}

/// Proof id with composition linkage and vocabulary declarations.
/// `vocabularies` MUST already be sorted by ns and deduped. Empty sets encode
/// the identical binding map as [`proof_id`]: V1 proofs keep byte-identical
/// ids. Non-empty sets add sorted keys, so declarations are tamper-evident.
// Eight explicit parameters are the point here: every binding term is named
// and mandatory at each call site (the id cannot silently drop a member set).
#[allow(clippy::too_many_arguments)]
pub fn proof_id_full(
    proposition: &CborValue,
    created_at: u64,
    event_ids: &[String],
    attestation_ids: &[String],
    evidence_ids: &[String],
    relationship_ids: &[String],
    referenced_proofs: &[String],
    vocabularies: &[(String, u64)],
) -> String {
    fn sorted(ids: &[String]) -> CborValue {
        let mut v: Vec<String> = ids.to_vec();
        v.sort();
        CborValue::Array(v.into_iter().map(CborValue::Text).collect())
    }
    let binding = CborValue::Map({
        let mut pairs = vec![
            (
                CborValue::Text("attestations".into()),
                sorted(attestation_ids),
            ),
            (
                CborValue::Text("created_at".into()),
                CborValue::Uint(created_at),
            ),
            (CborValue::Text("events".into()), sorted(event_ids)),
            (CborValue::Text("evidence".into()), sorted(evidence_ids)),
            (
                CborValue::Text("relationships".into()),
                sorted(relationship_ids),
            ),
            (CborValue::Text("proposition".into()), proposition.clone()),
            (CborValue::Text("v".into()), CborValue::Uint(1)),
        ];
        if !referenced_proofs.is_empty() {
            pairs.push((
                CborValue::Text("referenced_proofs".into()),
                sorted(referenced_proofs),
            ));
        }
        if !vocabularies.is_empty() {
            // Sort by ns so direct callers with unsorted input still bind
            // deterministically (member id sets sort the same way above).
            let mut vocabs: Vec<(String, u64)> = vocabularies.to_vec();
            vocabs.sort_by(|a, b| a.0.cmp(&b.0));
            pairs.push((
                CborValue::Text("vocabularies".into()),
                CborValue::Array(
                    vocabs
                        .iter()
                        .map(|(ns, version)| {
                            CborValue::Map(vec![
                                (CborValue::Text("ns".into()), CborValue::Text(ns.clone())),
                                (CborValue::Text("version".into()), CborValue::Uint(*version)),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        pairs
    });
    id_with(
        proof_core::model::id_prefix::PROOF,
        &encode_canonical(&binding),
    )
}

/// Validate the *shape* of a composition reference (content is never embedded,
/// so no digest can be recomputed): `prf:v1:` prefix, canonical no-pad
/// base64url, exactly 32 digest bytes. Well-formed is necessary but not
/// sufficient — the pipeline additionally rejects self-references and
/// over-count sets, and treats every reference as linkage-only
/// (REFERENCED, never verified content).
pub fn check_proof_ref_shape(id: &str) -> Result<(), proof_core::ProofError> {
    use proof_core::ErrorCode;
    let rest = id.strip_prefix("prf:v1:").ok_or_else(|| {
        ErrorCode::SchemaViolation.err("referenced proof id must start with prf:v1:")
    })?;
    let raw = b64u_decode(rest)?;
    if b64u_nopad(&raw) != rest {
        return Err(
            ErrorCode::SchemaViolation.err("referenced proof id is not canonical base64url")
        );
    }
    if raw.len() != 32 {
        return Err(ErrorCode::SchemaViolation.err("referenced proof id digest must be 32 bytes"));
    }
    Ok(())
}

pub fn verify_id(prefix: &str, id: &str, canonical: &[u8]) -> Result<(), proof_core::ProofError> {
    let expect_prefix = format!("{prefix}:v1:");
    let rest = id.strip_prefix(expect_prefix.as_str()).ok_or_else(|| {
        proof_core::ErrorCode::IdMismatch.err(format!("id prefix mismatch for {prefix}"))
    })?;
    // Validate base64url shape (reject +//padding/whitespace) AND
    // canonical bits: re-encoding must reproduce the string, else two
    // different strings could name one digest (audit P2, PE-SEC-005).
    let raw = b64u_decode(rest)?;
    if b64u_nopad(&raw) != rest {
        return Err(
            proof_core::ErrorCode::IdMismatch.err("id is not canonical base64url (pad bits?)")
        );
    }
    if raw.len() != 32 {
        return Err(proof_core::ErrorCode::IdMismatch.err("id digest must be 32 bytes (sha-256)"));
    }
    let expect = sha256(canonical);
    if raw.as_slice() != expect.as_slice() {
        return Err(proof_core::ErrorCode::IdMismatch.err("id digest mismatch (tamper?)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_stable_and_bound() {
        let a = event_id(b"canonical-a");
        let b = event_id(b"canonical-a");
        assert_eq!(a, b);
        assert!(a.starts_with("evt:v1:"));
        assert_ne!(a, event_id(b"canonical-b"));
        verify_id("evt", &a, b"canonical-a").unwrap();
    }

    #[test]
    fn id_mismatch_on_tamper() {
        let id = event_id(b"canonical-a");
        let e = verify_id("evt", &id, b"canonical-a-tampered").unwrap_err();
        assert_eq!(e.code, proof_core::ErrorCode::IdMismatch);
    }

    #[test]
    fn id_rejects_non_canonical_b64() {
        // Standard-base64 chars (+, /, =) must not appear in ids.
        for bad in ["evt:v1:ab+cd", "evt:v1:ab/cd", "evt:v1:abcd===="] {
            assert!(verify_id("evt", bad, b"x").is_err());
        }
        // PE-SEC-005: pad-bit variants of the last char name the same digest
        // in lenient decoders — only the canonical re-encoding is accepted
        // here (rejected either at decode or by the canonical-spelling check
        // in verify_id, belt and suspenders against decoder leniency).
        let id = event_id(b"canonical-a");
        let body = &id["evt:v1:".len()..];
        let alphabet: Vec<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                .chars()
                .collect();
        let last = body.chars().last().unwrap();
        let pos = alphabet.iter().position(|&c| c == last).unwrap();
        // Flip the low 2 (pad) bits of the last char: same top 4 bits.
        let base = pos & !3;
        let mut rejected = 0;
        for k in 0..4 {
            let mut v = body.to_string();
            v.pop();
            v.push(alphabet[base | k]);
            let full = format!("evt:v1:{v}");
            if full == id {
                assert!(verify_id("evt", &full, b"canonical-a").is_ok());
            } else {
                assert!(verify_id("evt", &full, b"canonical-a").is_err());
                rejected += 1;
            }
        }
        assert_eq!(rejected, 3, "all non-canonical pad-bit spellings refused");
    }

    /// PE-CRYPTO-009 (FORMAT §3): every id carries exactly one full SHA-256
    /// digest. Truncated or oversized digests cannot name an object.
    #[test]
    fn id_digest_must_be_full_sha256() {
        let id = event_id(b"canonical-a");
        let body = &id["evt:v1:".len()..];
        let raw = b64u_decode(body).unwrap();
        assert_eq!(raw.len(), 32);
        // Truncated digest (31 bytes) must not verify.
        let short = format!("evt:v1:{}", b64u_nopad(&raw[..31]));
        assert_eq!(
            verify_id("evt", &short, b"canonical-a").unwrap_err().code,
            proof_core::ErrorCode::IdMismatch
        );
        // Oversized digest (33 bytes) must not verify either.
        let mut big = raw.clone();
        big.push(0);
        let long = format!("evt:v1:{}", b64u_nopad(&big));
        assert_eq!(
            verify_id("evt", &long, b"canonical-a").unwrap_err().code,
            proof_core::ErrorCode::IdMismatch
        );
    }
}
