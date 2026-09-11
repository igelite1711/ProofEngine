// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! ProofBuilder: assemble a portable Proof from validated artifacts.
//! Members must be `Created*` outputs (already schema-valid with bound ids).
//! The builder sorts members by id, binds them into `proof_id`, and self-checks
//! that the emitted bytes re-parse to the identical Proof.

use proof_core::{
    model::{Proof, Proposition, VocabularyDecl},
    ErrorCode, Limits, ProofError,
};
use proof_crypto::build::{CreatedAttestation, CreatedEvent, CreatedEvidence, CreatedRelationship};
use proof_crypto::id::proof_id_full;
use proof_format::{decode_and_check_canonical, encode_canonical, proof_to_cbor};
use std::collections::HashSet;

/// Assembled, serialized proof.
#[derive(Debug, Clone)]
pub struct BuiltProof {
    pub proof: Proof,
    pub canonical: Vec<u8>,
    pub id: String,
}

#[derive(Debug, Default)]
pub struct ProofBuilder {
    proposition: Option<Proposition>,
    created_at: u64,
    events: Vec<CreatedEvent>,
    attestations: Vec<CreatedAttestation>,
    evidence: Vec<CreatedEvidence>,
    relationships: Vec<CreatedRelationship>,
    referenced_proofs: Vec<String>,
    vocabularies: Vec<VocabularyDecl>,
}

impl ProofBuilder {
    pub fn new(proposition: Proposition, created_at: u64) -> Self {
        Self {
            proposition: Some(proposition),
            created_at,
            ..Default::default()
        }
    }

    pub fn add_event(&mut self, e: CreatedEvent) {
        self.events.push(e);
    }

    pub fn add_attestation(&mut self, a: CreatedAttestation) {
        self.attestations.push(a);
    }

    pub fn add_evidence(&mut self, e: CreatedEvidence) {
        self.evidence.push(e);
    }

    pub fn add_relationship(&mut self, r: CreatedRelationship) {
        self.relationships.push(r);
    }

    /// Record that this proof was composed from another proof (SPEC §7).
    /// The id shape is checked now (`prf:v1:` + 32-byte digest); sorting,
    /// dedup, count bound, and self-reference are enforced at build time and
    /// re-checked by every verifier. References are linkage only.
    pub fn add_referenced_proof(&mut self, id: String) -> Result<(), ProofError> {
        proof_crypto::id::check_proof_ref_shape(&id)?;
        self.referenced_proofs.push(id);
        Ok(())
    }

    /// Declare a vocabulary namespace used by this proof's labels, at a
    /// version. Sorted, deduped, and bound at build time; bound by `proof_id`
    /// when present, byte-identical V1 encoding when absent. Declaration is
    /// provenance, not permission: acceptance is policy (see
    /// `VocabularyAccept` and policy v2 `vocabulary_accepted`).
    pub fn add_vocabulary(&mut self, ns: String, version: u64) -> Result<(), ProofError> {
        if ns.is_empty() || ns.len() > 128 {
            return Err(ErrorCode::SchemaViolation.err("vocabulary ns length out of bounds"));
        }
        if ns.contains(':') || ns.contains(char::is_whitespace) {
            return Err(
                ErrorCode::SchemaViolation.err("vocabulary ns must not contain ':' or whitespace")
            );
        }
        self.vocabularies.push(VocabularyDecl { ns, version });
        Ok(())
    }

    fn check_duplicates(ids: &[String], what: &str) -> Result<(), ProofError> {
        let mut seen = HashSet::new();
        for id in ids {
            if !seen.insert(id) {
                return Err(ErrorCode::SchemaViolation.err(format!("duplicate {what} member {id}")));
            }
        }
        Ok(())
    }

    pub fn build(mut self, limits: &Limits) -> Result<BuiltProof, ProofError> {
        let proposition = self
            .proposition
            .take()
            .ok_or_else(|| ErrorCode::SchemaViolation.err("proof needs a proposition"))?;
        if proposition.v != 1 {
            return Err(ErrorCode::UnsupportedVersion.err("only proposition v=1 supported"));
        }
        // Deterministic member order: sort by id.
        self.events.sort_by(|a, b| a.id.cmp(&b.id));
        self.attestations.sort_by(|a, b| a.id.cmp(&b.id));
        self.evidence.sort_by(|a, b| a.id.cmp(&b.id));
        self.relationships.sort_by(|a, b| a.id.cmp(&b.id));

        let event_ids: Vec<String> = self.events.iter().map(|e| e.id.clone()).collect();
        let att_ids: Vec<String> = self.attestations.iter().map(|a| a.id.clone()).collect();
        let evd_ids: Vec<String> = self.evidence.iter().map(|e| e.id.clone()).collect();
        let rel_ids: Vec<String> = self.relationships.iter().map(|r| r.id.clone()).collect();
        Self::check_duplicates(&event_ids, "event")?;
        Self::check_duplicates(&att_ids, "attestation")?;
        Self::check_duplicates(&evd_ids, "evidence")?;
        Self::check_duplicates(&rel_ids, "relationship")?;
        // Composition linkage: sorted, deduped, bounded. Empty → byte-identical
        // V1 binding (see `proof_id_full`).
        self.referenced_proofs.sort();
        self.referenced_proofs.dedup();
        if self.referenced_proofs.len() > limits.max_referenced_proofs {
            return Err(ErrorCode::LimitExceeded.err("too many referenced proofs"));
        }
        // Vocabulary declarations: same additive discipline.
        self.vocabularies.sort_by(|a, b| a.ns.cmp(&b.ns));
        self.vocabularies.dedup_by(|a, b| a.ns == b.ns);
        if self.vocabularies.len() > limits.max_vocabularies {
            return Err(ErrorCode::LimitExceeded.err("too many vocabularies"));
        }

        let prop_cbor = proof_format::proposition_to_cbor(&proposition);
        let vocab_pairs: Vec<(String, u64)> = self
            .vocabularies
            .iter()
            .map(|vd| (vd.ns.clone(), vd.version))
            .collect();
        let id = proof_id_full(
            &prop_cbor,
            &event_ids,
            &att_ids,
            &evd_ids,
            &rel_ids,
            &self.referenced_proofs,
            &vocab_pairs,
        );
        if self.referenced_proofs.iter().any(|r| r == &id) {
            return Err(ErrorCode::CycleDetected.err("proof cannot reference itself"));
        }

        let proof = Proof {
            v: 1,
            proof_id: id.clone(),
            proposition,
            events: self.events.iter().map(|e| e.content.clone()).collect(),
            attestations: self
                .attestations
                .iter()
                .map(|a| proof_core::model::StoredAttestation {
                    content: a.content.clone(),
                    sign1: a.sign1.clone(),
                })
                .collect(),
            evidence: self.evidence.iter().map(|e| e.content.clone()).collect(),
            relationships: self
                .relationships
                .iter()
                .map(|r| r.content.clone())
                .collect(),
            referenced_proofs: self.referenced_proofs.clone(),
            vocabularies: self.vocabularies.clone(),
            created_at: self.created_at,
        };
        let canonical = encode_canonical(&proof_to_cbor(&proof)?);
        if canonical.len() > limits.max_proof_size {
            return Err(ErrorCode::LimitExceeded.err("built proof exceeds max_proof_size"));
        }
        // Self-check: the pipeline must parse what the builder emits.
        let back =
            proof_format::cbor_to_proof(&decode_and_check_canonical(&canonical, limits)?, limits)?;
        if back != proof {
            return Err(ErrorCode::SchemaViolation.err("built proof failed self-check round-trip"));
        }
        Ok(BuiltProof {
            proof,
            canonical,
            id,
        })
    }
}
