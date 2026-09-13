// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! VerifiedState: the exact, minimal view of a verified proof that policy
//! evaluation may consume. Derived from a `VerifyReport` plus the parsed
//! `Proof` it describes — never from databases, reputation, or prose.

use proof_core::{
    model::{vocabulary_ns, EvidenceKind, EvidenceStatus, Proof, RelType, VocabularyDecl},
    ErrorCode, LifecycleStatus, ProofError,
};
use proof_verify::{Validity, VerifyReport};
use std::collections::{HashMap, HashSet};

/// One verified statement claim, projected for policy adjudication
/// (delegation chains, transparency inclusion, conflict review).
#[derive(Debug, Clone)]
pub struct ClaimSummary {
    pub attestation_id: String,
    pub issuer: String,
    pub subject: String,
    pub claim_type: String,
}

/// One validated relationship edge with its asserter, for endpoint-aware
/// policy evaluation (identity bindings and contradiction review).
#[derive(Debug, Clone)]
pub struct EdgeFact {
    pub from: String,
    pub rel_type: RelType,
    pub to: String,
    /// Issuer of the backing attestation (`attestation_ref`), if the edge
    /// carries one that resolved to a verified attestation.
    pub attester: Option<String>,
    /// The backing `attestation_ref` id itself, if any (for activity checks:
    /// only edges backed by lifecycle-ACTIVE attestations count for trust).
    pub attestation: Option<String>,
}

/// A delegation grant projected from a verified `delegate` attestation:
/// `delegator` (issuer) grants `delegatee` (subject) `scope`.
#[derive(Debug, Clone)]
pub struct Delegation {
    pub attestation_id: String,
    pub delegator: String,
    pub delegatee: String,
    pub scope: Option<String>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

/// An identity binding projected from a verified `identity.bind`
/// attestation: `asserter` states `subject` ≡ `equivalent`.
#[derive(Debug, Clone)]
pub struct IdentityBinding {
    pub attestation_id: String,
    pub asserter: String,
    pub subject: String,
    pub equivalent: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedState {
    pub proof_id: String,
    pub crypto_valid: bool,
    pub evidence_valid: bool,
    /// Caller-feed health for status inputs (V1.1 F2 fix). False when any
    /// STATUS-stage check failed. Proof validity is unaffected (ineffective
    /// effects never apply), but feed operators SHOULD alert: it
    /// distinguishes "proof revoked" from "feed broken".
    pub status_inputs_valid: bool,
    /// Issuers whose attestations carry verified signatures in this proof.
    pub verified_issuers: Vec<String>,
    /// Ids of signature-verified attestations (aligned with `attestation_times`).
    pub attestation_ids: Vec<String>,
    /// Ids of verified statements whose lifecycle is ACTIVE (timely,
    /// unrevoked, uncompromised, fresh info). Delegation chains traverse
    /// active links only.
    pub active_attestation_ids: Vec<String>,
    /// Objects the pipeline lifecycle marked SUPERSEDED (subset of
    /// `attestation_ids`). Historical records: valid, but stale.
    // PE-POLICY-006: lifecycle-derived currency view.
    pub superseded_ids: Vec<String>,
    /// (issued_at, expires_at) aligned with `attestation_ids`.
    pub attestation_times: Vec<(u64, Option<u64>)>,
    pub rel_types: Vec<RelType>,
    pub evidence_kinds: Vec<EvidenceKind>,
    /// The proof's created_at timestamp (covered by the proof_id binding;
    /// V1 CORE freeze deviation, pre-V1.0 wire fix).
    /// Used by the `proof_fresh` policy requirement (V1.1).
    pub proof_created_at: u64,
    /// Verified statement claims (signature-verified, any lifecycle).
    /// Delegation chains, transparency inclusion, and conflict review read here.
    pub claims: Vec<ClaimSummary>,
    /// Validated relationship edges with asserters (endpoint-aware facts for
    /// identity bindings and contradiction review).
    pub edges: Vec<EdgeFact>,
    /// Delegation grants from verified `delegate` attestations.
    pub delegations: Vec<Delegation>,
    /// Identity bindings from verified `identity.bind` attestations.
    pub identity_bindings: Vec<IdentityBinding>,
    /// Artifact ids covered by valid withdrawals (any artifact kind).
    pub withdrawn_ids: Vec<String>,
    /// Namespaces used by member labels (for vocabulary policy).
    pub vocabularies_used: Vec<String>,
    /// Namespaces declared by the proof (possibly empty).
    pub vocabularies_declared: Vec<VocabularyDecl>,
    /// Conflict groups from the verification report (representation only).
    pub conflicts: Vec<proof_verify::ConflictRecord>,
    /// Composition linkage: sorted source proof ids bound by `proof_id`
    /// (possibly empty). Reference hooks (`requires_reference`,
    /// `forbids_reference`) read this direct linkage; transitive closure
    /// is the bundle layer's job (`proof_verify::resolve`).
    pub referenced_proofs: Vec<String>,
    /// Per-evidence derived status (id, kind, status) for usability policy.
    pub evidence_statuses: Vec<EvidenceStatusEntry>,
}

/// One evidence item's derived status, projected for policy.
#[derive(Debug, Clone)]
pub struct EvidenceStatusEntry {
    pub id: String,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    /// The evidence item's `attestation_ref` (backing attestation id, if any).
    pub attestation_ref: Option<String>,
}

impl VerifiedState {
    pub fn has_transparency(&self) -> bool {
        self.evidence_kinds
            .contains(&EvidenceKind::new(EvidenceKind::TRANSPARENCY_RECEIPT))
    }
}

/// Build the evaluation view. Fails (caller error, not a verdict) when the
/// report and proof do not belong together — evaluation must never run on a
/// mismatched pair.
pub fn state_from_report_and_proof(
    report: &VerifyReport,
    proof: &Proof,
) -> Result<VerifiedState, ProofError> {
    let rid = report.proof_id.as_deref().ok_or_else(|| {
        ErrorCode::SchemaViolation.err("no proof id in report: proof never parsed")
    })?;
    if rid != proof.proof_id {
        return Err(ErrorCode::SchemaViolation.err("report and proof describe different proofs"));
    }
    // Signature-verified attestation ids, read off the report's own records.
    let verified: HashSet<&str> = report
        .checks
        .iter()
        .filter(|c| c.ok && c.stage == "SIGNATURES")
        .filter_map(|c| c.object.strip_prefix("att:"))
        .collect();
    // PE-TRUST-004: embedded status attestations (revoke/supersede/withdraw/
    // compromise) must never satisfy `issuer_trusted` / populate validity
    // intervals: a revocation authority is not (by signature alone) a
    // statement issuer.
    let status_objects: HashSet<&str> = report.status_objects.iter().map(|s| s.as_str()).collect();
    // Issuer of every signature-verified attestation (statements and status),
    // for edge-attester resolution.
    let mut issuer_by_id: HashMap<String, String> = HashMap::new();
    let mut verified_contents: HashMap<String, proof_core::model::AttestationContent> =
        HashMap::new();
    for a in &proof.attestations {
        let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(&a.content));
        let id = proof_crypto::id::attestation_id(&canon);
        if verified.contains(id.as_str()) {
            issuer_by_id.insert(id.clone(), a.content.issuer.clone());
            verified_contents.insert(id, a.content.clone());
        }
    }
    let mut verified_issuers = vec![];
    let mut attestation_ids = vec![];
    let mut attestation_times = vec![];
    let mut claims = vec![];
    let mut delegations = vec![];
    let mut identity_bindings = vec![];
    let mut active_attestation_ids = vec![];
    for a in &proof.attestations {
        let canon = proof_format::encode_canonical(&proof_format::attestation_to_cbor(&a.content));
        let id = proof_crypto::id::attestation_id(&canon);
        if verified.contains(id.as_str()) && !status_objects.contains(id.as_str()) {
            verified_issuers.push(a.content.issuer.clone());
            attestation_times.push((a.content.issued_at, a.content.expires_at));
            attestation_ids.push(id.clone());
            claims.push(ClaimSummary {
                attestation_id: id.clone(),
                issuer: a.content.issuer.clone(),
                subject: a.content.subject.clone(),
                claim_type: a.content.claim.claim_type.clone(),
            });
            // Reserved statement-level conventions, projected for policy.
            if a.content.claim.claim_type == proof_crypto::claim::CLAIM_DELEGATE {
                let scope = a.content.claim.fields.iter().find_map(|(k, v)| {
                    if k == "scope" {
                        match v {
                            proof_core::model::MetaValue::Text(s) => Some(s.clone()),
                            _ => None,
                        }
                    } else {
                        None
                    }
                });
                delegations.push(Delegation {
                    attestation_id: id,
                    delegator: a.content.issuer.clone(),
                    delegatee: a.content.subject.clone(),
                    scope,
                    issued_at: a.content.issued_at,
                    expires_at: a.content.expires_at,
                });
            } else if a.content.claim.claim_type == proof_crypto::claim::CLAIM_IDENTITY_BIND {
                if let Some(equivalent) = a.content.claim.fields.iter().find_map(|(k, v)| {
                    if k == "equivalent" {
                        match v {
                            proof_core::model::MetaValue::Text(s) => Some(s.clone()),
                            _ => None,
                        }
                    } else {
                        None
                    }
                }) {
                    identity_bindings.push(IdentityBinding {
                        attestation_id: id,
                        asserter: a.content.issuer.clone(),
                        subject: a.content.subject.clone(),
                        equivalent,
                    });
                }
            }
        }
    }
    for l in &report.lifecycle {
        if l.status == LifecycleStatus::Active {
            if let Some(id) = l.object.strip_prefix("att:") {
                active_attestation_ids.push(id.to_string());
            }
        }
    }
    let mut edges = vec![];
    for r in &proof.relationships {
        let attestation = r.attestation_ref.clone();
        edges.push(EdgeFact {
            from: r.from.clone(),
            rel_type: r.rel_type.clone(),
            to: r.to.clone(),
            attester: r.attestation_ref.as_deref().and_then(|aref| {
                // Only signature-verified asserters count.
                if verified.contains(aref) {
                    issuer_by_id.get(aref).cloned()
                } else {
                    None
                }
            }),
            attestation,
        });
    }
    let vocabularies_used: Vec<String> = {
        let mut set = HashSet::new();
        for e in &proof.events {
            set.insert(vocabulary_ns(e.event_type.as_str()).to_string());
        }
        for a in &proof.attestations {
            set.insert(vocabulary_ns(a.content.claim.claim_type.as_str()).to_string());
        }
        for e in &proof.evidence {
            set.insert(vocabulary_ns(e.kind.as_str()).to_string());
        }
        for r in &proof.relationships {
            set.insert(vocabulary_ns(r.rel_type.as_str()).to_string());
        }
        set.insert(vocabulary_ns(proof.proposition.kind.as_str()).to_string());
        set.insert(vocabulary_ns(proof.proposition.predicate.as_str()).to_string());
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        v
    };
    let superseded_ids = report
        .lifecycle
        .iter()
        .filter(|l| l.status == LifecycleStatus::Superseded)
        .filter_map(|l| l.object.strip_prefix("att:"))
        .map(str::to_string)
        .collect();
    Ok(VerifiedState {
        proof_id: rid.to_string(),
        crypto_valid: report.cryptographic_validity == Validity::Valid,
        evidence_valid: report.evidence_validity == Validity::Valid,
        status_inputs_valid: report.status_inputs_valid,
        verified_issuers,
        attestation_ids,
        active_attestation_ids,
        attestation_times,
        superseded_ids,
        rel_types: proof
            .relationships
            .iter()
            .map(|r| r.rel_type.clone())
            .collect(),
        evidence_kinds: proof.evidence.iter().map(|e| e.kind.clone()).collect(),
        proof_created_at: proof.created_at,
        claims,
        edges,
        delegations,
        identity_bindings,
        withdrawn_ids: report.withdrawn_ids.clone(),
        referenced_proofs: proof.referenced_proofs.clone(),
        vocabularies_used,
        vocabularies_declared: proof.vocabularies.clone(),
        conflicts: report.conflicts.clone(),
        evidence_statuses: {
            let by_object: HashMap<&str, proof_core::model::EvidenceStatus> = report
                .evidence_status
                .iter()
                .filter_map(|rec| rec.object.strip_prefix("evd:").map(|id| (id, rec.status)))
                .collect();
            proof
                .evidence
                .iter()
                .map(|e| {
                    let canon = proof_format::encode_canonical(&proof_format::evidence_to_cbor(e));
                    let id = proof_crypto::id::evidence_id(&canon);
                    let status = by_object
                        .get(id.as_str())
                        .copied()
                        .unwrap_or(proof_core::model::EvidenceStatus::Unknown);
                    EvidenceStatusEntry {
                        id,
                        kind: e.kind.clone(),
                        status,
                        attestation_ref: e.attestation_ref.clone(),
                    }
                })
                .collect()
        },
    })
}
