// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal domain model (V1.0 NEUTRAL). Open vocabularies; policy controls acceptance.
//!
//! DESIGN: EventType, EvidenceKind, and RelType are opaque string wrappers.
//! The core provides well-known constants for convenience, but accepts ANY string.
//! Unknown types are NOT rejected at schema stage—validation is the policy's job.
//!
//! This achieves true neutrality: healthcare, logistics, AI, and 100 other domains
//! can extend the vocabulary without modifying proof-core.

use crate::HashRef;
use std::hash::{Hash, Hasher};

/// Event type (open vocabulary). The core transports any string; policy decides
/// which types are acceptable. Well-known V1 types provided as constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventType(String);

impl EventType {
    // Well-known V1 types (for convenience, NOT exhaustive)
    pub const PAYMENT_CREATED: &'static str = "payment.created";
    pub const PAYMENT_COMPLETED: &'static str = "payment.completed";
    pub const INVOICE_ISSUED: &'static str = "invoice.issued";
    pub const DOCUMENT_SIGNED: &'static str = "document.signed";
    pub const PACKAGE_SHIPPED: &'static str = "package.shipped";
    pub const SENSOR_MEASUREMENT_RECORDED: &'static str = "sensor.measurement.recorded";
    pub const AI_ACTION_EXECUTED: &'static str = "ai.action.executed";

    /// Create from any string. No validation at this layer—policy decides acceptance.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is a well-known V1 type (for monitoring/telemetry, not validation).
    pub fn is_well_known(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::PAYMENT_CREATED
                | Self::PAYMENT_COMPLETED
                | Self::INVOICE_ISSUED
                | Self::DOCUMENT_SIGNED
                | Self::PACKAGE_SHIPPED
                | Self::SENSOR_MEASUREMENT_RECORDED
                | Self::AI_ACTION_EXECUTED
        )
    }
}

impl From<&str> for EventType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for EventType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for EventType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Hash for EventType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Evidence kind (open vocabulary). Policy controls which kinds are acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceKind(String);

impl EvidenceKind {
    // Well-known V1 kinds
    pub const SIGNED_EVENT: &'static str = "signed_event";
    pub const SIGNED_DOCUMENT: &'static str = "signed_document";
    pub const RECEIPT: &'static str = "receipt";
    pub const CREDENTIAL: &'static str = "credential";
    pub const MEASUREMENT: &'static str = "measurement";
    pub const TRANSACTION_RECORD: &'static str = "transaction_record";
    pub const TRANSPARENCY_RECEIPT: &'static str = "transparency_receipt";
    pub const DEVICE_ATTESTATION: &'static str = "device_attestation";
    pub const EXTERNAL_REFERENCE: &'static str = "external_reference";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_well_known(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::SIGNED_EVENT
                | Self::SIGNED_DOCUMENT
                | Self::RECEIPT
                | Self::CREDENTIAL
                | Self::MEASUREMENT
                | Self::TRANSACTION_RECORD
                | Self::TRANSPARENCY_RECEIPT
                | Self::DEVICE_ATTESTATION
                | Self::EXTERNAL_REFERENCE
        )
    }
}

impl From<&str> for EvidenceKind {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for EvidenceKind {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for EvidenceKind {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Hash for EvidenceKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Relationship type (open vocabulary). Policy controls which types are acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelType(String);

impl RelType {
    // Well-known V1 types
    pub const OWNS: &'static str = "OWNS";
    pub const CREATED: &'static str = "CREATED";
    pub const SETTLES: &'static str = "SETTLES";
    pub const REFERENCES: &'static str = "REFERENCES";
    pub const CONTAINS: &'static str = "CONTAINS";
    pub const PRODUCED: &'static str = "PRODUCED";
    pub const EXECUTED: &'static str = "EXECUTED";
    pub const ISSUED: &'static str = "ISSUED";
    pub const SUPERSEDES: &'static str = "SUPERSEDES";
    pub const REVOKES: &'static str = "REVOKES";

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Trust-relevant edges MUST carry backing evidence.
    /// This list is part of V1 semantics; well-known types are stable (see VERSIONING.md).
    pub fn requires_grounding(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::OWNS | Self::CREATED | Self::SETTLES | Self::EXECUTED
        )
    }

    pub fn is_well_known(&self) -> bool {
        matches!(
            self.0.as_str(),
            Self::OWNS
                | Self::CREATED
                | Self::SETTLES
                | Self::REFERENCES
                | Self::CONTAINS
                | Self::PRODUCED
                | Self::EXECUTED
                | Self::ISSUED
                | Self::SUPERSEDES
                | Self::REVOKES
        )
    }
}

impl From<&str> for RelType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RelType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for RelType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Hash for RelType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Event content (without id). `metadata` is flat string→scalar, max 16 entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContent {
    pub v: u8,
    pub event_type: EventType,
    pub subject: String,
    pub effective_at: u64,
    pub payload_ref: HashRef,
    pub metadata: Vec<(String, MetaValue)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    Text(String),
    Uint(u64),
    Bool(bool),
}

/// Attestation content (without id and signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationContent {
    pub v: u8,
    pub issuer: String,
    pub subject: String,
    pub claim: Claim,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub claim_type: String,
    pub fields: Vec<(String, MetaValue)>,
}

/// Evidence (without id). `digest` binds the material; `attestation_ref`
/// and `hint` are optional references. IDs are derived, never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub v: u8,
    pub kind: EvidenceKind,
    pub digest: HashRef,
    pub attestation_ref: Option<String>,
    pub hint: Option<String>,
}

/// Relationship (without id): typed directed edge between object ids.
/// `from`/`to` reference verified artifact ids (events, attestations, evidence,
/// or external object ids known to the verifier). Trust-relevant types MUST
/// carry `evidence_ref` or `attestation_ref` (enforced in `proof-graph`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub v: u8,
    pub from: String,
    pub rel_type: RelType,
    pub to: String,
    pub evidence_ref: Option<String>,
    pub attestation_ref: Option<String>,
}

/// Machine-readable proposition: what the proof attempts to establish.
/// `description` (human text) is never authoritative and is not stored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposition {
    pub v: u8,
    pub kind: String,
    pub subject: String,
    pub predicate: String,
    pub object: Option<String>,
    pub at_time: Option<u64>,
    pub context: Vec<(String, MetaValue)>,
}

/// A stored attestation inside a Proof: content plus its COSE_Sign1 envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttestation {
    pub content: AttestationContent,
    pub sign1: Vec<u8>,
}

/// Portable proof package (without canonical bytes). `proof_id` binds the
/// proposition plus the exact member id sets (see `proof-crypto::id`).
/// `created_at` is informational only and is NOT covered by the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub v: u8,
    pub proof_id: String,
    pub proposition: Proposition,
    pub events: Vec<EventContent>,
    pub attestations: Vec<StoredAttestation>,
    pub evidence: Vec<Evidence>,
    pub relationships: Vec<Relationship>,
    pub created_at: u64,
}

/// Per-attestation lifecycle state, computed by verification stages TIME and
/// REVOCATION (ARCHITECTURE §4, stages 7–8). Authority: the pipeline only.
/// `SUPERSEDED` keeps evidence validity (historical record preserved); every
/// other non-`ACTIVE` state fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// PE-LIFE-001.
pub enum LifecycleStatus {
    /// Within validity and no valid revocation/supersession applies.
    Active,
    /// Outside its validity window at the verifier clock.
    Expired,
    /// Covered by a valid signed revocation.
    Revoked,
    /// Replaced by a newer attestation via a valid signed supersession.
    Superseded,
    /// Revocation information missing or stale — fail closed.
    Unknown,
}

impl LifecycleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Superseded => "SUPERSEDED",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ACTIVE" => Some(Self::Active),
            "EXPIRED" => Some(Self::Expired),
            "REVOKED" => Some(Self::Revoked),
            "SUPERSEDED" => Some(Self::Superseded),
            "UNKNOWN" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// ID prefixes (wire format `<prefix>:v1:<b64uNoPad(sha256)>`).
pub mod id_prefix {
    pub const EVENT: &str = "evt";
    pub const ATTESTATION: &str = "att";
    pub const EVIDENCE: &str = "evd";
    pub const REL: &str = "rel";
    pub const PROOF: &str = "prf";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_types_accept_any_string() {
        // Well-known types work
        let evt = EventType::new(EventType::PAYMENT_CREATED);
        assert_eq!(evt.as_str(), "payment.created");
        assert!(evt.is_well_known());

        // Unknown types are accepted (neutrality principle)
        let custom = EventType::new("healthcare.patient.admitted");
        assert_eq!(custom.as_str(), "healthcare.patient.admitted");
        assert!(!custom.is_well_known()); // Not in V1 list, but still valid

        // Evidence kinds work the same way
        let evd = EvidenceKind::new(EvidenceKind::TRANSPARENCY_RECEIPT);
        assert_eq!(evd.as_str(), "transparency_receipt");
        assert!(evd.is_well_known());

        let custom_evd = EvidenceKind::new("medical_record");
        assert!(!custom_evd.is_well_known()); // Unknown but accepted

        // Relationship types too
        let rel = RelType::new(RelType::SETTLES);
        assert_eq!(rel.as_str(), "SETTLES");
        assert!(rel.is_well_known());
    }

    #[test]
    fn grounding_flags_work_with_strings() {
        assert!(RelType::new(RelType::SETTLES).requires_grounding());
        assert!(RelType::new(RelType::OWNS).requires_grounding());
        assert!(RelType::new(RelType::CREATED).requires_grounding());
        assert!(RelType::new(RelType::EXECUTED).requires_grounding());
        assert!(!RelType::new(RelType::REFERENCES).requires_grounding());
        assert!(!RelType::new(RelType::SUPERSEDES).requires_grounding());

        // Unknown types don't match well-known grounding rules
        assert!(!RelType::new("CUSTOM_REL").requires_grounding());
    }

    #[test]
    fn lifecycle_status_closed_and_round_trip() {
        // LifecycleStatus remains closed (pipeline-internal state machine)
        for (s, expected) in [
            ("ACTIVE", LifecycleStatus::Active),
            ("EXPIRED", LifecycleStatus::Expired),
            ("REVOKED", LifecycleStatus::Revoked),
            ("SUPERSEDED", LifecycleStatus::Superseded),
            ("UNKNOWN", LifecycleStatus::Unknown),
        ] {
            assert_eq!(LifecycleStatus::parse(s), Some(expected));
            assert_eq!(expected.as_str(), s);
        }
        assert_eq!(LifecycleStatus::parse("PENDING"), None);
    }

    #[test]
    fn extensibility_demonstration() {
        // Healthcare domain can add types without modifying proof-core
        let healthcare_evt = EventType::new("healthcare.surgery.scheduled");
        let healthcare_evd = EvidenceKind::new("medical_imaging");
        let healthcare_rel = RelType::new("DIAGNOSED_WITH");

        // Logistics domain can add types without modifying proof-core
        let logistics_evt = EventType::new("logistics.shipment.departed");
        let logistics_evd = EvidenceKind::new("customs_declaration");
        let logistics_rel = RelType::new("TRANSPORTED_VIA");

        // AI domain can add types without modifying proof-core
        let ai_evt = EventType::new("ai.model.trained");
        let ai_evd = EvidenceKind::new("training_log");
        let ai_rel = RelType::new("TRAINED_ON");

        // All accepted at core layer; policy decides if they're valid
        assert_eq!(healthcare_evt.as_str(), "healthcare.surgery.scheduled");
        assert_eq!(healthcare_evd.as_str(), "medical_imaging");
        assert_eq!(healthcare_rel.as_str(), "DIAGNOSED_WITH");
        assert_eq!(logistics_evt.as_str(), "logistics.shipment.departed");
        assert_eq!(logistics_evd.as_str(), "customs_declaration");
        assert_eq!(logistics_rel.as_str(), "TRANSPORTED_VIA");
        assert_eq!(ai_evt.as_str(), "ai.model.trained");
        assert_eq!(ai_evd.as_str(), "training_log");
        assert_eq!(ai_rel.as_str(), "TRAINED_ON");
        // None are well-known V1 labels: extension happened without
        // modifying proof-core — the neutrality property, by construction.
        assert!(!healthcare_evt.is_well_known());
        assert!(!healthcare_evd.is_well_known());
        assert!(!healthcare_rel.is_well_known());
        assert!(!logistics_evt.is_well_known());
        assert!(!logistics_evd.is_well_known());
        assert!(!logistics_rel.is_well_known());
        assert!(!ai_evt.is_well_known());
        assert!(!ai_evd.is_well_known());
        assert!(!ai_rel.is_well_known());
    }
}
