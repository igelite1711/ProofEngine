// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Closed schemas for Event / Attestation / Evidence / Relationship / Proof (FORMAT §4).
//! Unknown fields and unknown enum variants are rejected (fail closed).

use proof_core::{
    model::{
        AttestationContent, Claim, EventContent, EventType, Evidence, EvidenceKind, MetaValue,
        Proof, Proposition, RelType, Relationship, StoredAttestation, VocabularyDecl,
    },
    ErrorCode, HashAlgorithm, HashRef, Limits, ProofError,
};

use crate::cbor::CborValue;
use std::collections::HashSet;

fn text_field(map: &[(CborValue, CborValue)], key: &str) -> Result<String, ProofError> {
    for (k, v) in map {
        if let CborValue::Text(kk) = k {
            if kk == key {
                if let CborValue::Text(s) = v {
                    if s.is_empty() || s.len() > 1024 {
                        return Err(ErrorCode::SchemaViolation
                            .err(format!("field {key} length out of bounds")));
                    }
                    return Ok(s.clone());
                }
                return Err(ErrorCode::SchemaViolation.err(format!("field {key} must be text")));
            }
        }
    }
    Err(ErrorCode::SchemaViolation.err(format!("missing field {key}")))
}

fn uint_field(map: &[(CborValue, CborValue)], key: &str) -> Result<u64, ProofError> {
    for (k, v) in map {
        if let CborValue::Text(kk) = k {
            if kk == key {
                if let CborValue::Uint(n) = v {
                    return Ok(*n);
                }
                return Err(ErrorCode::SchemaViolation.err(format!("field {key} must be uint")));
            }
        }
    }
    Err(ErrorCode::SchemaViolation.err(format!("missing field {key}")))
}

fn opt_text_or_nil(
    map: &[(CborValue, CborValue)],
    key: &str,
) -> Result<Option<String>, ProofError> {
    for (k, v) in map {
        if let CborValue::Text(kk) = k {
            if kk == key {
                match v {
                    CborValue::Null => return Ok(None),
                    CborValue::Text(s) => {
                        if s.is_empty() || s.len() > 1024 {
                            return Err(
                                ErrorCode::SchemaViolation.err(format!("field {key} too long"))
                            );
                        }
                        return Ok(Some(s.clone()));
                    }
                    _ => {
                        return Err(
                            ErrorCode::SchemaViolation.err(format!("field {key} must be text|nil"))
                        )
                    }
                }
            }
        }
    }
    Err(ErrorCode::SchemaViolation.err(format!("missing field {key}")))
}

fn opt_uint_or_nil(map: &[(CborValue, CborValue)], key: &str) -> Result<Option<u64>, ProofError> {
    for (k, v) in map {
        if let CborValue::Text(kk) = k {
            if kk == key {
                match v {
                    CborValue::Null => return Ok(None),
                    CborValue::Uint(n) => return Ok(Some(*n)),
                    _ => {
                        return Err(
                            ErrorCode::SchemaViolation.err(format!("field {key} must be uint|nil"))
                        )
                    }
                }
            }
        }
    }
    Err(ErrorCode::SchemaViolation.err(format!("missing field {key}")))
}

fn check_version(map: &[(CborValue, CborValue)]) -> Result<(), ProofError> {
    for (k, v) in map {
        if let CborValue::Text(kk) = k {
            if kk == "v" {
                if let CborValue::Uint(1) = v {
                    return Ok(());
                }
                return Err(ErrorCode::UnsupportedVersion.err("only v=1 supported"));
            }
        }
    }
    Err(ErrorCode::SchemaViolation.err("missing field v"))
}

// PE-FMT-008 (closed schemas/versions/enums).
fn check_closed(
    map: &[(CborValue, CborValue)],
    allowed: &[&str],
    what: &str,
) -> Result<(), ProofError> {
    for (k, _) in map {
        if let CborValue::Text(kk) = k {
            if !allowed.contains(&kk.as_str()) {
                return Err(ErrorCode::SchemaViolation.err(format!("{what}: unknown field {kk}")));
            }
        } else {
            return Err(ErrorCode::SchemaViolation.err(format!("{what}: non-text map key")));
        }
    }
    Ok(())
}

fn meta_value_from_cbor(v: &CborValue) -> Result<MetaValue, ProofError> {
    match v {
        CborValue::Text(s) => {
            if s.len() > 1024 {
                return Err(ErrorCode::SchemaViolation.err("meta text too long"));
            }
            Ok(MetaValue::Text(s.clone()))
        }
        CborValue::Uint(n) => Ok(MetaValue::Uint(*n)),
        CborValue::Bool(b) => Ok(MetaValue::Bool(*b)),
        _ => Err(ErrorCode::SchemaViolation.err("meta value must be text|uint|bool")),
    }
}

fn meta_value_to_cbor(m: &MetaValue) -> CborValue {
    match m {
        MetaValue::Text(s) => CborValue::Text(s.clone()),
        MetaValue::Uint(n) => CborValue::Uint(*n),
        MetaValue::Bool(b) => CborValue::Bool(*b),
    }
}

fn hashref_to_cbor(h: &HashRef) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::Text("alg".into()),
            CborValue::Uint(h.alg.cbor_enum()),
        ),
        (
            CborValue::Text("digest".into()),
            CborValue::Bytes(h.digest.clone()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(h.v as u64)),
    ])
}

fn hashref_from_cbor(v: &CborValue) -> Result<HashRef, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("payload_ref must be map")),
    };
    check_closed(map, &["v", "alg", "digest"], "HashRef")?;
    check_version(map)?;
    let alg_n = uint_field(map, "alg")?;
    let alg = HashAlgorithm::from_cbor_enum(alg_n)?;
    let digest = map
        .iter()
        .find_map(|(k, val)| match k {
            CborValue::Text(kk) if kk == "digest" => match val {
                CborValue::Bytes(b) => Some(b.clone()),
                _ => None,
            },
            _ => None,
        })
        .ok_or_else(|| ErrorCode::SchemaViolation.err("HashRef.digest must be bytes"))?;
    HashRef::new(alg, digest)
}

// ---------- Event ----------

const EVENT_FIELDS: &[&str] = &[
    "effective_at",
    "metadata",
    "payload_ref",
    "subject",
    "type",
    "v",
];

/// Domain → canonical-model CBOR (maps are sorted at encode time).
pub fn event_to_cbor(e: &EventContent) -> Result<CborValue, ProofError> {
    // PE-FMT-008: version confusion fails closed as data, never panics.
    if e.v != 1 {
        return Err(ErrorCode::UnsupportedVersion.err("only v=1 encodable"));
    }
    let meta: Vec<(CborValue, CborValue)> = e
        .metadata
        .iter()
        .map(|(k, v)| (CborValue::Text(k.clone()), meta_value_to_cbor(v)))
        .collect();
    Ok(CborValue::Map(vec![
        (
            CborValue::Text("effective_at".into()),
            CborValue::Uint(e.effective_at),
        ),
        (CborValue::Text("metadata".into()), CborValue::Map(meta)),
        (
            CborValue::Text("payload_ref".into()),
            hashref_to_cbor(&e.payload_ref),
        ),
        (
            CborValue::Text("subject".into()),
            CborValue::Text(e.subject.clone()),
        ),
        (
            CborValue::Text("type".into()),
            CborValue::Text(e.event_type.as_str().into()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(1)),
    ]))
}

/// CBOR → domain with closed validation.
pub fn cbor_to_event(v: &CborValue, limits: &Limits) -> Result<EventContent, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Event must be map")),
    };
    if map.len() > limits.max_map_entries {
        return Err(ErrorCode::LimitExceeded.err("Event map too large"));
    }
    check_closed(map, EVENT_FIELDS, "Event")?;
    check_version(map)?;
    let t = text_field(map, "type")?;
    // V1.0 NEUTRAL: accept any string, policy decides which types are valid
    let event_type = EventType::new(t);
    let subject = text_field(map, "subject")?;
    let effective_at = uint_field(map, "effective_at")?;
    let pref = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "payload_ref"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field payload_ref"))?;
    let payload_ref = hashref_from_cbor(pref)?;
    let meta_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "metadata"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field metadata"))?;
    let meta_pairs = match meta_cbor {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("metadata must be map")),
    };
    if meta_pairs.len() > 16 {
        return Err(ErrorCode::LimitExceeded.err("metadata too many entries"));
    }
    let mut seen = HashSet::new();
    let mut metadata = Vec::with_capacity(meta_pairs.len());
    for (k, val) in meta_pairs {
        let ks = match k {
            CborValue::Text(s) => s,
            _ => return Err(ErrorCode::SchemaViolation.err("metadata key must be text")),
        };
        if ks.len() > 64 || !seen.insert(ks.clone()) {
            return Err(ErrorCode::SchemaViolation.err("bad metadata key"));
        }
        metadata.push((ks.clone(), meta_value_from_cbor(val)?));
    }
    Ok(EventContent {
        v: 1,
        event_type,
        subject,
        effective_at,
        payload_ref,
        metadata,
    })
}

// ---------- Attestation ----------

const ATT_FIELDS: &[&str] = &[
    "claim",
    "evidence_ref",
    "expires_at",
    "issued_at",
    "issuer",
    "subject",
    "v",
];

pub fn attestation_to_cbor(a: &AttestationContent) -> CborValue {
    let mut claim_pairs = vec![(
        CborValue::Text("type".into()),
        CborValue::Text(a.claim.claim_type.clone()),
    )];
    for (k, v) in &a.claim.fields {
        claim_pairs.push((CborValue::Text(k.clone()), meta_value_to_cbor(v)));
    }
    CborValue::Map(vec![
        (CborValue::Text("claim".into()), CborValue::Map(claim_pairs)),
        (
            CborValue::Text("evidence_ref".into()),
            match &a.evidence_ref {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("expires_at".into()),
            match a.expires_at {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("issued_at".into()),
            CborValue::Uint(a.issued_at),
        ),
        (
            CborValue::Text("issuer".into()),
            CborValue::Text(a.issuer.clone()),
        ),
        (
            CborValue::Text("subject".into()),
            CborValue::Text(a.subject.clone()),
        ),
        // Emit the actual version so v=2 never silently downgrades to v=1
        // bytes: the decoder's check_version then fails closed with
        // UNSUPPORTED_VERSION.
        (CborValue::Text("v".into()), CborValue::Uint(a.v as u64)),
    ])
}

pub fn cbor_to_attestation(
    v: &CborValue,
    limits: &Limits,
) -> Result<AttestationContent, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Attestation must be map")),
    };
    if map.len() > limits.max_map_entries {
        return Err(ErrorCode::LimitExceeded.err("Attestation map too large"));
    }
    check_closed(map, ATT_FIELDS, "Attestation")?;
    check_version(map)?;
    let issuer = text_field(map, "issuer")?;
    let subject = text_field(map, "subject")?;
    let issued_at = uint_field(map, "issued_at")?;
    let expires_at = opt_uint_or_nil(map, "expires_at")?;
    let evidence_ref = opt_text_or_nil(map, "evidence_ref")?;
    if let (Some(e), _) = (expires_at, issued_at) {
        if e < issued_at {
            return Err(ErrorCode::SchemaViolation.err("expires_at < issued_at"));
        }
    }
    let claim_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "claim"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field claim"))?;
    let claim_pairs = match claim_cbor {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("claim must be map")),
    };
    if claim_pairs.len() > 16 || claim_pairs.is_empty() {
        return Err(ErrorCode::SchemaViolation.err("claim size out of bounds"));
    }
    let mut claim_type: Option<String> = None;
    let mut fields = Vec::new();
    let mut seen = HashSet::new();
    for (k, val) in claim_pairs {
        let ks = match k {
            CborValue::Text(s) => s,
            _ => return Err(ErrorCode::SchemaViolation.err("claim key must be text")),
        };
        if !seen.insert(ks.clone()) {
            return Err(ErrorCode::SchemaViolation.err("duplicate claim key"));
        }
        if ks == "type" {
            match val {
                CborValue::Text(s) => {
                    if s.is_empty() || s.len() > 128 {
                        return Err(ErrorCode::SchemaViolation.err("bad claim type"));
                    }
                    claim_type = Some(s.clone());
                }
                _ => return Err(ErrorCode::SchemaViolation.err("claim.type must be text")),
            }
        } else {
            fields.push((ks.clone(), meta_value_from_cbor(val)?));
        }
    }
    let claim_type =
        claim_type.ok_or_else(|| ErrorCode::SchemaViolation.err("missing claim.type"))?;
    void_limits(limits)?;
    Ok(AttestationContent {
        v: 1,
        issuer,
        subject,
        claim: Claim { claim_type, fields },
        issued_at,
        expires_at,
        evidence_ref,
    })
}

// ---------- Evidence ----------

const EVIDENCE_FIELDS: &[&str] = &["attestation_ref", "digest", "hint", "kind", "v"];

pub fn evidence_to_cbor(e: &Evidence) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::Text("attestation_ref".into()),
            match &e.attestation_ref {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (CborValue::Text("digest".into()), hashref_to_cbor(&e.digest)),
        (
            CborValue::Text("hint".into()),
            match &e.hint {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("kind".into()),
            CborValue::Text(e.kind.as_str().into()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(e.v as u64)),
    ])
}

pub fn cbor_to_evidence(v: &CborValue, limits: &Limits) -> Result<Evidence, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Evidence must be map")),
    };
    if map.len() > limits.max_map_entries {
        return Err(ErrorCode::LimitExceeded.err("Evidence map too large"));
    }
    check_closed(map, EVIDENCE_FIELDS, "Evidence")?;
    check_version(map)?;
    let k = text_field(map, "kind")?;
    // V1.0 NEUTRAL: accept any string, policy decides which kinds are valid
    let kind = EvidenceKind::new(k);
    let digest_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "digest"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field digest"))?;
    let digest = hashref_from_cbor(digest_cbor)?;
    let attestation_ref = opt_text_or_nil(map, "attestation_ref")?;
    let hint = opt_text_or_nil(map, "hint")?;
    if hint.as_deref().is_some_and(|s| s.len() > 256) {
        return Err(ErrorCode::SchemaViolation.err("hint too long"));
    }
    void_limits(limits)?;
    Ok(Evidence {
        v: 1,
        kind,
        digest,
        attestation_ref,
        hint,
    })
}

fn void_limits(_: &Limits) -> Result<(), ProofError> {
    Ok(())
}

// ---------- Relationship ----------

const REL_FIELDS: &[&str] = &["attestation_ref", "evidence_ref", "from", "to", "type", "v"];

pub fn relationship_to_cbor(r: &Relationship) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::Text("attestation_ref".into()),
            match &r.attestation_ref {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("evidence_ref".into()),
            match &r.evidence_ref {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("from".into()),
            CborValue::Text(r.from.clone()),
        ),
        (CborValue::Text("to".into()), CborValue::Text(r.to.clone())),
        (
            CborValue::Text("type".into()),
            CborValue::Text(r.rel_type.as_str().into()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(r.v as u64)),
    ])
}

pub fn cbor_to_relationship(v: &CborValue, limits: &Limits) -> Result<Relationship, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Relationship must be map")),
    };
    if map.len() > limits.max_map_entries {
        return Err(ErrorCode::LimitExceeded.err("Relationship map too large"));
    }
    check_closed(map, REL_FIELDS, "Relationship")?;
    check_version(map)?;
    let from = text_field(map, "from")?;
    let to = text_field(map, "to")?;
    if from == to {
        return Err(ErrorCode::SchemaViolation.err("self-edge forbidden in V1"));
    }
    let t = text_field(map, "type")?;
    // V1.0 NEUTRAL: accept any string, policy decides which types are valid
    let rel_type = RelType::new(t);
    let evidence_ref = opt_text_or_nil(map, "evidence_ref")?;
    let attestation_ref = opt_text_or_nil(map, "attestation_ref")?;
    void_limits(limits)?;
    Ok(Relationship {
        v: 1,
        from,
        rel_type,
        to,
        evidence_ref,
        attestation_ref,
    })
}

// ---------- Proposition ----------

const PROP_FIELDS: &[&str] = &[
    "at_time",
    "context",
    "kind",
    "object",
    "predicate",
    "subject",
    "v",
];

pub fn proposition_to_cbor(p: &Proposition) -> CborValue {
    let ctx: Vec<(CborValue, CborValue)> = p
        .context
        .iter()
        .map(|(k, v)| (CborValue::Text(k.clone()), meta_value_to_cbor(v)))
        .collect();
    CborValue::Map(vec![
        (
            CborValue::Text("at_time".into()),
            match p.at_time {
                Some(n) => CborValue::Uint(n),
                None => CborValue::Null,
            },
        ),
        (CborValue::Text("context".into()), CborValue::Map(ctx)),
        (
            CborValue::Text("kind".into()),
            CborValue::Text(p.kind.clone()),
        ),
        (
            CborValue::Text("object".into()),
            match &p.object {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            },
        ),
        (
            CborValue::Text("predicate".into()),
            CborValue::Text(p.predicate.clone()),
        ),
        (
            CborValue::Text("subject".into()),
            CborValue::Text(p.subject.clone()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(p.v as u64)),
    ])
}

pub fn cbor_to_proposition(v: &CborValue, limits: &Limits) -> Result<Proposition, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Proposition must be map")),
    };
    if map.len() > limits.max_map_entries {
        return Err(ErrorCode::LimitExceeded.err("Proposition map too large"));
    }
    check_closed(map, PROP_FIELDS, "Proposition")?;
    check_version(map)?;
    let kind = text_field(map, "kind")?;
    let subject = text_field(map, "subject")?;
    let predicate = text_field(map, "predicate")?;
    let object = opt_text_or_nil(map, "object")?;
    let at_time = opt_uint_or_nil(map, "at_time")?;
    let ctx_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "context"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field context"))?;
    let ctx_pairs = match ctx_cbor {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("context must be map")),
    };
    if ctx_pairs.len() > 16 {
        return Err(ErrorCode::LimitExceeded.err("context too many entries"));
    }
    let mut seen = HashSet::new();
    let mut context = Vec::with_capacity(ctx_pairs.len());
    for (k, val) in ctx_pairs {
        let ks = match k {
            CborValue::Text(s) => s,
            _ => return Err(ErrorCode::SchemaViolation.err("context key must be text")),
        };
        if ks.len() > 64 || !seen.insert(ks.clone()) {
            return Err(ErrorCode::SchemaViolation.err("bad context key"));
        }
        context.push((ks.clone(), meta_value_from_cbor(val)?));
    }
    void_limits(limits)?;
    Ok(Proposition {
        v: 1,
        kind,
        subject,
        predicate,
        object,
        at_time,
        context,
    })
}

// ---------- Proof ----------

const PROOF_FIELDS: &[&str] = &[
    "attestations",
    "created_at",
    "events",
    "evidence",
    "proof_id",
    "proposition",
    "referenced_proofs",
    "relationships",
    "v",
    "vocabularies",
];

fn attestation_entry_to_cbor(a: &StoredAttestation) -> CborValue {
    CborValue::Map(vec![
        (
            CborValue::Text("content".into()),
            attestation_to_cbor(&a.content),
        ),
        (
            CborValue::Text("sign1".into()),
            CborValue::Bytes(a.sign1.clone()),
        ),
    ])
}

fn cbor_to_attestation_entry(
    v: &CborValue,
    limits: &Limits,
) -> Result<StoredAttestation, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("attestation entry must be map")),
    };
    check_closed(map, &["content", "sign1"], "AttestationEntry")?;
    let content_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "content"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field content"))?;
    let content = cbor_to_attestation(content_cbor, limits)?;
    let sign1 = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "sign1"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field sign1"))?;
    let sign1 = match sign1 {
        CborValue::Bytes(b) => {
            // sign1 here is the full COSE_Sign1 envelope (protected + payload
            // + 64B sig), not the raw signature: max_proof_size is correct.
            // The crypto layer separately enforces max_sig_size on the raw
            // signature bytes at verify time.
            if b.is_empty() || b.len() > limits.max_proof_size {
                return Err(ErrorCode::LimitExceeded.err("sign1 size out of bounds"));
            }
            b.clone()
        }
        _ => return Err(ErrorCode::SchemaViolation.err("sign1 must be bytes")),
    };
    Ok(StoredAttestation { content, sign1 })
}

pub fn proof_to_cbor(p: &Proof) -> Result<CborValue, ProofError> {
    let mut events = Vec::with_capacity(p.events.len());
    for e in &p.events {
        events.push(event_to_cbor(e)?);
    }
    // Composition linkage is additive: proofs without references encode the
    // exact V1 map (byte-identical); the key appears only when non-empty.
    let mut pairs = vec![
        (
            CborValue::Text("attestations".into()),
            CborValue::Array(
                p.attestations
                    .iter()
                    .map(attestation_entry_to_cbor)
                    .collect(),
            ),
        ),
        (
            CborValue::Text("created_at".into()),
            CborValue::Uint(p.created_at),
        ),
        (CborValue::Text("events".into()), CborValue::Array(events)),
        (
            CborValue::Text("evidence".into()),
            CborValue::Array(p.evidence.iter().map(evidence_to_cbor).collect()),
        ),
        (
            CborValue::Text("proof_id".into()),
            CborValue::Text(p.proof_id.clone()),
        ),
        (
            CborValue::Text("proposition".into()),
            proposition_to_cbor(&p.proposition),
        ),
        (
            CborValue::Text("relationships".into()),
            CborValue::Array(p.relationships.iter().map(relationship_to_cbor).collect()),
        ),
        (CborValue::Text("v".into()), CborValue::Uint(1)),
    ];
    if !p.referenced_proofs.is_empty() {
        pairs.push((
            CborValue::Text("referenced_proofs".into()),
            CborValue::Array(
                p.referenced_proofs
                    .iter()
                    .map(|s| CborValue::Text(s.clone()))
                    .collect(),
            ),
        ));
    }
    // Vocabulary declarations are additive like linkage: absent/empty in V1
    // bytes (byte-identical); bound when present.
    if !p.vocabularies.is_empty() {
        pairs.push((
            CborValue::Text("vocabularies".into()),
            CborValue::Array(
                p.vocabularies
                    .iter()
                    .map(|vd| {
                        CborValue::Map(vec![
                            (CborValue::Text("ns".into()), CborValue::Text(vd.ns.clone())),
                            (
                                CborValue::Text("version".into()),
                                CborValue::Uint(vd.version),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    Ok(CborValue::Map(pairs))
}

fn cbor_array<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Result<&'a Vec<CborValue>, ProofError> {
    map.iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == key))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err(format!("missing field {key}")))
        .and_then(|v| match v {
            CborValue::Array(a) => Ok(a),
            _ => Err(ErrorCode::SchemaViolation.err(format!("field {key} must be array"))),
        })
}

/// Closed validation of the full Proof envelope (member bytes are NOT
/// cryptographically verified here — that is the pipeline's job).
pub fn cbor_to_proof(v: &CborValue, limits: &Limits) -> Result<Proof, ProofError> {
    let map = match v {
        CborValue::Map(p) => p,
        _ => return Err(ErrorCode::SchemaViolation.err("Proof must be map")),
    };
    check_closed(map, PROOF_FIELDS, "Proof")?;
    check_version(map)?;
    let proof_id = text_field(map, "proof_id")?;
    if !proof_id.starts_with("prf:v1:") {
        return Err(ErrorCode::SchemaViolation.err("proof_id must start with prf:v1:"));
    }
    let prop_cbor = map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "proposition"))
        .map(|(_, v)| v)
        .ok_or_else(|| ErrorCode::SchemaViolation.err("missing field proposition"))?;
    let proposition = cbor_to_proposition(prop_cbor, limits)?;
    let created_at = uint_field(map, "created_at")?;

    let mut events = vec![];
    for item in cbor_array(map, "events")? {
        events.push(cbor_to_event(item, limits)?);
    }
    let mut attestations = vec![];
    for item in cbor_array(map, "attestations")? {
        attestations.push(cbor_to_attestation_entry(item, limits)?);
    }
    let mut evidence = vec![];
    for item in cbor_array(map, "evidence")? {
        evidence.push(cbor_to_evidence(item, limits)?);
    }
    let mut relationships = vec![];
    for item in cbor_array(map, "relationships")? {
        relationships.push(cbor_to_relationship(item, limits)?);
    }
    // Composition linkage (additive): absent in V1 bytes → empty vec.
    // Present → sorted, deduped, well-formed `prf:v1:` ids within bound.
    // Referenced content is never embedded, so no digest is recomputed here;
    // the pipeline re-checks shape plus self-reference and treats every
    // reference as linkage-only (REFERENCED, never verified content).
    let referenced_proofs = match map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "referenced_proofs"))
    {
        None => vec![],
        Some((_, CborValue::Array(items))) => {
            if items.len() > limits.max_referenced_proofs {
                return Err(ErrorCode::LimitExceeded.err("too many referenced proofs"));
            }
            let mut refs = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    CborValue::Text(s) => {
                        check_proof_ref_shape(s)?;
                        refs.push(s.clone());
                    }
                    _ => {
                        return Err(ErrorCode::SchemaViolation
                            .err("referenced_proofs entries must be text"));
                    }
                }
            }
            let mut sorted = refs.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() != refs.len() || sorted != refs {
                return Err(ErrorCode::SchemaViolation
                    .err("referenced_proofs must be sorted ascending with no duplicates"));
            }
            refs
        }
        Some(_) => {
            return Err(
                ErrorCode::SchemaViolation.err("referenced_proofs must be an array of text")
            );
        }
    };
    // Semantic size bounds (decoder already caps raw array lengths).
    if relationships.len() > limits.max_edges {
        return Err(ErrorCode::LimitExceeded.err("too many relationships"));
    }
    if events.len() + attestations.len() + evidence.len() > limits.max_nodes {
        return Err(ErrorCode::LimitExceeded.err("too many artifact members"));
    }
    void_limits(limits)?;
    Ok(Proof {
        v: 1,
        proof_id,
        proposition,
        events,
        attestations,
        evidence,
        relationships,
        referenced_proofs,
        vocabularies: cbor_to_vocabularies(map, limits)?,
        created_at,
    })
}

/// Declared vocabularies (additive): absent in V1 bytes → empty vec.
/// Present → array of `{ns: tstr, version: uint}` sorted by ns, deduped,
/// bounded. `ns` must be non-empty (≤128 chars); `legacy` (un-namespaced
/// labels) may be declared explicitly like any namespace.
fn cbor_to_vocabularies(
    map: &[(CborValue, CborValue)],
    limits: &Limits,
) -> Result<Vec<VocabularyDecl>, ProofError> {
    use proof_core::model::VocabularyDecl;
    let arr = match map
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(s) if s == "vocabularies"))
    {
        None => return Ok(vec![]),
        Some((_, CborValue::Array(items))) => items,
        Some(_) => {
            return Err(ErrorCode::SchemaViolation.err("vocabularies must be an array"));
        }
    };
    if arr.len() > limits.max_vocabularies {
        return Err(ErrorCode::LimitExceeded.err("too many vocabularies"));
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let pairs = match item {
            CborValue::Map(p) => p,
            _ => return Err(ErrorCode::SchemaViolation.err("vocabulary must be a map")),
        };
        check_closed(pairs, &["ns", "version"], "Vocabulary")?;
        let ns = text_field(pairs, "ns")?;
        if ns.is_empty() || ns.len() > 128 {
            return Err(ErrorCode::SchemaViolation.err("vocabulary ns length out of bounds"));
        }
        // `:` would make the namespace unmatchable (`vocabulary_ns` takes
        // text before the first `:`), whitespace is never significant.
        if ns.contains(':') || ns.contains(char::is_whitespace) {
            return Err(
                ErrorCode::SchemaViolation.err("vocabulary ns must not contain ':' or whitespace")
            );
        }
        let version = uint_field(pairs, "version")?;
        out.push(VocabularyDecl { ns, version });
    }
    let mut sorted = out.clone();
    sorted.sort_by(|a, b| a.ns.cmp(&b.ns));
    sorted.dedup_by(|a, b| a.ns == b.ns);
    if sorted.len() != out.len() || sorted.iter().map(|v| &v.ns).ne(out.iter().map(|v| &v.ns)) {
        return Err(
            ErrorCode::SchemaViolation.err("vocabularies must be sorted by ns with no duplicates")
        );
    }
    Ok(out)
}

/// Shape of a composition reference: `prf:v1:` + canonical no-pad base64url
/// of exactly 32 digest bytes. (Digest recomputation is impossible — content
/// is never embedded — so this validates naming only; see
/// `proof-crypto::id::check_proof_ref_shape`, which enforces the same rule
/// pipeline-side.)
fn check_proof_ref_shape(id: &str) -> Result<(), ProofError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let rest = id.strip_prefix("prf:v1:").ok_or_else(|| {
        ErrorCode::SchemaViolation.err("referenced proof id must start with prf:v1:")
    })?;
    let raw = URL_SAFE_NO_PAD
        .decode(rest)
        .map_err(|_| ErrorCode::SchemaViolation.err("referenced proof id is not base64url"))?;
    if URL_SAFE_NO_PAD.encode(&raw) != rest {
        return Err(
            ErrorCode::SchemaViolation.err("referenced proof id is not canonical base64url")
        );
    }
    if raw.len() != 32 {
        return Err(ErrorCode::SchemaViolation.err("referenced proof id digest must be 32 bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proof_core::model::{Claim, EventType, EvidenceKind, MetaValue, RelType, Relationship};

    pub fn event_fixture() -> EventContent {
        EventContent {
            v: 1,
            event_type: EventType::new(EventType::PAYMENT_CREATED),
            subject: "acct:merchant-01".into(),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap(),
            metadata: vec![("order".into(), MetaValue::Text("ord-1".into()))],
        }
    }

    /// PE-FMT-008: version confusion fails closed as data, never panics —
    /// a hand-built v=2 event cannot be encoded (decode path already
    /// rejects v!=1 with UNSUPPORTED_VERSION).
    #[test]
    fn event_v2_refuses_to_encode() {
        let mut e = event_fixture();
        e.v = 2;
        let err = event_to_cbor(&e).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
    }

    /// Non-event primitives must never silently downgrade v=2 to v=1 bytes:
    /// they preserve the version on encode so decode fails closed with
    /// UNSUPPORTED_VERSION.
    #[test]
    fn non_event_v2_preserved_then_rejected() {
        use proof_core::model::{AttestationContent, Claim, Evidence, Proposition, Relationship};
        let lim = Limits::default();
        let digest = HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).unwrap();

        let mut att = AttestationContent {
            v: 2,
            issuer: "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            subject: "s".into(),
            claim: Claim {
                claim_type: "t".into(),
                fields: vec![],
            },
            issued_at: 1,
            expires_at: None,
            evidence_ref: None,
        };
        // Empty claim fields rejected by claim-size check before version?
        // No: check_version runs first, so version wins.
        let v = attestation_to_cbor(&att);
        let err = cbor_to_attestation(&v, &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
        att.v = 1;
        // v=1 still needs a non-empty claim map (type + no fields is empty);
        // use a field so round-trip is valid.
        att.claim
            .fields
            .push(("k".into(), MetaValue::Text("v".into())));
        let v1 = attestation_to_cbor(&att);
        assert!(cbor_to_attestation(&v1, &lim).is_ok());

        let evd = Evidence {
            v: 2,
            kind: EvidenceKind::new("k"),
            digest: digest.clone(),
            attestation_ref: None,
            hint: None,
        };
        let err = cbor_to_evidence(&evidence_to_cbor(&evd), &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);

        let rel = Relationship {
            v: 2,
            from: "a".into(),
            rel_type: RelType::new("REFERENCES"),
            to: "b".into(),
            evidence_ref: None,
            attestation_ref: None,
        };
        let err = cbor_to_relationship(&relationship_to_cbor(&rel), &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);

        let prop = Proposition {
            v: 2,
            kind: "k".into(),
            subject: "s".into(),
            predicate: "p".into(),
            object: None,
            at_time: None,
            context: vec![],
        };
        let err = cbor_to_proposition(&proposition_to_cbor(&prop), &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
    }

    /// Shared fixture constructor lives in a tiny helper to keep vectors identical
    /// between unit tests and the golden-vector generator.
    #[test]
    fn event_round_trip() {
        let lim = Limits::default();
        let e = event_fixture();
        let v = event_to_cbor(&e).unwrap();
        let bytes = crate::encode_canonical(&v);
        let back = crate::decode_strict(&bytes, &lim).unwrap();
        // Decoded pair order is canonical (sorted); re-encoding must be stable.
        assert_eq!(crate::encode_canonical(&back), bytes);
        let e2 = cbor_to_event(&back, &lim).unwrap();
        assert_eq!(e2, e);
    }

    #[test]
    fn unknown_event_type_accepted() {
        // V1.0 NEUTRAL: unknown types are accepted, policy decides validity
        let lim = Limits::default();
        let v = CborValue::Map(vec![
            (CborValue::Text("effective_at".into()), CborValue::Uint(1)),
            (CborValue::Text("metadata".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("payload_ref".into()),
                CborValue::Map(vec![
                    (CborValue::Text("alg".into()), CborValue::Uint(0)),
                    (
                        CborValue::Text("digest".into()),
                        CborValue::Bytes(vec![0u8; 32]),
                    ),
                    (CborValue::Text("v".into()), CborValue::Uint(1)),
                ]),
            ),
            (
                CborValue::Text("subject".into()),
                CborValue::Text("s".into()),
            ),
            (
                CborValue::Text("type".into()),
                CborValue::Text("healthcare.patient.admitted".into()),
            ),
            (CborValue::Text("v".into()), CborValue::Uint(1)),
        ]);
        let evt = cbor_to_event(&v, &lim).unwrap();
        assert_eq!(evt.event_type.as_str(), "healthcare.patient.admitted");
        assert!(!evt.event_type.is_well_known());
    }

    #[test]
    fn unknown_field_rejected() {
        let lim = Limits::default();
        let mut e = event_fixture();
        e.subject = "s".into();
        let mut v = event_to_cbor(&e).unwrap();
        if let CborValue::Map(p) = &mut v {
            p.push((CborValue::Text("evil".into()), CborValue::Uint(1)));
        }
        assert_eq!(
            cbor_to_event(&v, &lim).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }

    #[test]
    fn attestation_expires_before_issued_rejected() {
        let lim = Limits::default();
        let a = AttestationContent {
            v: 1,
            issuer: "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            subject: "s".into(),
            claim: Claim {
                claim_type: "t".into(),
                fields: vec![],
            },
            issued_at: 200,
            expires_at: Some(100),
            evidence_ref: None,
        };
        let v = attestation_to_cbor(&a);
        assert_eq!(
            cbor_to_attestation(&v, &lim).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }

    #[test]
    fn metadata_value_types_restricted() {
        let lim = Limits::default();
        let v = CborValue::Map(vec![
            (CborValue::Text("effective_at".into()), CborValue::Uint(1)),
            (
                CborValue::Text("metadata".into()),
                CborValue::Map(vec![(
                    CborValue::Text("k".into()),
                    CborValue::Array(vec![]),
                )]),
            ),
            (
                CborValue::Text("payload_ref".into()),
                CborValue::Map(vec![
                    (CborValue::Text("alg".into()), CborValue::Uint(0)),
                    (
                        CborValue::Text("digest".into()),
                        CborValue::Bytes(vec![0u8; 32]),
                    ),
                    (CborValue::Text("v".into()), CborValue::Uint(1)),
                ]),
            ),
            (
                CborValue::Text("subject".into()),
                CborValue::Text("s".into()),
            ),
            (
                CborValue::Text("type".into()),
                CborValue::Text("payment.created".into()),
            ),
            (CborValue::Text("v".into()), CborValue::Uint(1)),
        ]);
        assert_eq!(
            cbor_to_event(&v, &lim).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }

    #[test]
    fn evidence_round_trip() {
        let lim = Limits::default();
        let e = Evidence {
            v: 1,
            kind: EvidenceKind::new(EvidenceKind::TRANSACTION_RECORD),
            digest: HashRef::new(HashAlgorithm::Sha256, vec![0xCDu8; 32]).unwrap(),
            attestation_ref: Some("att:v1:placeholder".into()),
            hint: Some("invoice-I-9 settlement".into()),
        };
        let v = evidence_to_cbor(&e);
        let bytes = crate::encode_canonical(&v);
        let back = crate::decode_strict(&bytes, &lim).unwrap();
        assert_eq!(crate::encode_canonical(&back), bytes);
        assert_eq!(cbor_to_evidence(&back, &lim).unwrap(), e);
    }

    #[test]
    fn unknown_evidence_kind_accepted() {
        // V1.0 NEUTRAL: unknown kinds are accepted, policy decides validity
        let lim = Limits::default();
        let v = CborValue::Map(vec![
            (CborValue::Text("attestation_ref".into()), CborValue::Null),
            (
                CborValue::Text("digest".into()),
                CborValue::Map(vec![
                    (CborValue::Text("alg".into()), CborValue::Uint(0)),
                    (
                        CborValue::Text("digest".into()),
                        CborValue::Bytes(vec![0u8; 32]),
                    ),
                    (CborValue::Text("v".into()), CborValue::Uint(1)),
                ]),
            ),
            (CborValue::Text("hint".into()), CborValue::Null),
            (
                CborValue::Text("kind".into()),
                CborValue::Text("medical_imaging".into()),
            ),
            (CborValue::Text("v".into()), CborValue::Uint(1)),
        ]);
        let evd = cbor_to_evidence(&v, &lim).unwrap();
        assert_eq!(evd.kind.as_str(), "medical_imaging");
        assert!(!evd.kind.is_well_known());
    }

    #[test]
    fn relationship_round_trip() {
        let lim = Limits::default();
        let r = Relationship {
            v: 1,
            from: "evt:v1:aaa".into(),
            rel_type: RelType::new(RelType::SETTLES),
            to: "evt:v1:bbb".into(),
            evidence_ref: Some("evd:v1:ccc".into()),
            attestation_ref: None,
        };
        let v = relationship_to_cbor(&r);
        let bytes = crate::encode_canonical(&v);
        let back = crate::decode_strict(&bytes, &lim).unwrap();
        assert_eq!(crate::encode_canonical(&back), bytes);
        assert_eq!(cbor_to_relationship(&back, &lim).unwrap(), r);
    }

    #[test]
    fn relationship_rejects_self_edge_and_accepts_unknown_type() {
        let lim = Limits::default();
        let base = Relationship {
            v: 1,
            from: "evt:v1:aaa".into(),
            rel_type: RelType::new(RelType::REFERENCES),
            to: "evt:v1:bbb".into(),
            evidence_ref: None,
            attestation_ref: None,
        };
        // V1.0 NEUTRAL: Unknown type is accepted, policy decides validity
        let mut v = relationship_to_cbor(&base);
        if let CborValue::Map(p) = &mut v {
            for (k, val) in p.iter_mut() {
                if matches!(k, CborValue::Text(s) if s == "type") {
                    *val = CborValue::Text("CUSTOM_RELATIONSHIP".into());
                }
            }
        }
        let rel = cbor_to_relationship(&v, &lim).unwrap();
        assert_eq!(rel.rel_type.as_str(), "CUSTOM_RELATIONSHIP");
        assert!(!rel.rel_type.is_well_known());

        // Self-edge still rejected (V1 semantic rule)
        let mut selfy = base.clone();
        selfy.to = selfy.from.clone();
        let v2 = relationship_to_cbor(&selfy);
        assert_eq!(
            cbor_to_relationship(&v2, &lim).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }

    #[test]
    fn proposition_round_trip() {
        use proof_core::model::Proposition;
        let lim = Limits::default();
        let p = Proposition {
            v: 1,
            kind: "payment.settles-invoice".into(),
            subject: "payment:p9".into(),
            predicate: "settles".into(),
            object: Some("invoice:i9".into()),
            at_time: Some(1_700_000_000),
            context: vec![(
                "policy".into(),
                MetaValue::Text("merchant_payment_v1".into()),
            )],
        };
        let v = proposition_to_cbor(&p);
        let bytes = crate::encode_canonical(&v);
        let back = crate::decode_strict(&bytes, &lim).unwrap();
        assert_eq!(crate::encode_canonical(&back), bytes);
        assert_eq!(cbor_to_proposition(&back, &lim).unwrap(), p);
    }

    #[test]
    fn proof_envelope_round_trip_and_bounds() {
        use proof_core::model::{AttestationContent, Claim, Proof, StoredAttestation};
        let lim = Limits::default();
        let p = Proof {
            v: 1,
            proof_id: "prf:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            proposition: Proposition {
                v: 1,
                kind: "k".into(),
                subject: "s".into(),
                predicate: "p".into(),
                object: None,
                at_time: None,
                context: vec![],
            },
            events: vec![],
            attestations: vec![StoredAttestation {
                content: AttestationContent {
                    v: 1,
                    issuer: "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                    subject: "s".into(),
                    claim: Claim {
                        claim_type: "t".into(),
                        fields: vec![],
                    },
                    issued_at: 1,
                    expires_at: None,
                    evidence_ref: None,
                },
                sign1: vec![0u8; 64],
            }],
            evidence: vec![],
            relationships: vec![],
            referenced_proofs: vec![],
            vocabularies: vec![],
            created_at: 1_700_000_000,
        };
        let v = proof_to_cbor(&p).unwrap();
        let bytes = crate::encode_canonical(&v);
        let back = crate::decode_strict(&bytes, &lim).unwrap();
        assert_eq!(crate::encode_canonical(&back), bytes);
        assert_eq!(cbor_to_proof(&back, &lim).unwrap(), p);
        // Bad proof_id prefix rejected at schema level.
        let mut bad = p.clone();
        bad.proof_id = "evt:v1:xxx".into();
        let vb = proof_to_cbor(&bad).unwrap();
        assert_eq!(
            cbor_to_proof(&vb, &lim).unwrap_err().code,
            ErrorCode::SchemaViolation
        );
    }
}
