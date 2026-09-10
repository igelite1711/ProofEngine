// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy schema + validator (spec §9). JSON is the input language; it is
//! validated BEFORE anything is evaluated, and never executed as code.

use proof_core::{
    model::{EvidenceKind, RelType},
    ErrorCode, Limits, ProofError,
};

/// Closed requirement set (V0.1). Unknown `type` values are rejected.
/// PE-POLICY-008.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    /// Cryptographic validity established by the pipeline.
    SignatureValid,
    /// A signature-verified attestation by this issuer exists AND the
    /// verifier's trust list contains it. Valid signature alone never suffices.
    IssuerTrusted { issuer: String },
    /// No signature-verified attestation by this issuer exists in the proof.
    /// Deny-list for sanctions/blocklist screening: a listed issuer touching
    /// the chain fails closed, regardless of other requirements.
    IssuerExcluded { issuer: String },
    /// A validated edge of this type exists in the proof graph.
    RelationshipExists { relationship: RelType },
    /// Every attestation satisfies issued/expires against the verifier clock.
    NotExpired,
    /// No attestation id is in the caller-supplied revocation set.
    NotRevoked,
    /// No signature-verified attestation in this proof is SUPERSEDED by a
    /// valid signed supersession. Without this requirement, a superseded
    /// (stale but historical) attestation still satisfies the other
    /// requirements — PASS then means "valid", not "current".
    NotSuperseded,
    /// Evidence of this kind is present (digest-bound).
    EvidencePresent { kind: EvidenceKind },
    /// Transparency evidence is present (a `transparency_receipt` item).
    TransparencyPresent,
    /// The proof was created within `max_age_seconds` of the verifier clock.
    /// Provides replay protection: a valid but stale proof fails this check.
    /// Uses the proof's `created_at` field (informational, outside proof_id).
    ProofFresh { max_age_seconds: u64 },
}

impl Requirement {
    /// Stable rendering for results and explanations.
    pub fn describe(&self) -> String {
        match self {
            Self::SignatureValid => "signature_valid".into(),
            Self::IssuerTrusted { issuer } => format!("issuer_trusted({issuer})"),
            Self::IssuerExcluded { issuer } => format!("issuer_excluded({issuer})"),
            Self::RelationshipExists { relationship } => {
                format!("relationship_exists({})", relationship.as_str())
            }
            Self::NotExpired => "not_expired".into(),
            Self::NotRevoked => "not_revoked".into(),
            Self::NotSuperseded => "not_superseded".into(),
            Self::EvidencePresent { kind } => format!("evidence_present({})", kind.as_str()),
            Self::TransparencyPresent => "transparency_present".into(),
            Self::ProofFresh { max_age_seconds } => format!("proof_fresh({max_age_seconds}s)"),
        }
    }

    /// Stable wire string for the requirement type (used in canonical encoding).
    pub fn type_str(&self) -> &'static str {
        match self {
            Self::SignatureValid => "signature_valid",
            Self::IssuerTrusted { .. } => "issuer_trusted",
            Self::IssuerExcluded { .. } => "issuer_excluded",
            Self::RelationshipExists { .. } => "relationship_exists",
            Self::NotExpired => "not_expired",
            Self::NotRevoked => "not_revoked",
            Self::NotSuperseded => "not_superseded",
            Self::EvidencePresent { .. } => "evidence_present",
            Self::TransparencyPresent => "transparency_present",
            Self::ProofFresh { .. } => "proof_fresh",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub version: u8,
    pub id: String,
    pub requirements: Vec<Requirement>,
}

/// Serialize a Policy to canonical CBOR bytes.
/// Enables signing, comparison, and deterministic caching.
/// The canonical form uses sorted map keys and no extra whitespace.
pub fn policy_to_canonical_cbor(policy: &Policy) -> Vec<u8> {
    use proof_format::{encode_canonical, CborValue};

    // Build CBOR representation with deterministic key ordering
    let mut reqs = Vec::new();
    for req in &policy.requirements {
        let mut req_map: Vec<(CborValue, CborValue)> = vec![(
            CborValue::Text("type".into()),
            CborValue::Text(req.type_str().into()),
        )];
        match req {
            Requirement::IssuerTrusted { issuer } | Requirement::IssuerExcluded { issuer } => {
                req_map.push((
                    CborValue::Text("issuer".into()),
                    CborValue::Text(issuer.clone()),
                ));
            }
            Requirement::RelationshipExists { relationship } => {
                req_map.push((
                    CborValue::Text("relationship".into()),
                    CborValue::Text(relationship.as_str().into()),
                ));
            }
            Requirement::EvidencePresent { kind } => {
                req_map.push((
                    CborValue::Text("kind".into()),
                    CborValue::Text(kind.as_str().into()),
                ));
            }
            Requirement::ProofFresh { max_age_seconds } => {
                req_map.push((
                    CborValue::Text("max_age_seconds".into()),
                    CborValue::Uint(*max_age_seconds),
                ));
            }
            _ => {}
        }
        // Sort keys for canonical form
        req_map.sort_by(|(a, _), (b, _)| {
            let a_bytes = encode_canonical(a);
            let b_bytes = encode_canonical(b);
            a_bytes.cmp(&b_bytes)
        });
        reqs.push(CborValue::Map(req_map));
    }

    let root = CborValue::Map(vec![
        (
            CborValue::Text("policy_id".into()),
            CborValue::Text(policy.id.clone()),
        ),
        (
            CborValue::Text("policy_version".into()),
            CborValue::Uint(policy.version as u64),
        ),
        (
            CborValue::Text("requirements".into()),
            CborValue::Array(reqs),
        ),
    ]);

    encode_canonical(&root)
}

/// Compute a canonical hash of a policy for referencing by content.
/// Returns `policy:v1:<b64u(sha256(canonical_cbor))>`.
pub fn canonical_policy_hash(policy: &Policy) -> String {
    use proof_crypto::hash::sha256;
    use proof_crypto::id::b64u_nopad;

    let cbor = policy_to_canonical_cbor(policy);
    let hash = sha256(&cbor);
    format!("policy:v1:{}", b64u_nopad(&hash))
}

fn obj_get<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value, ProofError> {
    v.get(key)
        .ok_or_else(|| ErrorCode::PolicyInvalid.err(format!("policy missing field {key}")))
}

fn reject_extra_keys(
    v: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), ProofError> {
    for k in v.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(ErrorCode::PolicyInvalid.err(format!("{what}: unknown field {k}")));
        }
    }
    Ok(())
}

fn req_string(
    v: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<String, ProofError> {
    match v.get(key) {
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(_) => {
            Err(ErrorCode::PolicyInvalid.err(format!("{what}: field {key} must be a string")))
        }
        None => Err(ErrorCode::PolicyInvalid.err(format!("{what}: missing field {key}"))),
    }
}

/// Parse + validate a policy document. Fails closed: any syntax problem is
/// `POLICY_INVALID` and nothing is evaluated, partially or otherwise.
pub fn parse_policy(v: &serde_json::Value, limits: &Limits) -> Result<Policy, ProofError> {
    let root = v
        .as_object()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err("policy must be a JSON object"))?;
    reject_extra_keys(
        root,
        &["policy_version", "policy_id", "requirements"],
        "policy",
    )?;

    let version = match root.get("policy_version") {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
            ErrorCode::PolicyInvalid.err("policy_version must be a positive integer")
        })?,
        Some(_) => {
            return Err(ErrorCode::PolicyInvalid.err("policy_version must be a positive integer"));
        }
        None => return Err(ErrorCode::PolicyInvalid.err("policy missing field policy_version")),
    };
    if version != 1 {
        return Err(ErrorCode::UnsupportedVersion.err("only policy_version 1 is supported"));
    }
    let id = req_string(root, "policy_id", "policy")?;
    if id.is_empty() || id.len() > 128 {
        return Err(ErrorCode::PolicyInvalid.err("policy_id length out of bounds"));
    }
    let reqs = obj_get(v, "requirements")?;
    let reqs = reqs
        .as_array()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err("requirements must be an array"))?;
    if reqs.is_empty() {
        // Vacuous truth would PASS everything: refuse instead.
        return Err(ErrorCode::PolicyInvalid.err("requirements must not be empty"));
    }
    if reqs.len() > limits.max_policy_requirements {
        return Err(ErrorCode::LimitExceeded.err("too many policy requirements"));
    }
    let mut out = Vec::with_capacity(reqs.len());
    for (i, r) in reqs.iter().enumerate() {
        out.push(parse_requirement(r, i)?);
    }
    Ok(Policy {
        version: 1,
        id,
        requirements: out,
    })
}

fn parse_requirement(v: &serde_json::Value, index: usize) -> Result<Requirement, ProofError> {
    let what = format!("requirements[{index}]");
    let obj = v
        .as_object()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err(format!("{what} must be an object")))?;
    let t = req_string(obj, "type", &what)?;
    match t.as_str() {
        "signature_valid" => {
            reject_extra_keys(obj, &["type"], &what)?;
            Ok(Requirement::SignatureValid)
        }
        "issuer_trusted" => {
            reject_extra_keys(obj, &["type", "issuer"], &what)?;
            let issuer = req_string(obj, "issuer", &what)?;
            if !(issuer.starts_with("key:ed25519:") || issuer.starts_with("key:p256:")) {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: issuer must be a key:* KeyRef"))
                );
            }
            Ok(Requirement::IssuerTrusted { issuer })
        }
        "issuer_excluded" => {
            reject_extra_keys(obj, &["type", "issuer"], &what)?;
            let issuer = req_string(obj, "issuer", &what)?;
            if !(issuer.starts_with("key:ed25519:") || issuer.starts_with("key:p256:")) {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: issuer must be a key:* KeyRef"))
                );
            }
            Ok(Requirement::IssuerExcluded { issuer })
        }
        "relationship_exists" => {
            reject_extra_keys(obj, &["type", "relationship"], &what)?;
            let r = req_string(obj, "relationship", &what)?;
            // V1.0 NEUTRAL: accept any string, policy defines acceptable types
            let relationship = RelType::new(r);
            Ok(Requirement::RelationshipExists { relationship })
        }
        "not_expired" => {
            reject_extra_keys(obj, &["type"], &what)?;
            Ok(Requirement::NotExpired)
        }
        "not_revoked" => {
            reject_extra_keys(obj, &["type"], &what)?;
            Ok(Requirement::NotRevoked)
        }
        "not_superseded" => {
            reject_extra_keys(obj, &["type"], &what)?;
            Ok(Requirement::NotSuperseded)
        }
        "evidence_present" => {
            reject_extra_keys(obj, &["type", "kind"], &what)?;
            let k = req_string(obj, "kind", &what)?;
            // V1.0 NEUTRAL: accept any string, policy defines acceptable kinds
            let kind = EvidenceKind::new(k);
            Ok(Requirement::EvidencePresent { kind })
        }
        "transparency_present" => {
            reject_extra_keys(obj, &["type"], &what)?;
            Ok(Requirement::TransparencyPresent)
        }
        "proof_fresh" => {
            reject_extra_keys(obj, &["type", "max_age_seconds"], &what)?;
            let max_age = match obj.get("max_age_seconds") {
                Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    ErrorCode::PolicyInvalid
                        .err(format!("{what}: max_age_seconds must be positive"))
                })?,
                _ => {
                    return Err(
                        ErrorCode::PolicyInvalid.err(format!("{what}: max_age_seconds required"))
                    )
                }
            };
            Ok(Requirement::ProofFresh {
                max_age_seconds: max_age,
            })
        }
        _ => Err(ErrorCode::PolicyInvalid.err(format!("{what}: unknown requirement type {t}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> Limits {
        Limits::default()
    }

    fn policy_json() -> serde_json::Value {
        serde_json::json!({
            "policy_version": 1,
            "policy_id": "merchant_payment_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                {"type": "relationship_exists", "relationship": "SETTLES"},
                {"type": "not_expired"},
                {"type": "not_revoked"}
            ]
        })
    }

    #[test]
    fn valid_policy_parses() {
        let p = parse_policy(&policy_json(), &lim()).unwrap();
        assert_eq!(p.id, "merchant_payment_v1");
        assert_eq!(p.requirements.len(), 5);
    }

    #[test]
    fn not_superseded_parses_and_describes() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "current_only",
            "requirements": [{"type": "not_superseded"}]
        });
        let p = parse_policy(&v, &lim()).unwrap();
        assert_eq!(p.requirements, vec![Requirement::NotSuperseded]);
        assert_eq!(p.requirements[0].describe(), "not_superseded");
    }

    #[test]
    fn issuer_excluded_parses_and_describes() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "sanctions_screen",
            "requirements": [{"type": "issuer_excluded", "issuer": "key:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]
        });
        let p = parse_policy(&v, &lim()).unwrap();
        assert_eq!(p.requirements.len(), 1);
        assert!(p.requirements[0].describe().starts_with("issuer_excluded("));
        let mut bad = v.clone();
        bad["requirements"][0] =
            serde_json::json!({"type": "issuer_excluded", "issuer": "mallory"});
        assert_eq!(
            parse_policy(&bad, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn unknown_requirement_type_rejected() {
        let mut v = policy_json();
        v["requirements"][0] = serde_json::json!({"type": "vibes_good"});
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn extra_fields_rejected() {
        let mut v = policy_json();
        v["requirements"][0] = serde_json::json!({"type": "signature_valid", "severity": "low"});
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
        let mut v2 = policy_json();
        v2["author"] = serde_json::json!("mallory");
        assert_eq!(
            parse_policy(&v2, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn empty_requirements_rejected() {
        let mut v = policy_json();
        v["requirements"] = serde_json::json!([]);
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn bad_version_rejected() {
        let mut v = policy_json();
        v["policy_version"] = serde_json::json!(2);
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn bad_issuer_format_rejected() {
        // V1.0 NEUTRAL: relationship types are open vocabulary, any string accepted
        // This test now only checks issuer format validation
        let mut v = policy_json();
        v["requirements"][1] = serde_json::json!({"type": "issuer_trusted", "issuer": "mallory"});
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
        // Custom relationship types are accepted
        let mut v2 = policy_json();
        v2["requirements"][2] =
            serde_json::json!({"type": "relationship_exists", "relationship": "CUSTOM_REL"});
        let policy = parse_policy(&v2, &lim()).unwrap();
        assert_eq!(policy.requirements.len(), 5);
    }

    #[test]
    fn proof_fresh_parses_and_describes() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "fresh_only",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 300}]
        });
        let p = parse_policy(&v, &lim()).unwrap();
        assert_eq!(p.requirements.len(), 1);
        assert!(p.requirements[0].describe().contains("proof_fresh"));
        assert!(p.requirements[0].describe().contains("300"));
    }

    #[test]
    fn proof_fresh_missing_field_rejected() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "bad_fresh",
            "requirements": [{"type": "proof_fresh"}]
        });
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn proof_fresh_extra_field_rejected() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "bad_fresh",
            "requirements": [{"type": "proof_fresh", "max_age_seconds": 300, "extra": "no"}]
        });
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
        );
    }

    #[test]
    fn canonical_cbor_deterministic() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "test_v1",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "not_expired"}
            ]
        });
        let p1 = parse_policy(&v, &lim()).unwrap();
        let p2 = parse_policy(&v, &lim()).unwrap();
        let cbor1 = policy_to_canonical_cbor(&p1);
        let cbor2 = policy_to_canonical_cbor(&p2);
        assert_eq!(cbor1, cbor2, "canonical CBOR must be deterministic");
    }

    #[test]
    fn canonical_hash_stable() {
        let v = serde_json::json!({
            "policy_version": 1,
            "policy_id": "hash_test",
            "requirements": [{"type": "signature_valid"}]
        });
        let p = parse_policy(&v, &lim()).unwrap();
        let hash1 = canonical_policy_hash(&p);
        let hash2 = canonical_policy_hash(&p);
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("policy:v1:"));
    }

    #[test]
    fn canonical_cbor_same_policy_same_bytes() {
        // Same policy parsed from different JSON key orders should produce
        // identical canonical CBOR
        let v1 = serde_json::json!({
            "policy_version": 1,
            "policy_id": "order_test",
            "requirements": [{"type": "not_revoked"}]
        });
        let v2 = serde_json::json!({
            "policy_id": "order_test",
            "policy_version": 1,
            "requirements": [{"type": "not_revoked"}]
        });
        let p1 = parse_policy(&v1, &lim()).unwrap();
        let p2 = parse_policy(&v2, &lim()).unwrap();
        assert_eq!(policy_to_canonical_cbor(&p1), policy_to_canonical_cbor(&p2));
    }
}
