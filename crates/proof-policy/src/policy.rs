// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy schema + validator (spec §9). JSON is the input language; it is
//! validated BEFORE anything is evaluated, and never executed as code.

use proof_core::{
    model::{EvidenceKind, RelType},
    ErrorCode, Limits, ProofError,
};

/// Closed requirement set (V1). Unknown `type` values are rejected.
/// PE-POLICY-008.
///
/// V1 (`policy_version: 1`) accepts exactly the first ten variants, combined
/// by implicit AND. The eight adjudication variants below are V2-only
/// (`policy_version: 2`, usable inside boolean/threshold expressions):
/// v1 parsing rejects their type names, so v1 semantics are frozen
/// byte-for-byte while new trust questions become expressible.
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
    /// Uses the proof's `created_at` field, which IS covered by `proof_id`
    /// (V1 CORE freeze deviation, pre-V1.0 wire fix): re-stamping it breaks
    /// the id and fails `ID_MISMATCH` at IDENTIFIERS.
    ///
    /// SCOPE (read before relying on this): `created_at` is self-declared
    /// age bound against the verifier clock, not a trusted timestamp. The
    /// binding prevents silent re-stamps, but a holder can still mint a fresh
    /// proof wrapper around old members only by changing the id (resolving
    /// to nothing old). Pair with `not_expired` (signed attestation windows
    /// the holder cannot rewrite) and/or transparency anchoring for strong
    /// freshness.
    ProofFresh { max_age_seconds: u64 },
    // ---- V2 adjudication leaves (policy_version 2 only) ----
    /// `issuer` is authorized by `root`: root is trust-listed and issuer
    /// equals root (with a verified attestation) or chains to root through
    /// active `delegate` links. When `scope` is set, every traversed link
    /// must carry that exact scope string (scope is opaque to the core:
    /// string equality only, domain defines meaning). Delegation without a
    /// trusted root is nothing.
    DelegatedAuthority {
        root: String,
        issuer: String,
        scope: Option<String>,
    },
    /// Identifiers `a` and `b` are bound by `identity.bind` assertions and/or
    /// grounded EQUIVALENT edges from trust-listed asserters. The core never
    /// merges globally; this checks a verifier-scoped path.
    IdentityBound { a: String, b: String },
    /// A `transparency_receipt` is bound to a currently-valid
    /// `transparency.checkpoint` attestation issued by log `log`
    /// (registration → receipt → checkpoint freshness, adapter-verified
    /// inclusion beneath).
    TransparencyInclusion { log: String },
    /// No conflict groups are recorded in the verification report.
    /// Adjudication itself (thresholds, preferred issuers) composes with
    /// boolean connectives around the underlying requirements.
    NoConflictingEvidence,
    /// Namespace `ns` is used-or-declared only within the accepted version:
    /// every declaration of `ns` has version ≤ `max_version`, and `ns` is
    /// not used while undeclared. Unused namespaces pass vacuously.
    VocabularyAccepted { ns: String, max_version: u64 },
    /// Evidence of this kind exists with status AVAILABLE (digest-bound,
    /// present, not withdrawn/compromised/revoked/unknown). Strict
    /// counterpart to `evidence_present` for callers that need usability,
    /// not mere presence (e.g. renewal-carried evidence with unverified
    /// backing reads UNKNOWN and fails here while passing presence).
    EvidenceUsable { kind: EvidenceKind },
    /// The composition linkage directly names proof `id`. Composition
    /// hook: callers pinning which sources a proof must be built from.
    /// Direct linkage only (what `proof_id` binds); transitive closure is
    /// the bundle layer (`proof_verify::resolve`), not policy.
    RequiresReference { id: String },
    /// The composition linkage does not name proof `id`. Exclusion hook:
    /// callers forbidding a source (tainted origin, wrong upstream).
    /// Direct linkage only, like `RequiresReference`.
    ForbidsReference { id: String },
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
            Self::DelegatedAuthority {
                root,
                issuer,
                scope,
            } => match scope {
                None => format!("delegated_authority(root={root}, issuer={issuer})"),
                Some(sc) => {
                    format!("delegated_authority(root={root}, issuer={issuer}, scope={sc})")
                }
            },
            Self::IdentityBound { a, b } => format!("identity_bound({a}, {b})"),
            Self::TransparencyInclusion { log } => {
                format!("transparency_inclusion({log})")
            }
            Self::NoConflictingEvidence => "no_conflicting_evidence".into(),
            Self::VocabularyAccepted { ns, max_version } => {
                format!("vocabulary_accepted({ns}, max_version={max_version})")
            }
            Self::EvidenceUsable { kind } => format!("evidence_usable({})", kind.as_str()),
            Self::RequiresReference { id } => format!("requires_reference({id})"),
            Self::ForbidsReference { id } => format!("forbids_reference({id})"),
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
            Self::DelegatedAuthority { .. } => "delegated_authority",
            Self::IdentityBound { .. } => "identity_bound",
            Self::TransparencyInclusion { .. } => "transparency_inclusion",
            Self::NoConflictingEvidence => "no_conflicting_evidence",
            Self::VocabularyAccepted { .. } => "vocabulary_accepted",
            Self::EvidenceUsable { .. } => "evidence_usable",
            Self::RequiresReference { .. } => "requires_reference",
            Self::ForbidsReference { .. } => "forbids_reference",
        }
    }

    /// True for the eight V2-only adjudication leaves.
    pub fn is_v2_only(&self) -> bool {
        matches!(
            self,
            Self::DelegatedAuthority { .. }
                | Self::IdentityBound { .. }
                | Self::TransparencyInclusion { .. }
                | Self::NoConflictingEvidence
                | Self::VocabularyAccepted { .. }
                | Self::EvidenceUsable { .. }
                | Self::RequiresReference { .. }
                | Self::ForbidsReference { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub version: u8,
    pub id: String,
    /// V1 implicit-AND list. Non-empty for v1; always empty for v2 (which
    /// uses `expression`). V1 parsing rejects v2 leaf names, so v1 semantics
    /// are frozen byte-for-byte.
    pub requirements: Vec<Requirement>,
    /// V2 expression tree. `Some` for v2 policies, `None` for v1.
    pub expression: Option<super::expr::PolicyExpr>,
}

/// Serialize a Policy to canonical CBOR bytes.
/// Enables signing, comparison, and deterministic caching.
/// The canonical form uses sorted map keys and no extra whitespace.
/// V1 shape (`requirements` array) is unchanged; v2 encodes the expression
/// tree under `expression` with the same leaf maps.
pub fn policy_to_canonical_cbor(policy: &Policy) -> Vec<u8> {
    use proof_format::{encode_canonical, CborValue};

    let mut root = vec![
        (
            CborValue::Text("policy_id".into()),
            CborValue::Text(policy.id.clone()),
        ),
        (
            CborValue::Text("policy_version".into()),
            CborValue::Uint(policy.version as u64),
        ),
    ];
    if policy.version == 2 {
        if let Some(expr) = &policy.expression {
            root.push((
                CborValue::Text("expression".into()),
                super::expr::expression_to_cbor(expr),
            ));
        }
    } else {
        let mut reqs = Vec::new();
        for req in &policy.requirements {
            reqs.push(requirement_to_cbor(req));
        }
        root.push((
            CborValue::Text("requirements".into()),
            CborValue::Array(reqs),
        ));
    }

    encode_canonical(&CborValue::Map(root))
}

/// Canonical CBOR for one requirement leaf (shared by v1 lists and v2 trees).
pub(crate) fn requirement_to_cbor(req: &Requirement) -> proof_format::CborValue {
    use proof_format::{encode_canonical, CborValue};

    // Build CBOR representation with deterministic key ordering
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
        Requirement::EvidencePresent { kind } | Requirement::EvidenceUsable { kind } => {
            req_map.push((
                CborValue::Text("kind".into()),
                CborValue::Text(kind.as_str().into()),
            ));
        }
        Requirement::RequiresReference { id } | Requirement::ForbidsReference { id } => {
            req_map.push((CborValue::Text("id".into()), CborValue::Text(id.clone())));
        }
        Requirement::ProofFresh { max_age_seconds } => {
            req_map.push((
                CborValue::Text("max_age_seconds".into()),
                CborValue::Uint(*max_age_seconds),
            ));
        }
        Requirement::DelegatedAuthority {
            root,
            issuer,
            scope,
        } => {
            req_map.push((
                CborValue::Text("root".into()),
                CborValue::Text(root.clone()),
            ));
            req_map.push((
                CborValue::Text("issuer".into()),
                CborValue::Text(issuer.clone()),
            ));
            if let Some(sc) = scope {
                req_map.push((CborValue::Text("scope".into()), CborValue::Text(sc.clone())));
            }
        }
        Requirement::IdentityBound { a, b } => {
            req_map.push((CborValue::Text("a".into()), CborValue::Text(a.clone())));
            req_map.push((CborValue::Text("b".into()), CborValue::Text(b.clone())));
        }
        Requirement::TransparencyInclusion { log } => {
            req_map.push((CborValue::Text("log".into()), CborValue::Text(log.clone())));
        }
        Requirement::VocabularyAccepted { ns, max_version } => {
            req_map.push((CborValue::Text("ns".into()), CborValue::Text(ns.clone())));
            req_map.push((
                CborValue::Text("max_version".into()),
                CborValue::Uint(*max_version),
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
    CborValue::Map(req_map)
}

/// Compute a canonical hash of a policy for referencing by content.
/// Returns `policy:vN:<b64u(sha256(canonical_cbor))>` versioned by the
/// policy's own version (v1 output is byte-identical to before).
pub fn canonical_policy_hash(policy: &Policy) -> String {
    use proof_crypto::hash::sha256;
    use proof_crypto::id::b64u_nopad;

    let cbor = policy_to_canonical_cbor(policy);
    let hash = sha256(&cbor);
    format!("policy:v{}:{}", policy.version, b64u_nopad(&hash))
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
/// Version 1 keeps the implicit-AND requirements list (frozen); version 2
/// carries an `expression` tree (boolean connectives + thresholds over v1
/// leaves plus the eight V2 adjudication leaves).
pub fn parse_policy(v: &serde_json::Value, limits: &Limits) -> Result<Policy, ProofError> {
    let root = v
        .as_object()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err("policy must be a JSON object"))?;

    let version = match root.get("policy_version") {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
            ErrorCode::PolicyInvalid.err("policy_version must be a positive integer")
        })?,
        Some(_) => {
            return Err(ErrorCode::PolicyInvalid.err("policy_version must be a positive integer"));
        }
        None => return Err(ErrorCode::PolicyInvalid.err("policy missing field policy_version")),
    };
    let id = req_string(root, "policy_id", "policy")?;
    if id.is_empty() || id.len() > 128 {
        return Err(ErrorCode::PolicyInvalid.err("policy_id length out of bounds"));
    }
    match version {
        1 => {
            reject_extra_keys(
                root,
                &["policy_version", "policy_id", "requirements"],
                "policy",
            )?;
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
                expression: None,
            })
        }
        2 => {
            reject_extra_keys(
                root,
                &["policy_version", "policy_id", "expression"],
                "policy",
            )?;
            // Strict separation: v2 policies carry no v1 requirements list.
            if root.contains_key("requirements") {
                return Err(
                    ErrorCode::PolicyInvalid.err("v2 policy uses expression, not requirements")
                );
            }
            let expr_value = obj_get(v, "expression")?;
            let mut budget = limits.max_policy_requirements;
            let expr = super::expr::parse_expression(expr_value, "expression", &mut budget)?;
            Ok(Policy {
                version: 2,
                id,
                requirements: vec![],
                expression: Some(expr),
            })
        }
        _ => Err(ErrorCode::UnsupportedVersion.err("only policy_version 1 and 2 are supported")),
    }
}

fn parse_requirement(v: &serde_json::Value, index: usize) -> Result<Requirement, ProofError> {
    let what = format!("requirements[{index}]");
    let obj = v
        .as_object()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err(format!("{what} must be an object")))?;
    parse_requirement_inner(obj, &what, true)
}

/// Parse one requirement leaf inside a v2 expression. Accepts the ten frozen
/// v1 leaves plus the eight V2 adjudication leaves.
pub(crate) fn parse_requirement_v2_leaf(
    obj: &serde_json::Map<String, serde_json::Value>,
    what: &str,
) -> Result<Requirement, ProofError> {
    parse_requirement_inner(obj, what, false)
}

/// Shared leaf validation. `v1_only` rejects the eight V2 adjudication names,
/// freezing v1 semantics byte-for-byte.
fn parse_requirement_inner(
    obj: &serde_json::Map<String, serde_json::Value>,
    what: &str,
    v1_only: bool,
) -> Result<Requirement, ProofError> {
    let t = req_string(obj, "type", what)?;
    // Frozen v1: the eight adjudication names never parse under v1, so v1
    // semantics (and bytes) cannot drift as v2 grows.
    if v1_only
        && matches!(
            t.as_str(),
            "delegated_authority"
                | "identity_bound"
                | "transparency_inclusion"
                | "no_conflicting_evidence"
                | "vocabulary_accepted"
                | "evidence_usable"
                | "requires_reference"
                | "forbids_reference"
        )
    {
        return Err(ErrorCode::PolicyInvalid
            .err(format!("{what}: {} is v2-only (use policy_version 2)", t)));
    }
    match t.as_str() {
        "signature_valid" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::SignatureValid)
        }
        "issuer_trusted" => {
            reject_extra_keys(obj, &["type", "issuer"], what)?;
            let issuer = req_string(obj, "issuer", what)?;
            if !proof_crypto::keys::is_supported_keyref(&issuer) {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: issuer must be a key:* KeyRef"))
                );
            }
            Ok(Requirement::IssuerTrusted { issuer })
        }
        "issuer_excluded" => {
            reject_extra_keys(obj, &["type", "issuer"], what)?;
            let issuer = req_string(obj, "issuer", what)?;
            if !proof_crypto::keys::is_supported_keyref(&issuer) {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: issuer must be a key:* KeyRef"))
                );
            }
            Ok(Requirement::IssuerExcluded { issuer })
        }
        "relationship_exists" => {
            reject_extra_keys(obj, &["type", "relationship"], what)?;
            let r = req_string(obj, "relationship", what)?;
            // V1.0 NEUTRAL: accept any string, policy defines acceptable types
            let relationship = RelType::new(r);
            Ok(Requirement::RelationshipExists { relationship })
        }
        "not_expired" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::NotExpired)
        }
        "not_revoked" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::NotRevoked)
        }
        "not_superseded" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::NotSuperseded)
        }
        "evidence_present" => {
            reject_extra_keys(obj, &["type", "kind"], what)?;
            let k = req_string(obj, "kind", what)?;
            // V1.0 NEUTRAL: accept any string, policy defines acceptable kinds
            let kind = EvidenceKind::new(k);
            Ok(Requirement::EvidencePresent { kind })
        }
        "transparency_present" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::TransparencyPresent)
        }
        "proof_fresh" => {
            reject_extra_keys(obj, &["type", "max_age_seconds"], what)?;
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
        "delegated_authority" => {
            reject_extra_keys(obj, &["type", "root", "issuer", "scope"], what)?;
            let scope = match obj.get("scope") {
                None => None,
                Some(serde_json::Value::String(sc)) if !sc.is_empty() => Some(sc.clone()),
                _ => {
                    return Err(ErrorCode::PolicyInvalid
                        .err(format!("{what}: scope must be a non-empty string")))
                }
            };
            Ok(Requirement::DelegatedAuthority {
                root: require_keyref(obj, "root", what)?,
                issuer: require_keyref(obj, "issuer", what)?,
                scope,
            })
        }
        "identity_bound" => {
            reject_extra_keys(obj, &["type", "a", "b"], what)?;
            let a = req_string(obj, "a", what)?;
            let b = req_string(obj, "b", what)?;
            if a.is_empty() || b.is_empty() {
                return Err(ErrorCode::PolicyInvalid.err(format!("{what}: a/b must not be empty")));
            }
            Ok(Requirement::IdentityBound { a, b })
        }
        "transparency_inclusion" => {
            reject_extra_keys(obj, &["type", "log"], what)?;
            Ok(Requirement::TransparencyInclusion {
                log: require_keyref(obj, "log", what)?,
            })
        }
        "no_conflicting_evidence" => {
            reject_extra_keys(obj, &["type"], what)?;
            Ok(Requirement::NoConflictingEvidence)
        }
        "vocabulary_accepted" => {
            reject_extra_keys(obj, &["type", "ns", "max_version"], what)?;
            let ns = req_string(obj, "ns", what)?;
            if ns.is_empty() || ns.len() > 128 {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: ns length out of bounds"))
                );
            }
            let max_version = match obj.get("max_version") {
                Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    ErrorCode::PolicyInvalid.err(format!("{what}: max_version must be an integer"))
                })?,
                _ => {
                    return Err(
                        ErrorCode::PolicyInvalid.err(format!("{what}: max_version required"))
                    )
                }
            };
            Ok(Requirement::VocabularyAccepted { ns, max_version })
        }
        "evidence_usable" => {
            reject_extra_keys(obj, &["type", "kind"], what)?;
            let k = req_string(obj, "kind", what)?;
            // Open vocabulary like evidence_present: policy defines kinds.
            Ok(Requirement::EvidenceUsable {
                kind: EvidenceKind::new(k),
            })
        }
        "requires_reference" => {
            reject_extra_keys(obj, &["type", "id"], what)?;
            Ok(Requirement::RequiresReference {
                id: require_proof_ref(obj, "id", what)?,
            })
        }
        "forbids_reference" => {
            reject_extra_keys(obj, &["type", "id"], what)?;
            Ok(Requirement::ForbidsReference {
                id: require_proof_ref(obj, "id", what)?,
            })
        }
        _ => Err(ErrorCode::PolicyInvalid.err(format!("{what}: unknown requirement type {t}"))),
    }
}

/// `prf:v1:` proof-id field shared by reference hooks. Shape-checked at
/// parse time (like keyrefs): a typo'd id fails closed as POLICY_INVALID
/// rather than silently never matching.
fn require_proof_ref(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<String, ProofError> {
    let v = req_string(obj, key, what)?;
    proof_crypto::id::check_proof_ref_shape(&v).map_err(|e| {
        ErrorCode::PolicyInvalid.err(format!("{what}: {key} must be a prf:v1: id ({e})"))
    })?;
    Ok(v)
}

/// `key:*` KeyRef field shared by issuer/root/log bindings.
fn require_keyref(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    what: &str,
) -> Result<String, ProofError> {
    let v = req_string(obj, key, what)?;
    if !proof_crypto::keys::is_supported_keyref(&v) {
        return Err(ErrorCode::PolicyInvalid.err(format!("{what}: {key} must be a key:* KeyRef")));
    }
    Ok(v)
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
        v["policy_version"] = serde_json::json!(3);
        assert_eq!(
            parse_policy(&v, &lim()).unwrap_err().code,
            ErrorCode::UnsupportedVersion
        );
        // Version 2 dispatches to expression parsing (no v1 requirements key).
        let mut v2 = policy_json();
        v2["policy_version"] = serde_json::json!(2);
        assert_eq!(
            parse_policy(&v2, &lim()).unwrap_err().code,
            ErrorCode::PolicyInvalid
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
