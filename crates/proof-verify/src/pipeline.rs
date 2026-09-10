// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Staged verification pipeline (ARCHITECTURE §4, stages 1–11).
//! Order is fixed and every stage has one job. Failures are recorded, never
//! repaired; unknown is never converted into valid.
//! Stages 7 (TIME) and 8 (REVOCATION/SUPERSESSION) implement the lifecycle
//! state machine (Phase 6); policy (stage 12) is evaluated by the caller.

use std::collections::{HashMap, HashSet};

use proof_core::model::AttestationContent;
use proof_core::{ErrorCode, LifecycleStatus, Limits, ProofError};
use proof_crypto::build::verify_attestation;
use proof_crypto::build::verify_status_object;
use proof_crypto::claim::{claim_kind, revocation_target, supersession_pair, ClaimKind};
use proof_crypto::id::{b64u_nopad, proof_id};
use proof_crypto::{cose::parse_sign1, AllowedAlgs, COSE_ED25519, COSE_ESP256};
use proof_format::{
    attestation_to_cbor, cbor_to_proof, decode_strict, encode_canonical, event_to_cbor,
    evidence_to_cbor, proposition_to_cbor, relationship_to_cbor,
};
use proof_graph::{validate_graph, EdgeRecord, NodeSet};

use crate::report::{CheckRecord, LifecycleRecord, PolicyDecision, Validity, VerifyReport};

/// Explicit verifier inputs. Anything the verdict depends on that is not in
/// the Proof bytes must appear here (and is echoed in the explanation basis).
/// PE-TRUST-003: defaults fail closed (zero clock, empty trust, no status).
#[derive(Debug, Clone)]
pub struct VerifyCtx {
    /// Unix seconds from a caller-trustworthy clock. `0` is the fail-closed
    /// sentinel "no clock supplied": timeliness cannot be established, every
    /// attestation is EXPIRED (no trustworthy clock).
    pub verified_at: u64,
    /// Absorbs honest clock drift (default 300s). Applied to both bounds:
    /// `issued_at ≤ now+skew` and `now ≤ expires_at+skew`.
    pub clock_skew_leeway: u64,
    /// Trusted issuer keyrefs (used by callers that combine pipeline + policy;
    /// the pipeline itself never decides trust — that is the policy's job).
    pub trusted_issuers: Vec<String>,
    /// Must be false in V0.1: the verifier performs zero network I/O.
    pub allow_remote: bool,
    pub allowed_algs: AllowedAlgs,
    pub limits: Limits,
    /// Caller-supplied signed status objects: revoke/supersede attestations
    /// (FORMAT §4.7), i.e. the "verifier-supplied revocation set". Unsigned
    /// id lists are never trusted. Each is signature-verified end-to-end.
    pub status_objects: Vec<proof_crypto::SignedStatus>,
    /// Keyrefs empowered to sign status objects over ANY target, in addition
    /// to each target attestation's original issuer.
    pub revocation_authorities: Vec<String>,
    /// When the revocation/status information above was obtained (Unix secs).
    /// `None` → freshness unknown → attestations without a signed status are
    /// UNKNOWN → evidence invalid (fail closed, never PASS).
    pub revocations_known_at: Option<u64>,
    /// If true, report all failures instead of stopping at the first.
    /// Useful for debugging; default false for fail-fast behavior (V1.1).
    pub report_all_failures: bool,
}

impl Default for VerifyCtx {
    fn default() -> Self {
        Self {
            verified_at: 0,
            clock_skew_leeway: 300,
            trusted_issuers: vec![],
            allow_remote: false,
            allowed_algs: AllowedAlgs::strict(),
            limits: Limits::default(),
            status_objects: vec![],
            revocation_authorities: vec![],
            revocations_known_at: None,
            report_all_failures: false,
        }
    }
}

const CRYPTO_STAGES: &[&str] = &[
    "PARSE",
    "SCHEMA",
    "CANONICAL",
    "IDENTIFIERS",
    "SIGNATURES",
    "KEYS",
];
const EVIDENCE_STAGES: &[&str] = &["TIME", "REVOCATION", "EVIDENCE", "RELATIONSHIPS", "GRAPH"];

fn stage_valid(checks: &[CheckRecord], stages: &[&str]) -> Validity {
    let bad = checks.iter().any(|c| !c.ok && stages.contains(&c.stage));
    if bad {
        Validity::Invalid
    } else {
        Validity::Valid
    }
}

/// PE-VERIFY-010 (failures recorded never repaired) · PE-VERIFY-011 (early
/// exit reports evidence Invalid) · PE-VERIFY-012 (deterministic output).
fn finalize(
    proof_id: Option<String>,
    checks: Vec<CheckRecord>,
    note_extra: Option<CheckRecord>,
    lifecycle: Vec<LifecycleRecord>,
    status_objects: Vec<String>,
    lifecycle_checked: bool,
) -> VerifyReport {
    let mut checks = checks;
    if let Some(n) = note_extra {
        checks.push(n);
    }
    let cryptographic_validity = stage_valid(&checks, CRYPTO_STAGES);
    // Evidence stages never ran on early exit (PARSE/SCHEMA/CANONICAL
    // failure): report Invalid, never a vacuous Valid. Without this, garbage
    // bytes would present as `evidence_validity: valid` next to a crypto
    // failure (audit P1-1/P1-2: only callers ANDing both validities were safe).
    let evidence_validity = if lifecycle_checked {
        stage_valid(&checks, EVIDENCE_STAGES)
    } else {
        Validity::Invalid
    };
    VerifyReport {
        proof_id,
        cryptographic_validity,
        evidence_validity,
        policy_decision: PolicyDecision::Indeterminate,
        lifecycle_checked,
        lifecycle,
        status_objects,
        checks,
    }
}

/// Timeliness of an attestation against the explicit verifier clock.
/// Both bounds get the configured skew leeway. `verified_at == 0` means no
/// trustworthy clock — fail closed. The stable code is always `EXPIRED`.
fn time_validity(content: &AttestationContent, ctx: &VerifyCtx) -> Result<(), String> {
    let now = ctx.verified_at;
    let skew = ctx.clock_skew_leeway;
    if now == 0 {
        return Err(
            "no trustworthy clock: verified_at=0 (timeliness cannot be established)".into(),
        );
    }
    if content.issued_at > now.saturating_add(skew) {
        return Err(format!(
            "attestation issued_at {} > verifier clock {} + skew {} (not yet valid)",
            content.issued_at, now, skew
        ));
    }
    if let Some(exp) = content.expires_at {
        if now > exp.saturating_add(skew) {
            return Err(format!(
                "attestation expired at {} before verifier clock {} (skew {})",
                exp, now, skew
            ));
        }
    }
    Ok(())
}

/// Verify portable Proof bytes with no database access. Returns a report even
/// for malformed input (fail-closed as data). `Err` is reserved for caller
/// misuse (e.g. requesting remote fetches the engine will never perform).
pub fn verify_proof(bytes: &[u8], ctx: &VerifyCtx) -> Result<VerifyReport, ProofError> {
    // PE-SEC-003 · PE-EVID-003: no network fetch during verification.
    if ctx.allow_remote {
        return Err(ErrorCode::SchemaViolation
            .err("allow_remote=true is not supported: V0.1 never fetches during verification"));
    }
    let mut checks: Vec<CheckRecord> = vec![];

    // V1.1: Enforce VerifyCtx input vector bounds (DoS prevention).
    if ctx.status_objects.len() > ctx.limits.max_status_objects {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "status_objects count {} exceeds max_status_objects {}",
            ctx.status_objects.len(),
            ctx.limits.max_status_objects
        )));
    }
    if ctx.trusted_issuers.len() > ctx.limits.max_trusted_issuers {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "trusted_issuers count {} exceeds max_trusted_issuers {}",
            ctx.trusted_issuers.len(),
            ctx.limits.max_trusted_issuers
        )));
    }
    if ctx.revocation_authorities.len() > ctx.limits.max_revocation_authorities {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "revocation_authorities count {} exceeds max_revocation_authorities {}",
            ctx.revocation_authorities.len(),
            ctx.limits.max_revocation_authorities
        )));
    }

    // ---- 1. PARSE ----  PE-VERIFY-001
    let value = match decode_strict(bytes, &ctx.limits) {
        Ok(v) => {
            checks.push(CheckRecord::ok(
                "PARSE",
                "proof:bytes",
                "CBOR decoded within limits",
            ));
            v
        }
        Err(e) => {
            checks.push(CheckRecord::fail("PARSE", "proof:bytes", e.code, e.message));
            return Ok(finalize(
                None,
                checks,
                Some(policy_note()),
                vec![],
                vec![],
                false,
            ));
        }
    };

    // ---- 2. SCHEMA ----  PE-VERIFY-002
    let proof = match cbor_to_proof(&value, &ctx.limits) {
        Ok(p) => {
            checks.push(CheckRecord::ok(
                "SCHEMA",
                format!("proof:{}", p.proof_id),
                "envelope version, closed fields, member schemas valid",
            ));
            p
        }
        Err(e) => {
            checks.push(CheckRecord::fail(
                "SCHEMA",
                "proof:bytes",
                e.code,
                e.message,
            ));
            return Ok(finalize(
                None,
                checks,
                Some(policy_note()),
                vec![],
                vec![],
                false,
            ));
        }
    };
    let stored_id = proof.proof_id.clone();

    // ---- 3. CANONICAL ----  PE-VERIFY-003
    if encode_canonical(&value) != bytes {
        checks.push(CheckRecord::fail(
            "CANONICAL",
            format!("proof:{stored_id}"),
            ErrorCode::NonCanonical,
            "bytes are not the deterministic encoding",
        ));
        return Ok(finalize(
            Some(stored_id),
            checks,
            Some(policy_note()),
            vec![],
            vec![],
            false,
        ));
    }
    checks.push(CheckRecord::ok(
        "CANONICAL",
        format!("proof:{stored_id}"),
        "re-encoded bytes identical",
    ));

    // ---- Member canonicals + ids (shared basis for IDENTIFIERS and later) ----
    let mut event_ids = vec![];
    for e in &proof.events {
        event_ids.push(proof_crypto::id::event_id(&encode_canonical(
            &event_to_cbor(e).map_err(|e| {
                ErrorCode::SchemaViolation.err(format!("member event failed to encode: {e}"))
            })?,
        )));
    }
    let mut att_ids = vec![];
    for a in &proof.attestations {
        let canon = encode_canonical(&attestation_to_cbor(&a.content));
        att_ids.push(proof_crypto::id::attestation_id(&canon));
    }
    let mut evd_ids = vec![];
    for e in &proof.evidence {
        evd_ids.push(proof_crypto::id::evidence_id(&encode_canonical(
            &evidence_to_cbor(e),
        )));
    }
    let mut rel_ids = vec![];
    for r in &proof.relationships {
        rel_ids.push(proof_crypto::id::relationship_id(&encode_canonical(
            &relationship_to_cbor(r),
        )));
    }

    // ---- 4. IDENTIFIERS ----  PE-VERIFY-004
    let recomputed = proof_id(
        &proposition_to_cbor(&proof.proposition),
        &event_ids,
        &att_ids,
        &evd_ids,
        &rel_ids,
    );
    if recomputed != stored_id {
        checks.push(CheckRecord::fail(
            "IDENTIFIERS",
            format!("proof:{stored_id}"),
            ErrorCode::IdMismatch,
            format!("recomputed id {recomputed} (member set or proposition tampered?)"),
        ));
    } else {
        checks.push(CheckRecord::ok(
            "IDENTIFIERS",
            format!("proof:{stored_id}"),
            format!(
                "proof id binds {} events, {} attestations, {} evidence, {} relationships",
                event_ids.len(),
                att_ids.len(),
                evd_ids.len(),
                rel_ids.len()
            ),
        ));
    }

    // ---- 5+6. SIGNATURES + KEYS ----  PE-VERIFY-005 PE-VERIFY-006
    // `verified` collects attestations whose signature (and key binding) held.
    // Only these may influence lifecycle/evidence state later.
    let mut verified: Vec<(String, proof_core::model::AttestationContent)> = vec![];
    for (entry, att_id) in proof.attestations.iter().zip(att_ids.iter()) {
        let obj = format!("att:{att_id}");
        // Derive the self-bound issuer from the kid BEFORE crypto: the key the
        // signature must come from. Unknown/deprecated algs fail in verify.
        let parsed = match parse_sign1(&entry.sign1, &ctx.limits) {
            Ok(p) => p,
            Err(e) => {
                checks.push(CheckRecord::fail("SIGNATURES", obj, e.code, e.message));
                continue;
            }
        };
        let expected = match parsed.alg {
            COSE_ED25519 => format!("key:ed25519:{}", b64u_nopad(&parsed.kid)),
            COSE_ESP256 => format!("key:p256:{}", b64u_nopad(&parsed.kid)),
            _ => "key:unknown:placeholder".to_string(),
        };
        match verify_attestation(&entry.sign1, &expected, &ctx.allowed_algs, &ctx.limits) {
            Ok((content, id)) => {
                // The stored content must equal the authenticated payload content.
                if content != entry.content || id != *att_id {
                    checks.push(CheckRecord::fail(
                        "SIGNATURES",
                        obj,
                        ErrorCode::SignatureInvalid,
                        "envelope content differs from authenticated payload",
                    ));
                    continue;
                }
                checks.push(CheckRecord::ok(
                    "SIGNATURES",
                    obj.clone(),
                    format!("COSE alg {} verified", parsed.alg),
                ));
                checks.push(CheckRecord::ok(
                    "KEYS",
                    obj,
                    "kid well-formed, alg matches key shape, issuer bound to key",
                ));
                verified.push((att_id.clone(), entry.content.clone()));
            }
            Err(e) => {
                checks.push(CheckRecord::fail("SIGNATURES", obj, e.code, e.message));
            }
        }
    }
    if proof.attestations.is_empty() {
        checks.push(CheckRecord::note(
            "SIGNATURES",
            format!("proof:{stored_id}"),
            "no attestations present (policy decides whether that suffices)",
        ));
    }

    // ---- 7. TIME ----  PE-VERIFY-007 PE-LIFE-002 PE-LIFE-003
    // Timeliness of every signature-verified attestation against the explicit
    // verifier clock + skew. Any failure is `EXPIRED` (fail closed).
    let mut time_failed: HashSet<String> = HashSet::new();
    for (att_id, content) in &verified {
        let obj = format!("att:{att_id}");
        match time_validity(content, ctx) {
            Ok(()) => checks.push(CheckRecord::ok(
                "TIME",
                obj,
                format!(
                    "issued {} .. {} within verifier clock {} ± {}s",
                    content.issued_at,
                    content
                        .expires_at
                        .map_or_else(|| "∞".to_string(), |e| e.to_string()),
                    ctx.verified_at,
                    ctx.clock_skew_leeway
                ),
            )),
            Err(msg) => {
                time_failed.insert(att_id.clone());
                checks.push(CheckRecord::fail(
                    "TIME",
                    obj,
                    ErrorCode::Expired,
                    format!("{msg} (code EXPIRED, fail closed)"),
                ));
            }
        }
    }

    // ---- 8. REVOCATION + SUPERSESSION ----  PE-VERIFY-008 PE-LIFE-001 PE-LIFE-004 PE-LIFE-005 PE-LIFE-006
    // Status effects come from (a) embedded status attestations whose signature
    // already passed at SIGNATURES and (b) caller-supplied signed status
    // objects (VerifyCtx.status_objects). An effect applies only if its claim
    // is well-formed, its signer has authority over the target (original
    // issuer or a revocation authority), and it is not future-dated.
    #[derive(Debug, Clone)]
    struct StatusEffect {
        target: String,
        kind: ClaimKind,
        issuer: String,
        issued_at: u64,
        object: String,
    }
    let mut effects: Vec<StatusEffect> = vec![];
    let mut status_objects: Vec<String> = vec![];

    for (att_id, content) in &verified {
        let obj = format!("att:{att_id}");
        match claim_kind(content) {
            ClaimKind::Statement => {}
            ClaimKind::Revoke => {
                status_objects.push(att_id.clone());
                match revocation_target(content) {
                    Ok(target) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Revoke,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: obj,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        "REVOCATION",
                        obj,
                        e.code,
                        format!("malformed revoke claim: {}", e.message),
                    )),
                }
            }
            ClaimKind::Supersede => {
                status_objects.push(att_id.clone());
                match supersession_pair(content) {
                    Ok((old, _new)) => effects.push(StatusEffect {
                        target: old.to_string(),
                        kind: ClaimKind::Supersede,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: obj,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        "REVOCATION",
                        obj,
                        e.code,
                        format!("malformed supersede claim: {}", e.message),
                    )),
                }
            }
        }
    }

    for (i, status) in ctx.status_objects.iter().enumerate() {
        let label = format!("status:{}", i + 1);
        // The stated signer travels with the object (CLI verifies file-issuer ==
        // key at load); the signature is re-checked against it here, and
        // authority over the target is decided below — never from kid alone.
        match verify_status_object(
            &status.sign1,
            &status.content.issuer,
            &ctx.allowed_algs,
            &ctx.limits,
        ) {
            Ok(content) => match claim_kind(&content) {
                ClaimKind::Revoke => match revocation_target(&content) {
                    Ok(target) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Revoke,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: label,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        "REVOCATION",
                        label,
                        e.code,
                        format!("malformed revoke claim: {}", e.message),
                    )),
                },
                ClaimKind::Supersede => match supersession_pair(&content) {
                    Ok((old, _new)) => effects.push(StatusEffect {
                        target: old.to_string(),
                        kind: ClaimKind::Supersede,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: label,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        "REVOCATION",
                        label,
                        e.code,
                        format!("malformed supersede claim: {}", e.message),
                    )),
                },
                ClaimKind::Statement => checks.push(CheckRecord::fail(
                    "REVOCATION",
                    label,
                    ErrorCode::SchemaViolation,
                    "supplied object is not a status claim (revoke/supersede)",
                )),
            },
            Err(e) => checks.push(CheckRecord::fail(
                "REVOCATION",
                label,
                e.code,
                format!("status object rejected: {}", e.message),
            )),
        }
    }

    // Authority + own-timeliness validation; effects that fail never apply.
    let statement_by_id: HashMap<&str, &AttestationContent> = verified
        .iter()
        .filter(|(_, c)| claim_kind(c) == ClaimKind::Statement)
        .map(|(id, c)| (id.as_str(), c))
        .collect();
    let mut applies: Vec<(String, ClaimKind)> = vec![];
    for eff in &effects {
        let target_content = statement_by_id.get(eff.target.as_str());
        let empowered = match target_content {
            Some(tc) => tc.issuer == eff.issuer || ctx.revocation_authorities.contains(&eff.issuer),
            // Target outside this proof: only an explicit authority may claim
            // to touch it, and it has no lifecycle impact here regardless.
            None => ctx.revocation_authorities.contains(&eff.issuer),
        };
        if !empowered {
            checks.push(CheckRecord::fail(
                "REVOCATION",
                eff.object.clone(),
                ErrorCode::UnauthorizedStatus,
                format!(
                    "{} has no authority over {} (not the original issuer of the target, not in revocation_authorities)",
                    eff.issuer, eff.target
                ),
            ));
        }
        let timely = ctx.verified_at != 0
            && eff.issued_at <= ctx.verified_at.saturating_add(ctx.clock_skew_leeway);
        if !timely {
            checks.push(CheckRecord::fail(
                "REVOCATION",
                eff.object.clone(),
                ErrorCode::Expired,
                "status object is not valid yet at the verifier clock",
            ));
        }
        if empowered && timely {
            applies.push((eff.target.clone(), eff.kind));
        }
    }

    // Revocation info freshness: missing or stale → UNKNOWN → fail closed.
    let revocation_stale = ctx.revocations_known_at.is_none()
        || ctx
            .verified_at
            .saturating_sub(ctx.revocations_known_at.unwrap_or(0))
            > ctx.clock_skew_leeway;

    let mut lifecycle: Vec<LifecycleRecord> = vec![];
    for (att_id, content) in &verified {
        if claim_kind(content) != ClaimKind::Statement {
            continue;
        }
        let revoked = applies
            .iter()
            .any(|(t, k)| t == att_id && *k == ClaimKind::Revoke);
        let superseded = applies
            .iter()
            .any(|(t, k)| t == att_id && *k == ClaimKind::Supersede);
        let expired = time_failed.contains(att_id);
        let status = if revoked {
            LifecycleStatus::Revoked
        } else if superseded {
            LifecycleStatus::Superseded
        } else if expired {
            LifecycleStatus::Expired
        } else if revocation_stale {
            LifecycleStatus::Unknown
        } else {
            LifecycleStatus::Active
        };
        let obj = format!("att:{att_id}");
        let (code, ok, msg) = match status {
            LifecycleStatus::Active => (
                None,
                true,
                format!("lifecycle ACTIVE at {}", ctx.verified_at),
            ),
            LifecycleStatus::Revoked => (
                Some(ErrorCode::Revoked),
                false,
                "lifecycle REVOKED by a valid signed revocation (claim.type=revoke)"
                    .to_string(),
            ),
            LifecycleStatus::Superseded => (
                None,
                true,
                "lifecycle SUPERSEDED — historical record preserved; a signed supersession points to a newer attestation".to_string(),
            ),
            LifecycleStatus::Expired => (
                Some(ErrorCode::Expired),
                true,
                "lifecycle EXPIRED (timeliness failed at TIME stage)".to_string(),
            ),
            LifecycleStatus::Unknown => (
                Some(ErrorCode::RevocationUnknown),
                false,
                "lifecycle UNKNOWN — no or stale revocation information; fail closed"
                    .to_string(),
            ),
        };
        if ok {
            checks.push(CheckRecord::ok("REVOCATION", obj.clone(), msg.clone()));
        } else {
            checks.push(CheckRecord::fail(
                "REVOCATION",
                obj.clone(),
                code.unwrap_or(ErrorCode::RevocationUnknown),
                msg.clone(),
            ));
        }
        lifecycle.push(LifecycleRecord {
            object: obj,
            status,
            code,
            message: msg,
        });
    }
    checks.push(CheckRecord::note(
        "REVOCATION",
        format!("proof:{stored_id}"),
        format!(
            "lifecycle checked for {} attestation(s); {} + {} status object(s); revocation info {}",
            lifecycle.len(),
            status_objects.len(),
            ctx.status_objects.len(),
            ctx.revocations_known_at.map_or_else(
                || "UNKNOWN (fail closed)".to_string(),
                |t| format!("known as of {t}")
            ),
        ),
    ));

    // ---- 9. EVIDENCE ----  PE-VERIFY-009 PE-EVID-002
    // Digest bindings were recomputed above (ids). Here: attestation→evidence
    // references resolve, and external digests are marked digest-only.
    let node_ids: Vec<String> = event_ids
        .iter()
        .chain(att_ids.iter())
        .chain(evd_ids.iter())
        .cloned()
        .collect();
    let node_set = NodeSet::new(node_ids);
    let mut evidence_bad = false;
    for a in &proof.attestations {
        if let Some(r) = &a.content.evidence_ref {
            if !node_set.contains(r) {
                checks.push(CheckRecord::fail(
                    "EVIDENCE",
                    format!("proof:{stored_id}"),
                    ErrorCode::DanglingReference,
                    format!("attestation evidence_ref {r} not in proof"),
                ));
                evidence_bad = true;
            }
        }
    }
    if !evidence_bad {
        checks.push(CheckRecord::ok(
            "EVIDENCE",
            format!("proof:{stored_id}"),
            format!(
                "{} evidence digests bound by id; external content is digest-only (no fetch in V0.1)",
                evd_ids.len()
            ),
        ));
    }

    // ---- 10+11. RELATIONSHIPS + GRAPH ----  PE-VERIFY-009
    let edges: Vec<EdgeRecord> = proof
        .relationships
        .iter()
        .zip(rel_ids.iter())
        .map(|(r, id)| EdgeRecord::new(r.clone(), id.clone()))
        .collect();
    match validate_graph(&edges, &node_set, &ctx.limits) {
        Ok(g) => {
            checks.push(CheckRecord::ok(
                "RELATIONSHIPS",
                format!("proof:{stored_id}"),
                format!("{} endpoints resolve, grounding satisfied", g.edge_count),
            ));
            checks.push(CheckRecord::ok(
                "GRAPH",
                format!("proof:{stored_id}"),
                format!(
                    "{} nodes, {} edges consistent (longest supersedes chain {})",
                    g.node_count, g.edge_count, g.longest_supersedes_chain
                ),
            ));
        }
        Err(e) => {
            let stage = match e.code {
                ErrorCode::RelationshipUngrounded | ErrorCode::DanglingReference => "RELATIONSHIPS",
                _ => "GRAPH",
            };
            checks.push(CheckRecord::fail(
                stage,
                format!("proof:{stored_id}"),
                e.code,
                e.message,
            ));
        }
    }

    Ok(finalize(
        Some(stored_id),
        checks,
        Some(policy_note()),
        lifecycle,
        status_objects,
        true,
    ))
}

fn policy_note() -> CheckRecord {
    CheckRecord::note(
        "POLICY",
        "policy:caller",
        "policy decision is made by the caller via proof-policy::evaluate_policy; the pipeline reports INDETERMINATE (never PASS by default)",
    )
}
