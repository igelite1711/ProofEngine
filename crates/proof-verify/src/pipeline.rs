// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Staged verification pipeline (ARCHITECTURE §4, stages 1–11).
//! Order is fixed and every stage has one job. Failures are recorded, never
//! repaired; unknown is never converted into valid.
//! Stages 7 (TIME) and 8 (REVOCATION/SUPERSESSION) implement the lifecycle
//! state machine (Phase 6); policy (stage 12) is evaluated by the caller.

use std::collections::{HashMap, HashSet};

use proof_core::model::{AttestationContent, EvidenceStatus, VocabularyAccept, VocabularyDecl};
use proof_core::{ErrorCode, LifecycleStatus, Limits, ProofError};
use proof_crypto::build::verify_attestation;
use proof_crypto::build::verify_status_object;
use proof_crypto::claim::{
    claim_kind, compromise_mark, denial_target, revocation_target, supersession_pair,
    withdrawal_target, ClaimKind,
};
use proof_crypto::id::{b64u_nopad, check_proof_ref_shape, proof_id_full};
use proof_crypto::{cose::parse_sign1, AllowedAlgs, COSE_ED25519, COSE_ESP256};
use proof_format::{
    attestation_to_cbor, cbor_to_proof, decode_strict, encode_canonical, event_to_cbor,
    evidence_to_cbor, proposition_to_cbor, relationship_to_cbor,
};
use proof_graph::{validate_graph_with_grounding, EdgeRecord, NodeSet};

use crate::report::{
    CheckRecord, ConflictKind, ConflictRecord, EvidenceStatusRecord, LifecycleRecord,
    PolicyDecision, Validity, VerifyReport,
};

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
    /// Semantics: PARSE/SCHEMA always fail fast (no proof object exists to
    /// continue with). CANONICAL fails fast when false and continues
    /// collecting when true (evidence forced Invalid either way).
    /// IDENTIFIERS and all later stages always collect so structural facts
    /// (grounding, lifecycle, graph) are visible alongside id mismatches.
    pub report_all_failures: bool,
    /// Accepted label vocabularies: namespace → max acceptable version.
    /// Empty (default) means no vocabulary restriction: the pipeline emits
    /// no acceptance notes and policy decides everything. Non-empty enables
    /// per-namespace ACCEPTED/UNKNOWN/version notes (informational only;
    /// unknown vocabulary never fails the core — acceptance is policy).
    pub accepted_vocabularies: Vec<VocabularyAccept>,
    /// Extra trust-relevant edge types beyond the V1 `requires_grounding()`
    /// set. Empty (default) = V1 defaults; threaded to
    /// `validate_graph_with_grounding` so future vocabularies declare their
    /// own trust-relevant kinds without a core change (AUDIT §5).
    pub extra_grounded: Vec<String>,
    /// Provenance DAG profile (V1.1 F4 fix, default false = V1 semantics).
    /// False: only the SUPERSEDES subgraph must be linear/acyclic (V1 rule);
    /// general cycles (e.g. REFERENCES A→B→C→A) are linkage-valid.
    /// True: the full relationship graph must additionally be acyclic
    /// (iterative DFS over member endpoints; EQUIVALENT identity refs
    /// excluded). Provenance users (derived-from chains) SHOULD enable this;
    /// linkage users (citations, see-also) SHOULD leave it off. Opt-in, so
    /// existing proofs keep byte-identical verdicts unless the caller asks.
    pub require_acyclic_provenance: bool,
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
            accepted_vocabularies: vec![],
            extra_grounded: vec![],
            require_acyclic_provenance: false,
        }
    }
}

impl VerifyCtx {
    /// Populate signed status inputs from a `StatusSource` adapter.
    /// Offline default unchanged: direct `status_objects` users never call
    /// this. Objects are still re-verified end-to-end; the source is never
    /// trusted.
    pub fn with_status_source<S: crate::status::StatusSource>(
        mut self,
        source: &S,
    ) -> Result<Self, ProofError> {
        let objects = source.status_at(self.verified_at)?;
        self.status_objects = objects;
        if self.revocations_known_at.is_none() {
            self.revocations_known_at = source.known_at();
        }
        Ok(self)
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
/// Status-input hygiene stage (V1.1 fix for external-review F2).
/// `STATUS` records caller-feed and ineffective-effect problems —
/// malformed status claims, non-status supplied objects, bad signatures on
/// supplied objects, unauthorized effects, and future-dated effects.
/// These NEVER flip `evidence_validity`: an ineffective effect leaves the
/// target lifecycle untouched (ACTIVE stays ACTIVE). Feed health is exposed
/// separately via `VerifyReport::status_inputs_valid` so callers can
/// distinguish "proof revoked" from "feed broken" without conflating them.
/// Lifecycle outcomes (REVOKED/COMPROMISED/UNKNOWN) stay in `REVOCATION`
/// and DO flip validity.
const STATUS_STAGE: &str = "STATUS";

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
/// Eight narrowly-typed inputs (allowed: one purpose-built assembler, not a
/// general API — the arity is the report shape, not incidental complexity).
#[allow(clippy::too_many_arguments)]
fn finalize(
    proof_id: Option<String>,
    checks: Vec<CheckRecord>,
    note_extra: Option<CheckRecord>,
    lifecycle: Vec<LifecycleRecord>,
    status_objects: Vec<String>,
    withdrawn_ids: Vec<String>,
    referenced_proofs: Vec<String>,
    vocabularies: Vec<VocabularyDecl>,
    evidence_status: Vec<EvidenceStatusRecord>,
    conflicts: Vec<ConflictRecord>,
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
    // NOTE: STATUS-stage input-hygiene failures are intentionally excluded
    // from EVIDENCE_STAGES (see STATUS_STAGE): a bad feed must not poison a
    // good proof. Feed health travels in `status_inputs_valid`.
    let evidence_validity = if lifecycle_checked {
        stage_valid(&checks, EVIDENCE_STAGES)
    } else {
        Validity::Invalid
    };
    let status_inputs_valid = !checks.iter().any(|c| !c.ok && c.stage == STATUS_STAGE);
    VerifyReport {
        proof_id,
        cryptographic_validity,
        evidence_validity,
        policy_decision: PolicyDecision::Indeterminate,
        lifecycle_checked,
        lifecycle,
        status_objects,
        withdrawn_ids,
        referenced_proofs,
        vocabularies,
        evidence_status,
        conflicts,
        checks,
        status_inputs_valid,
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
/// Recompute the proof id over a parsed proof's own members. Exposed so
/// tests, front ends and tooling share the exact binding the verifier checks
/// at IDENTIFIERS (including the `created_at` term).
pub fn recomputed_proof_id(proof: &proof_core::model::Proof) -> Result<String, ProofError> {
    let event_ids: Vec<String> = proof
        .events
        .iter()
        .map(|e| {
            Ok(proof_crypto::id::event_id(&encode_canonical(
                &event_to_cbor(e).map_err(|e| {
                    ErrorCode::SchemaViolation.err(format!("member event failed to encode: {e}"))
                })?,
            )))
        })
        .collect::<Result<Vec<_>, ProofError>>()?;
    let att_ids: Vec<String> = proof
        .attestations
        .iter()
        .map(|a| {
            proof_crypto::id::attestation_id(&encode_canonical(&attestation_to_cbor(&a.content)))
        })
        .collect();
    let evd_ids: Vec<String> = proof
        .evidence
        .iter()
        .map(|e| proof_crypto::id::evidence_id(&encode_canonical(&evidence_to_cbor(e))))
        .collect();
    let rel_ids: Vec<String> = proof
        .relationships
        .iter()
        .map(|r| proof_crypto::id::relationship_id(&encode_canonical(&relationship_to_cbor(r))))
        .collect();
    let vocab_pairs: Vec<(String, u64)> = proof
        .vocabularies
        .iter()
        .map(|vd| (vd.ns.clone(), vd.version))
        .collect();
    Ok(proof_id_full(
        &proposition_to_cbor(&proof.proposition),
        proof.created_at,
        &event_ids,
        &att_ids,
        &evd_ids,
        &rel_ids,
        &proof.referenced_proofs,
        &vocab_pairs,
    ))
}

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
                vec![],
                vec![],
                vec![],
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
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
            ));
        }
    };
    let stored_id = proof.proof_id.clone();

    // ---- Vocabulary negotiation notes (informational only) ----
    // Declaration is provenance, acceptance is policy: unknown or undeclared
    // vocabulary NEVER fails the core. Notes are emitted only when the proof
    // declares vocabularies or the context restricts them, so V1 proofs see
    // zero new records.
    {
        use proof_core::model::vocabulary_ns;
        use std::collections::BTreeSet;
        let mut used: BTreeSet<&str> = BTreeSet::new();
        for e in &proof.events {
            used.insert(vocabulary_ns(e.event_type.as_str()));
        }
        for a in &proof.attestations {
            used.insert(vocabulary_ns(a.content.claim.claim_type.as_str()));
        }
        for e in &proof.evidence {
            used.insert(vocabulary_ns(e.kind.as_str()));
        }
        for r in &proof.relationships {
            used.insert(vocabulary_ns(r.rel_type.as_str()));
        }
        used.insert(vocabulary_ns(proof.proposition.kind.as_str()));
        used.insert(vocabulary_ns(proof.proposition.predicate.as_str()));
        let declared: HashMap<&str, u64> = proof
            .vocabularies
            .iter()
            .map(|vd| (vd.ns.as_str(), vd.version))
            .collect();
        if !proof.vocabularies.is_empty() {
            let mut undeclared: Vec<&&str> = used
                .iter()
                .filter(|ns| !declared.contains_key(**ns))
                .collect();
            undeclared.sort();
            for ns in undeclared {
                checks.push(CheckRecord::note(
                    "SCHEMA",
                    format!("proof:{stored_id}"),
                    format!(
                        "vocabulary namespace `{ns}` used but not declared (declaration is provenance; acceptance is policy)"
                    ),
                ));
            }
        }
        if !ctx.accepted_vocabularies.is_empty() {
            for vd in &proof.vocabularies {
                match ctx.accepted_vocabularies.iter().find(|a| a.ns == vd.ns) {
                    None => checks.push(CheckRecord::note(
                        "SCHEMA",
                        format!("proof:{stored_id}"),
                        format!(
                            "vocabulary `{}` declared but not in accepted vocabularies (policy adjudicates)",
                            vd.ns
                        ),
                    )),
                    Some(acc) if vd.version > acc.max_version => {
                        checks.push(CheckRecord::note(
                            "SCHEMA",
                            format!("proof:{stored_id}"),
                            format!(
                                "vocabulary `{}` declared at version {} exceeds accepted max {} (policy adjudicates)",
                                vd.ns, vd.version, acc.max_version
                            ),
                        ))
                    }
                    _ => {}
                }
            }
            let mut unknown: Vec<&&str> = used
                .iter()
                .filter(|ns| {
                    !ctx.accepted_vocabularies
                        .iter()
                        .any(|a| a.ns.as_str() == **ns)
                })
                .collect();
            unknown.sort();
            for ns in unknown {
                checks.push(CheckRecord::note(
                    "SCHEMA",
                    format!("proof:{stored_id}"),
                    format!(
                        "vocabulary namespace `{ns}` used but not in accepted vocabularies (policy adjudicates)"
                    ),
                ));
            }
        }
    }

    // ---- 3. CANONICAL ----  PE-VERIFY-003
    let mut canonical_failed = false;
    if encode_canonical(&value) != bytes {
        canonical_failed = true;
        checks.push(CheckRecord::fail(
            "CANONICAL",
            format!("proof:{stored_id}"),
            ErrorCode::NonCanonical,
            "bytes are not the deterministic encoding",
        ));
        if !ctx.report_all_failures {
            return Ok(finalize(
                Some(stored_id),
                checks,
                Some(policy_note()),
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                false,
            ));
        }
        // Fail-collect: continue so IDENTIFIERS/SIGNATURES/TIME/etc. also
        // report. Evidence stays Invalid (forced below) because non-canonical
        // bytes must never yield valid evidence.
    } else {
        checks.push(CheckRecord::ok(
            "CANONICAL",
            format!("proof:{stored_id}"),
            "re-encoded bytes identical",
        ));
    }

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
    // The binding covers member id sets, the creation timestamp, composition
    // linkage and vocabulary declarations (empty linkage/vocab sets encode the
    // byte-identical extension of the base V1 binding).
    let recomputed = recomputed_proof_id(&proof)?;
    if recomputed != stored_id {
        checks.push(CheckRecord::fail(
            "IDENTIFIERS",
            format!("proof:{stored_id}"),
            ErrorCode::IdMismatch,
            format!("recomputed id {recomputed} (member set or proposition tampered?)"),
        ));
        // Always continue to SIGNATURES/etc. after an id mismatch: later
        // stage records (e.g. RELATIONSHIPS grounding) are structural facts
        // callers and the neutrality suite rely on. Crypto is already Invalid
        // via this record; fail-fast vs collect is governed at CANONICAL
        // (where bytes cannot be trusted further) not here.
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
        // signature must come from. Unknown algs fail in verify; deprecated
        // ids map onto their fully-specified key shape for historical mode.
        let parsed = match parse_sign1(&entry.sign1, &ctx.limits) {
            Ok(p) => p,
            Err(e) => {
                let stage = match e.code {
                    ErrorCode::AlgorithmConfusion
                    | ErrorCode::UnknownAlgorithm
                    | ErrorCode::DeprecatedAlgorithm
                    | ErrorCode::UnexpectedHeaderParam => "KEYS",
                    _ => "SIGNATURES",
                };
                checks.push(CheckRecord::fail(stage, obj, e.code, e.message));
                continue;
            }
        };
        let expected = match parsed.alg {
            COSE_ED25519 => format!("key:ed25519:{}", b64u_nopad(&parsed.kid)),
            COSE_ESP256 => format!("key:p256:{}", b64u_nopad(&parsed.kid)),
            -8 if parsed.kid.len() == 32 => {
                format!("key:ed25519:{}", b64u_nopad(&parsed.kid))
            }
            -7 if parsed.kid.len() == 64 => {
                format!("key:p256:{}", b64u_nopad(&parsed.kid))
            }
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
                    if proof_crypto::AllowedAlgs::is_deprecated(parsed.alg) {
                        format!(
                            "COSE alg {} verified under explicit historical policy (was-valid-then; current acceptance still decided by policy)",
                            parsed.alg
                        )
                    } else {
                        format!("COSE alg {} verified", parsed.alg)
                    },
                ));
                checks.push(CheckRecord::ok(
                    "KEYS",
                    obj,
                    "kid well-formed, alg matches key shape, issuer bound to key",
                ));
                verified.push((att_id.clone(), entry.content.clone()));
            }
            Err(e) => {
                // Key-shape/alg confusion belongs to KEYS per ERROR-MODEL;
                // crypto failures stay under SIGNATURES.
                let stage = match e.code {
                    ErrorCode::AlgorithmConfusion
                    | ErrorCode::UnknownAlgorithm
                    | ErrorCode::DeprecatedAlgorithm
                    | ErrorCode::UnexpectedHeaderParam => "KEYS",
                    _ => "SIGNATURES",
                };
                checks.push(CheckRecord::fail(stage, obj, e.code, e.message));
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
    // Timeliness of every signature-verified STATEMENT attestation against
    // the explicit verifier clock + skew. Any failure is `EXPIRED` (fail
    // closed). Status attestations (revoke/supersede/withdraw/compromise)
    // are excluded here by design (V1.1 F2): their own timeliness is
    // effect-timeliness, recorded in STATUS as feed hygiene — a future-dated
    // revoke must not poison TIME when its effect never applies.
    let mut time_failed: HashSet<String> = HashSet::new();
    for (att_id, content) in &verified {
        if claim_kind(content) != ClaimKind::Statement {
            continue;
        }
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

    // ---- 8. REVOCATION + SUPERSESSION + WITHDRAWAL + COMPROMISE ----
    // PE-VERIFY-008 PE-LIFE-001 PE-LIFE-004 PE-LIFE-005 PE-LIFE-006.
    // Status effects come from (a) embedded status attestations whose signature
    // already passed at SIGNATURES and (b) caller-supplied signed status
    // objects (VerifyCtx.status_objects). An effect applies only if its claim
    // is well-formed, its signer has authority over the target, and it is not
    // future-dated. Revoke/supersede end currency of attestations; withdraw
    // ends reliance on any artifact (evidence status); compromise taints an
    // identity at/after its instant (history not preserved, unlike revocation).
    #[derive(Debug, Clone)]
    struct StatusEffect {
        target: String,
        kind: ClaimKind,
        issuer: String,
        issued_at: u64,
        object: String,
        /// Compromise instant for `Compromise` (from `at_time`); else `None`.
        at_time: Option<u64>,
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
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
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
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        obj,
                        e.code,
                        format!("malformed supersede claim: {}", e.message),
                    )),
                }
            }
            ClaimKind::Withdraw => {
                status_objects.push(att_id.clone());
                match withdrawal_target(content) {
                    Ok(target) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Withdraw,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: obj,
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        obj,
                        e.code,
                        format!("malformed withdraw claim: {}", e.message),
                    )),
                }
            }
            ClaimKind::Compromise => {
                status_objects.push(att_id.clone());
                match compromise_mark(content) {
                    Ok((target, at_time)) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Compromise,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: obj,
                        at_time: Some(at_time),
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        obj,
                        e.code,
                        format!("malformed compromise claim: {}", e.message),
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
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
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
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        label,
                        e.code,
                        format!("malformed supersede claim: {}", e.message),
                    )),
                },
                ClaimKind::Withdraw => match withdrawal_target(&content) {
                    Ok(target) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Withdraw,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: label,
                        at_time: None,
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        label,
                        e.code,
                        format!("malformed withdraw claim: {}", e.message),
                    )),
                },
                ClaimKind::Compromise => match compromise_mark(&content) {
                    Ok((target, at_time)) => effects.push(StatusEffect {
                        target: target.to_string(),
                        kind: ClaimKind::Compromise,
                        issuer: content.issuer.clone(),
                        issued_at: content.issued_at,
                        object: label,
                        at_time: Some(at_time),
                    }),
                    Err(e) => checks.push(CheckRecord::fail(
                        STATUS_STAGE,
                        label,
                        e.code,
                        format!("malformed compromise claim: {}", e.message),
                    )),
                },
                ClaimKind::Statement => checks.push(CheckRecord::fail(
                    STATUS_STAGE,
                    label,
                    ErrorCode::SchemaViolation,
                    "supplied object is not a status claim (revoke/supersede/withdraw/compromise)",
                )),
            },
            Err(e) => checks.push(CheckRecord::fail(
                STATUS_STAGE,
                label,
                e.code,
                format!("status object rejected: {}", e.message),
            )),
        }
    }

    // Authority + own-timeliness validation; effects that fail never apply.
    // Revoke/supersede: original issuer of the target attestation, or an
    // explicit authority. Withdraw: an explicit authority, the issuer of the
    // target attestation, or the issuer of an evidence item's bound
    // attestation (events/relationships need explicit authority — unsigned
    // happenings have no issuer of their own). Compromise: the target
    // identity itself (self-report) or an explicit authority. Compromise only
    // ever invalidates (fail-closed direction), so self-report grants nothing.
    let statement_by_id: HashMap<&str, &AttestationContent> = verified
        .iter()
        .filter(|(_, c)| claim_kind(c) == ClaimKind::Statement)
        .map(|(id, c)| (id.as_str(), c))
        .collect();
    let issuer_by_att_id: HashMap<&str, &str> = verified
        .iter()
        .map(|(id, c)| (id.as_str(), c.issuer.as_str()))
        .collect();
    let mut applies: Vec<(String, ClaimKind)> = vec![];
    let mut compromises: Vec<(String, u64)> = vec![];
    let mut withdrawn: Vec<String> = vec![];
    for eff in &effects {
        let empowered = match eff.kind {
            ClaimKind::Compromise => {
                eff.issuer == eff.target || ctx.revocation_authorities.contains(&eff.issuer)
            }
            ClaimKind::Withdraw => {
                if ctx.revocation_authorities.contains(&eff.issuer) {
                    true
                } else if let Some(iss) = issuer_by_att_id.get(eff.target.as_str()) {
                    // Target is a known attestation: its own issuer may
                    // withdraw it.
                    *iss == eff.issuer
                } else {
                    // Target is evidence: the issuer of its bound attestation
                    // (if any) may withdraw it. Events/relationships need
                    // explicit authority.
                    proof.evidence.iter().zip(evd_ids.iter()).any(|(ev, eid)| {
                        eid == &eff.target
                            && ev.attestation_ref.as_deref().is_some_and(|aref| {
                                issuer_by_att_id
                                    .get(aref)
                                    .is_some_and(|iss| *iss == eff.issuer)
                            })
                    })
                }
            }
            _ => {
                let target_content = statement_by_id.get(eff.target.as_str());
                match target_content {
                    Some(tc) => {
                        tc.issuer == eff.issuer || ctx.revocation_authorities.contains(&eff.issuer)
                    }
                    // Target outside this proof: only an explicit authority may claim
                    // to touch it, and it has no lifecycle impact here regardless.
                    None => ctx.revocation_authorities.contains(&eff.issuer),
                }
            }
        };
        if !empowered {
            checks.push(CheckRecord::fail(
                STATUS_STAGE,
                eff.object.clone(),
                ErrorCode::UnauthorizedStatus,
                format!(
                    "{} has no authority for this status kind over {} (needs original issuer, bound-attestation issuer, self-report, or revocation_authorities as applicable)",
                    eff.issuer, eff.target
                ),
            ));
        }
        let timely = ctx.verified_at != 0
            && eff.issued_at <= ctx.verified_at.saturating_add(ctx.clock_skew_leeway);
        if !timely {
            checks.push(CheckRecord::fail(
                STATUS_STAGE,
                eff.object.clone(),
                ErrorCode::Expired,
                "status object is not valid yet at the verifier clock",
            ));
        }
        if empowered && timely {
            applies.push((eff.target.clone(), eff.kind));
            if eff.kind == ClaimKind::Withdraw && !withdrawn.contains(&eff.target) {
                withdrawn.push(eff.target.clone());
            }
            if eff.kind == ClaimKind::Compromise {
                if let Some(at) = eff.at_time {
                    compromises.push((eff.target.clone(), at));
                }
            }
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
        // Compromise taints by issuer at/after the instant (history not
        // preserved); an id-targeted marking taints that attestation too.
        let compromised = compromises
            .iter()
            .any(|(t, at)| (*t == content.issuer || *t == *att_id) && content.issued_at >= *at);
        let revoked = applies
            .iter()
            .any(|(t, k)| t == att_id && *k == ClaimKind::Revoke);
        let superseded = applies
            .iter()
            .any(|(t, k)| t == att_id && *k == ClaimKind::Supersede);
        let expired = time_failed.contains(att_id);
        let status = if compromised {
            LifecycleStatus::Compromised
        } else if revoked {
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
            LifecycleStatus::Compromised => (
                Some(ErrorCode::Compromised),
                false,
                "lifecycle COMPROMISED by a valid signed compromise marking (tainted at/after its instant; history not preserved)".to_string(),
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
    // Per-evidence status derives from withdrawals, compromise markings, and
    // the backing attestation's lifecycle when that attestation is verified
    // in this proof. `attestation_ref` is a provenance hint, never a validity
    // input: a backing that is present-but-bad fails (disproven), while a
    // backing that is absent (dangling, or left behind by renewal carrying
    // old evidence forward) is recorded UNKNOWN with validity preserved —
    // fail on disproof, note on absence. Strict policies adjudicate via
    // `evidence_usable`, which requires AVAILABLE.
    let node_ids: Vec<String> = event_ids
        .iter()
        .chain(att_ids.iter())
        .chain(evd_ids.iter())
        .cloned()
        .collect();
    let node_set = NodeSet::new(node_ids);
    // Lifecycle key: lifecycle objects are "att:<full-id>".
    let lifecycle_by_att: HashMap<&str, LifecycleStatus> = lifecycle
        .iter()
        .filter_map(|l| l.object.strip_prefix("att:").map(|id| (id, l.status)))
        .collect();
    let mut evidence_status: Vec<EvidenceStatusRecord> = vec![];
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
    // Evidence lifecycle derivation. Precedence: COMPROMISED > WITHDRAWN >
    // REVOKED > SUPERSEDED > EXPIRED > UNKNOWN > AVAILABLE. Withdrawn,
    // compromised, revoked, and unknown states fail (flip evidence validity);
    // superseded preserves history and expired mirrors the attestation-level
    // convention (ok record carrying the code).
    for (ev, eid) in proof.evidence.iter().zip(evd_ids.iter()) {
        let obj = format!("evd:{eid}");
        let withdrawn = applies
            .iter()
            .any(|(t, k)| t == eid && *k == ClaimKind::Withdraw);
        let marked = compromises.iter().any(|(t, _)| t == eid);
        let backing = ev
            .attestation_ref
            .as_deref()
            .and_then(|aref| lifecycle_by_att.get(aref).copied());
        let (status, code, ok, msg) = if marked {
            (
                EvidenceStatus::Compromised,
                Some(ErrorCode::Compromised),
                false,
                "evidence tainted by a valid signed compromise marking".to_string(),
            )
        } else if withdrawn {
            (
                EvidenceStatus::Withdrawn,
                Some(ErrorCode::Withdrawn),
                false,
                "evidence covered by a valid signed withdrawal (history preserved)".to_string(),
            )
        } else {
            match backing {
                Some(LifecycleStatus::Compromised) => (
                    EvidenceStatus::Compromised,
                    Some(ErrorCode::Compromised),
                    false,
                    "backing attestation COMPROMISED".to_string(),
                ),
                Some(LifecycleStatus::Revoked) => (
                    EvidenceStatus::Revoked,
                    Some(ErrorCode::Revoked),
                    false,
                    "backing attestation REVOKED".to_string(),
                ),
                Some(LifecycleStatus::Superseded) => (
                    EvidenceStatus::Superseded,
                    None,
                    true,
                    "backing attestation SUPERSEDED — historical record preserved".to_string(),
                ),
                Some(LifecycleStatus::Expired) => (
                    EvidenceStatus::Expired,
                    Some(ErrorCode::Expired),
                    true,
                    "backing attestation EXPIRED".to_string(),
                ),
                Some(LifecycleStatus::Unknown) => (
                    EvidenceStatus::Unknown,
                    Some(ErrorCode::RevocationUnknown),
                    false,
                    "backing attestation state UNKNOWN — fail closed".to_string(),
                ),
                Some(LifecycleStatus::Active) => (
                    EvidenceStatus::Available,
                    None,
                    true,
                    "evidence digest-bound and available".to_string(),
                ),
                None if ev.attestation_ref.is_none() => (
                    EvidenceStatus::Available,
                    None,
                    true,
                    "evidence digest-bound and available".to_string(),
                ),
                // Backing attestation not verified in this proof (dangling or
                // left behind, e.g. renewal carrying old evidence forward).
                // `attestation_ref` is a provenance hint, never a validity
                // input: nothing is disproven, so validity is preserved and
                // the gap is recorded UNKNOWN for auditors and policy
                // (`evidence_usable` stays strict). Spoofed hints are visible
                // here; digest binding still holds.
                _ => (
                    EvidenceStatus::Unknown,
                    Some(ErrorCode::RevocationUnknown),
                    true,
                    "backing attestation not verified in this proof — provenance hint unverified, validity preserved".to_string(),
                ),
            }
        };
        if ok {
            checks.push(CheckRecord::ok("EVIDENCE", obj.clone(), msg.clone()));
        } else {
            checks.push(CheckRecord::fail(
                "EVIDENCE",
                obj.clone(),
                code.unwrap_or(ErrorCode::RevocationUnknown),
                msg.clone(),
            ));
            evidence_bad = true;
        }
        evidence_status.push(EvidenceStatusRecord {
            object: obj,
            status,
            code,
            message: msg,
        });
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
    let extra_set: Option<HashSet<String>> = if ctx.extra_grounded.is_empty() {
        None
    } else {
        Some(ctx.extra_grounded.iter().cloned().collect())
    };
    match validate_graph_with_grounding(&edges, &node_set, &ctx.limits, extra_set.as_ref()) {
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
            // Provenance DAG profile (V1.1 F4, opt-in): REFERENCES and other
            // derivation edges must additionally be acyclic. Off by default
            // (V1 linkage semantics); enable via
            // `VerifyCtx::require_acyclic_provenance` / `--require-acyclic`.
            if ctx.require_acyclic_provenance {
                match proof_graph::check_acyclic_provenance(&edges, &node_set) {
                    Ok(()) => checks.push(CheckRecord::ok(
                        "GRAPH",
                        format!("proof:{stored_id}"),
                        "provenance DAG profile: no cycles (opt-in)",
                    )),
                    Err(e) => checks.push(CheckRecord::fail(
                        "GRAPH",
                        format!("proof:{stored_id}"),
                        e.code,
                        e.message,
                    )),
                }
            }
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

    // ---- Composition linkage (SPEC §7) ----
    // References are validated as topology (shape/sorted/bound/self) and
    // reported as an availability note. Referenced content is never embedded,
    // never fetched, and contributes nothing to validity: every reference is
    // REFERENCED (digest-named via its id, content withheld), never VERIFIED.
    // A bundle layer may resolve these ids against sibling proofs; the core
    // only guarantees the linkage itself is tamper-evident (bound in proof_id).
    if !proof.referenced_proofs.is_empty() {
        let mut refs_ok = true;
        if proof.referenced_proofs.len() > ctx.limits.max_referenced_proofs {
            checks.push(CheckRecord::fail(
                "GRAPH",
                format!("proof:{stored_id}"),
                ErrorCode::LimitExceeded,
                format!(
                    "referenced proofs {} > max_referenced_proofs {}",
                    proof.referenced_proofs.len(),
                    ctx.limits.max_referenced_proofs
                ),
            ));
            refs_ok = false;
        }
        let mut sorted = proof.referenced_proofs.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != proof.referenced_proofs.len() || sorted != proof.referenced_proofs {
            checks.push(CheckRecord::fail(
                "GRAPH",
                format!("proof:{stored_id}"),
                ErrorCode::SchemaViolation,
                "referenced_proofs must be sorted ascending with no duplicates",
            ));
            refs_ok = false;
        }
        for r in &proof.referenced_proofs {
            if let Err(e) = check_proof_ref_shape(r) {
                checks.push(CheckRecord::fail(
                    "GRAPH",
                    format!("proof:{stored_id}"),
                    e.code,
                    e.message,
                ));
                refs_ok = false;
                break;
            }
            if *r == stored_id {
                checks.push(CheckRecord::fail(
                    "GRAPH",
                    format!("proof:{stored_id}"),
                    ErrorCode::CycleDetected,
                    "proof cannot reference itself",
                ));
                refs_ok = false;
                break;
            }
        }
        if refs_ok {
            checks.push(CheckRecord::note(
                "GRAPH",
                format!("proof:{stored_id}"),
                format!(
                    "{} referenced proof(s) REFERENCED — linkage only, content not embedded, contributes nothing to validity",
                    proof.referenced_proofs.len()
                ),
            ));
        }
    }

    // ---- Divergence representation (SPEC §17) ----
    // Three opposition shapes, one rule: record, never arbitrate. Validity is
    // unchanged in every case; policy adjudicates (preferred issuer,
    // threshold, recency, corroboration, human decision).
    // 1. Divergent claims: same (claim.type, subject), differing fields.
    // 2. Denials: a verified statement carries `denies: <attestation-id>`
    //    targeting another verified statement. Unresolvable targets are
    //    external denials (noted with the target as stated, never failed):
    //    denying another system's claim is legitimate.
    // 3. Contradictions: a grounded CONTRADICTS edge between two verified
    //    statement attestations (third-party contradiction assertions).
    let conflicts: Vec<ConflictRecord> = {
        use std::collections::BTreeMap;
        // Verified statements by id, for opposition resolution.
        let statements: HashMap<&str, &AttestationContent> = verified
            .iter()
            .filter(|(_, c)| claim_kind(c) == ClaimKind::Statement)
            .map(|(id, c)| (id.as_str(), c))
            .collect();
        let mut out = vec![];
        let mut groups: BTreeMap<(String, String), Vec<(String, AttestationContent)>> =
            BTreeMap::new();
        for (att_id, content) in &verified {
            if claim_kind(content) != ClaimKind::Statement {
                continue;
            }
            groups
                .entry((content.claim.claim_type.clone(), content.subject.clone()))
                .or_default()
                .push((att_id.clone(), content.clone()));
        }
        for ((ctype, subject), members) in &groups {
            if members.len() < 2 {
                continue;
            }
            let first = &members[0].1.claim;
            if members.iter().all(|(_, c)| c.claim == *first) {
                continue; // corroboration, not divergence
            }
            let mut ids: Vec<String> = members.iter().map(|(id, _)| format!("att:{id}")).collect();
            ids.sort();
            out.push(ConflictRecord {
                kind: ConflictKind::DivergentClaims,
                claim_type: ctype.clone(),
                subject: subject.clone(),
                attestation_ids: ids,
            });
        }
        // Explicit denials and contradictions.
        let mut opposed: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for (att_id, content) in &verified {
            if claim_kind(content) != ClaimKind::Statement {
                continue;
            }
            if let Some(target) = denial_target(content) {
                // Resolvable targets anchor on the denied claim; external
                // targets anchor on (denying type, "external:<id>") and still
                // record the asserter as denial provenance.
                let (key, mut ids) = match statements.get(target) {
                    Some(denied) => (
                        (denied.claim.claim_type.clone(), denied.subject.clone()),
                        vec![format!("att:{att_id}"), format!("att:{target}")],
                    ),
                    None => (
                        (
                            content.claim.claim_type.clone(),
                            format!("external:{target}"),
                        ),
                        vec![format!("att:{att_id}")],
                    ),
                };
                ids.sort();
                ids.dedup();
                opposed.entry(key).or_default().extend(ids);
            }
        }
        for edge in proof
            .relationships
            .iter()
            .filter(|r| r.rel_type.as_str() == proof_core::model::RelType::CONTRADICTS)
        {
            let from_ok = statements.contains_key(edge.from.as_str());
            let to_ok = statements.contains_key(edge.to.as_str());
            if from_ok && to_ok {
                let denied = &statements[edge.to.as_str()];
                let mut ids = vec![format!("att:{}", edge.from), format!("att:{}", edge.to)];
                ids.sort();
                ids.dedup();
                out.push(ConflictRecord {
                    kind: ConflictKind::Contradiction,
                    claim_type: denied.claim.claim_type.clone(),
                    subject: denied.subject.clone(),
                    attestation_ids: ids,
                });
            } else {
                // Grounded but not between two verified statements: the
                // assertion is kept (graph-valid) but records no conflict —
                // contradiction needs two verified claims to oppose.
                checks.push(CheckRecord::note(
                    "EVIDENCE",
                    format!("proof:{stored_id}"),
                    "CONTRADICTS edge does not connect two verified statements — no conflict recorded",
                ));
            }
        }
        for ((ctype, subject), mut ids) in opposed {
            ids.sort();
            ids.dedup();
            out.push(ConflictRecord {
                kind: ConflictKind::Denial,
                claim_type: ctype,
                subject,
                attestation_ids: ids,
            });
        }
        out.sort_by(|a, b| {
            (
                a.kind.as_str(),
                &a.claim_type,
                &a.subject,
                &a.attestation_ids,
            )
                .cmp(&(
                    b.kind.as_str(),
                    &b.claim_type,
                    &b.subject,
                    &b.attestation_ids,
                ))
        });
        out
    };
    for c in &conflicts {
        checks.push(CheckRecord::note(
            "EVIDENCE",
            format!("proof:{stored_id}"),
            format!(
                "conflicting evidence [{}]: claim `{}` about `{}` opposed across {} attestation(s) ({}) — representation only, policy adjudicates",
                c.kind.as_str(),
                c.claim_type,
                c.subject,
                c.attestation_ids.len(),
                c.attestation_ids.join(", ")
            ),
        ));
    }

    let mut report = finalize(
        Some(stored_id),
        checks,
        Some(policy_note()),
        lifecycle,
        status_objects,
        withdrawn.clone(),
        proof.referenced_proofs.clone(),
        proof.vocabularies.clone(),
        evidence_status,
        conflicts,
        true,
    );
    // Non-canonical bytes must never yield valid evidence, even in
    // fail-collect mode where later stages also ran for diagnostics.
    if canonical_failed {
        report.evidence_validity = Validity::Invalid;
    }
    Ok(report)
}

fn policy_note() -> CheckRecord {
    CheckRecord::note(
        "POLICY",
        "policy:caller",
        "policy decision is made by the caller via proof-policy::evaluate_policy; the pipeline reports INDETERMINATE (never PASS by default)",
    )
}
