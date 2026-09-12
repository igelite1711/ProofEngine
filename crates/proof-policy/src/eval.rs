// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic policy evaluator (implicit AND). Pure function of
//! (state, policy, explicit trust inputs) — no I/O, no crypto, no AI.
// PE-TRUST-005: trusted_issuers is caller input; constrain it by evaluation
// time for key-rotation semantics (TRUST.md "Key lifetime").
// PE-NEUT-002: broken cryptographic/evidence preconditions short-circuit to
// INDETERMINATE here — PASS is only ever produced by satisfied requirements,
// never by signature validity alone (valid ≠ trusted ≠ accepted).

use crate::policy::{Policy, Requirement};
use crate::state::VerifiedState;
use proof_core::model::RelType;
use proof_verify::PolicyDecision;
use std::collections::{HashMap, HashSet, VecDeque};

/// Caller-supplied revocation data. V0.1 semantics: an id present here is
/// revoked; anything else is "no revocation known" (NOT "fresh"). Freshness
/// windows and transparency-anchored status land in Phase 6.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    pub revoked: HashSet<String>,
}

impl RevocationSet {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            revoked: ids.into_iter().collect(),
        }
    }
}

/// Explicit trust inputs. `verified_at` must be a trustworthy clock reading;
/// `skew_leeway` (default 300s) absorbs honest clock drift only.
///
/// CALLER CONTRACT (DoS prevention): keep `trusted_issuers` within
/// `Limits::max_trusted_issuers` (32) and `revocations.revoked` small.
/// `evaluate_policy` itself is a pure function with no limits handle, so
/// direct callers enforce the bound; the one-shot `verify_and_evaluate`
/// enforces it for you and fails closed with `LIMIT_EXCEEDED` otherwise.
#[derive(Debug, Clone)]
pub struct EvalInputs {
    pub trusted_issuers: Vec<String>,
    pub revocations: RevocationSet,
    pub verified_at: u64,
    pub skew_leeway: u64,
}

impl Default for EvalInputs {
    fn default() -> Self {
        Self {
            trusted_issuers: vec![],
            revocations: RevocationSet::empty(),
            // Zero clock fails time requirements until the caller supplies a
            // real one — fail-closed default.
            verified_at: 0,
            skew_leeway: 300,
        }
    }
}

/// Thin projection from the single normative `VerificationContext`
/// (AUDIT F6). Clock + trust list project directly; the policy-side unsigned
/// `revocations` set has no counterpart in the signed pipeline inputs, so it
/// starts empty and the caller supplies it separately (see
/// `verify_and_evaluate`, which pairs both layers from one context).
impl From<&proof_verify::VerificationContext> for EvalInputs {
    fn from(ctx: &proof_verify::VerificationContext) -> Self {
        Self {
            trusted_issuers: ctx.trusted_issuers.clone(),
            revocations: RevocationSet::empty(),
            verified_at: ctx.verified_at,
            skew_leeway: ctx.clock_skew_leeway,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequirementResult {
    pub requirement: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    pub policy_id: String,
    pub decision: PolicyDecision,
    /// Why, when the decision is INDETERMINATE (proof-side failure).
    pub note: Option<String>,
    pub results: Vec<RequirementResult>,
}

fn pass(req: &str, message: impl Into<String>) -> RequirementResult {
    RequirementResult {
        requirement: req.into(),
        passed: true,
        message: message.into(),
    }
}

fn fail(req: &str, message: impl Into<String>) -> RequirementResult {
    RequirementResult {
        requirement: req.into(),
        passed: false,
        message: message.into(),
    }
}

/// Evaluate a validated policy against verified state. Deterministic: same
/// inputs always yield the same outcome.
pub fn evaluate_policy(
    state: &VerifiedState,
    policy: &Policy,
    inputs: &EvalInputs,
) -> PolicyOutcome {
    // Broken evidence makes policy evaluation meaningless — and must never
    // degrade into PASS. INDETERMINATE, not FAIL: the policy wasn't refuted,
    // its preconditions weren't met.
    // PE-NEUT-002: verification, trust, and policy verdicts stay distinct —
    // a broken proof is a precondition failure, never a domain opinion.
    if !state.crypto_valid || !state.evidence_valid {
        return PolicyOutcome {
            policy_id: policy.id.clone(),
            decision: PolicyDecision::Indeterminate,
            note: Some(format!(
                "proof not valid (crypto={}, evidence={}); policy not evaluated",
                onoff(state.crypto_valid),
                onoff(state.evidence_valid)
            )),
            results: vec![],
        };
    }
    let mut results = Vec::with_capacity(policy.requirements.len());
    if policy.version == 2 {
        // V2 expression tree over leaves (boolean once the guard above
        // passes; INDETERMINATE stays reserved for unevaluated policy).
        // Every leaf evaluates (no short-circuit skips) so explanations are
        // complete, exactly like the v1 loop below.
        match &policy.expression {
            Some(expr) => {
                let passed = eval_expr(expr, state, inputs, &mut results);
                let decision = if passed {
                    PolicyDecision::Pass
                } else {
                    PolicyDecision::Fail
                };
                return PolicyOutcome {
                    policy_id: policy.id.clone(),
                    decision,
                    note: None,
                    results,
                };
            }
            // Hand-built Policy without an expression: fail closed, never guess.
            None => {
                return PolicyOutcome {
                    policy_id: policy.id.clone(),
                    decision: PolicyDecision::Indeterminate,
                    note: Some("v2 policy without expression; policy not evaluated".into()),
                    results: vec![],
                };
            }
        }
    }
    for req in &policy.requirements {
        results.push(eval_one(req, state, inputs));
    }
    let decision = if results.iter().all(|r| r.passed) {
        PolicyDecision::Pass
    } else {
        PolicyDecision::Fail
    };
    PolicyOutcome {
        policy_id: policy.id.clone(),
        decision,
        note: None,
        results,
    }
}

/// Evaluate a v2 expression tree. Returns the boolean outcome and pushes one
/// flat leaf result per evaluated leaf (pre-order), so explanations and the
/// `results` contract match v1 shape.
fn eval_expr(
    expr: &crate::expr::PolicyExpr,
    state: &VerifiedState,
    inputs: &EvalInputs,
    results: &mut Vec<RequirementResult>,
) -> bool {
    use crate::expr::PolicyExpr;
    match expr {
        PolicyExpr::Leaf(req) => {
            let res = eval_one(req, state, inputs);
            let passed = res.passed;
            results.push(res);
            passed
        }
        PolicyExpr::All(cs) => {
            let mut ok = true;
            for c in cs {
                ok = eval_expr(c, state, inputs, results) && ok;
            }
            ok
        }
        PolicyExpr::Any(cs) => {
            let mut ok = false;
            for c in cs {
                ok = eval_expr(c, state, inputs, results) || ok;
            }
            ok
        }
        PolicyExpr::Not(c) => !eval_expr(c, state, inputs, results),
        PolicyExpr::Threshold { k, options } => {
            // Every option evaluates (complete explanations); passes counted.
            let mut count = 0;
            for c in options {
                if eval_expr(c, state, inputs, results) {
                    count += 1;
                }
            }
            count >= *k
        }
    }
}

fn onoff(b: bool) -> &'static str {
    if b {
        "valid"
    } else {
        "invalid"
    }
}

/// PE-POLICY-001..008 dispatch (PE-POLICY-009 gate above in evaluate_policy).
fn eval_one(req: &Requirement, state: &VerifiedState, inputs: &EvalInputs) -> RequirementResult {
    let name = req.describe();
    match req {
        // PE-POLICY-001
        Requirement::SignatureValid => pass(
            &name,
            "pipeline established cryptographic validity for this proof",
        ),
        // PE-POLICY-002 · PE-TRUST-001 · PE-NEUT-002 (valid signature and
        // trusted issuer are never conflated: both the trust list AND a
        // signature-verified attestation are required).
        Requirement::IssuerTrusted { issuer } => {
            let listed = inputs.trusted_issuers.iter().any(|t| t == issuer);
            let present = state.verified_issuers.iter().any(|i| i == issuer);
            match (listed, present) {
                (true, true) => pass(&name, format!("issuer {issuer} verified and trusted")),
                (false, _) => fail(&name, format!("issuer {issuer} not in trust list")),
                (true, false) => fail(
                    &name,
                    format!("trusted issuer {issuer} has no verified attestation here"),
                ),
            }
        }
        // PE-POLICY-003
        Requirement::IssuerExcluded { issuer } => {
            if state.verified_issuers.iter().any(|i| i == issuer) {
                fail(
                    &name,
                    format!("excluded issuer {issuer} has a verified attestation in this proof"),
                )
            } else {
                pass(
                    &name,
                    format!("excluded issuer {issuer} absent from this proof"),
                )
            }
        }
        Requirement::RelationshipExists { relationship } => {
            if state.rel_types.contains(relationship) {
                pass(
                    &name,
                    format!("edge {} present in validated graph", relationship.as_str()),
                )
            } else {
                fail(
                    &name,
                    format!("no {} edge in validated graph", relationship.as_str()),
                )
            }
        }
        // PE-POLICY-004
        Requirement::NotExpired => {
            for (id, (issued, expires)) in state
                .attestation_ids
                .iter()
                .zip(state.attestation_times.iter())
            {
                if *issued > inputs.verified_at.saturating_add(inputs.skew_leeway) {
                    return fail(
                        &name,
                        format!("attestation {id} issued in the future relative to verifier clock"),
                    );
                }
                if let Some(exp) = expires {
                    if inputs.verified_at > exp.saturating_add(inputs.skew_leeway) {
                        return fail(&name, format!("attestation {id} expired"));
                    }
                }
                // expires_at == None: no bounded validity to violate (a policy
                // needing mandatory expiry wants a future requirement type).
            }
            pass(
                &name,
                format!(
                    "{} attestation(s) within validity at {}",
                    state.attestation_ids.len(),
                    inputs.verified_at
                ),
            )
        }
        // PE-POLICY-005
        Requirement::NotRevoked => {
            for id in &state.attestation_ids {
                if inputs.revocations.revoked.contains(id) {
                    return fail(&name, format!("attestation {id} revoked"));
                }
            }
            pass(
                &name,
                format!(
                    "no known revocation among {} attestation(s)",
                    state.attestation_ids.len()
                ),
            )
        }
        // PE-POLICY-006
        Requirement::NotSuperseded => {
            if state.superseded_ids.is_empty() {
                pass(&name, "no attestation in this proof is superseded")
            } else {
                fail(
                    &name,
                    format!(
                        "superseded attestation(s) present: {}",
                        state.superseded_ids.join(", ")
                    ),
                )
            }
        }
        // PE-POLICY-007
        Requirement::EvidencePresent { kind } => {
            if state.evidence_kinds.contains(kind) {
                pass(&name, format!("evidence {} present", kind.as_str()))
            } else {
                fail(&name, format!("evidence {} missing", kind.as_str()))
            }
        }
        // PE-POLICY-007
        Requirement::TransparencyPresent => {
            if state.has_transparency() {
                pass(&name, "transparency_receipt present")
            } else {
                fail(&name, "no transparency_receipt in proof")
            }
        }
        // V1.1: Proof freshness (replay protection)
        // Advisory only: `created_at` is unauthenticated (see
        // `Requirement::ProofFresh`). The qualifier travels in the message so
        // explanations never oversell this check.
        Requirement::ProofFresh { max_age_seconds } => {
            // Zero clock = no trustworthy time: fail closed like TIME and
            // NotExpired do. Otherwise age saturates to 0 and any max_age
            // would PASS without any time anchor (replay-guard bypass).
            if inputs.verified_at == 0 {
                return fail(&name, "no trustworthy verifier clock (verified_at=0)");
            }
            let age = inputs.verified_at.saturating_sub(state.proof_created_at);
            if age <= *max_age_seconds {
                pass(&name, format!("proof age {age}s <= {max_age_seconds}s (created_at unauthenticated — advisory)"))
            } else {
                fail(&name, format!("proof too old: {age}s > {max_age_seconds}s"))
            }
        }
        // ---- V2 adjudication leaves (reachable only via policy_version 2;
        // v1 parsing rejects these names, so v1 verdicts cannot drift). ----
        Requirement::DelegatedAuthority {
            root,
            issuer,
            scope,
        } => {
            if !inputs.trusted_issuers.iter().any(|t| t == root) {
                return fail(&name, format!("delegation root {root} not in trust list"));
            }
            if !state.verified_issuers.iter().any(|i| i == issuer) {
                return fail(
                    &name,
                    format!("issuer {issuer} has no verified attestation here"),
                );
            }
            match delegation_chain(state, root, issuer, scope.as_deref()) {
                Some(chain) => pass(
                    &name,
                    format!(
                        "issuer {issuer} authorized by {root} via {} active link(s){}",
                        chain.len().saturating_sub(1),
                        match scope {
                            None => String::new(),
                            Some(sc) => format!(" (scope {sc})"),
                        }
                    ),
                ),
                None => fail(
                    &name,
                    format!("no active delegation chain from {root} to {issuer}"),
                ),
            }
        }
        Requirement::IdentityBound { a, b } => match identity_path(state, inputs, a, b) {
            Some(path) => pass(
                &name,
                format!(
                    "{a} ≡ {b} via {} trusted binding(s)",
                    path.len().saturating_sub(1)
                ),
            ),
            None => fail(
                &name,
                format!("no trusted identity path between {a} and {b}"),
            ),
        },
        Requirement::TransparencyInclusion { log } => match transparency_binding(state, log) {
            Some(detail) => pass(&name, detail),
            None => fail(
                &name,
                format!("no receipt bound to a currently-valid checkpoint by {log}"),
            ),
        },
        Requirement::NoConflictingEvidence => {
            if state.conflicts.is_empty() {
                pass(&name, "no conflicts recorded")
            } else {
                fail(
                    &name,
                    format!(
                        "{} conflicting group(s) recorded — adjudication required",
                        state.conflicts.len()
                    ),
                )
            }
        }
        Requirement::VocabularyAccepted { ns, max_version } => {
            let over: Vec<u64> = state
                .vocabularies_declared
                .iter()
                .filter(|vd| &vd.ns == ns)
                .map(|vd| vd.version)
                .collect();
            if over.iter().any(|v| v > max_version) {
                return fail(
                    &name,
                    format!("vocabulary `{ns}` declared above accepted max {max_version}"),
                );
            }
            if state.vocabularies_used.iter().any(|u| u == ns)
                && !over.iter().any(|v| v <= max_version)
            {
                return fail(
                    &name,
                    format!(
                        "vocabulary `{ns}` used but not declared within accepted max {max_version}"
                    ),
                );
            }
            pass(
                &name,
                format!("vocabulary `{ns}` within accepted max {max_version}"),
            )
        }
        Requirement::EvidenceUsable { kind } => {
            if state.evidence_statuses.iter().any(|e| {
                &e.kind == kind && e.status == proof_core::model::EvidenceStatus::Available
            }) {
                pass(
                    &name,
                    format!("evidence {} usable (AVAILABLE)", kind.as_str()),
                )
            } else {
                fail(
                    &name,
                    format!(
                        "no AVAILABLE evidence of kind {} (present-but-unusable is not enough)",
                        kind.as_str()
                    ),
                )
            }
        }
        Requirement::RequiresReference { id } => {
            if state.referenced_proofs.iter().any(|r| r == id) {
                pass(&name, format!("composition linkage names {id}"))
            } else {
                fail(&name, format!("composition linkage does not name {id}"))
            }
        }
        Requirement::ForbidsReference { id } => {
            if state.referenced_proofs.iter().any(|r| r == id) {
                fail(&name, format!("composition linkage names forbidden {id}"))
            } else {
                pass(&name, format!("composition linkage omits {id}"))
            }
        }
    }
}

/// Resolve an active delegation chain from `root` to `target` over verified
/// `delegate` grants whose link attestations are lifecycle-ACTIVE.
/// Returns the issuer chain (root first) or `None`. Cycle-safe (visited set);
/// bounded by delegation count (no separate depth limit needed). When `scope`
/// is set, every traversed link must carry that exact scope string — scope is
/// otherwise opaque to the core and ignored.
fn delegation_chain(
    state: &VerifiedState,
    root: &str,
    target: &str,
    scope: Option<&str>,
) -> Option<Vec<String>> {
    if target == root {
        return Some(vec![root.to_string()]);
    }
    let active: HashSet<&str> = state
        .active_attestation_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    // Adjacency over active, scope-matching links only.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for d in &state.delegations {
        if !active.contains(d.attestation_id.as_str()) {
            continue;
        }
        if let Some(required) = scope {
            if d.scope.as_deref() != Some(required) {
                continue;
            }
        }
        adj.entry(d.delegator.as_str())
            .or_default()
            .push(d.delegatee.as_str());
    }
    let mut prev: HashMap<&str, &str> = HashMap::new();
    let mut seen: HashSet<&str> = HashSet::from([root]);
    let mut queue: VecDeque<&str> = VecDeque::from([root]);
    while let Some(cur) = queue.pop_front() {
        if cur == target {
            let mut chain = vec![target.to_string()];
            let mut at = target;
            while at != root {
                let p = prev.get(at).copied().unwrap_or(root);
                chain.push(p.to_string());
                at = p;
            }
            chain.reverse();
            return Some(chain);
        }
        if let Some(nexts) = adj.get(cur) {
            for n in nexts {
                if seen.insert(n) {
                    prev.insert(n, cur);
                    queue.push_back(n);
                }
            }
        }
    }
    None
}

/// Undirected adjacency insert for verifier-scoped graph search.
fn link_edge<'a>(adj: &mut HashMap<&'a str, Vec<&'a str>>, x: &'a str, y: &'a str) {
    adj.entry(x).or_default().push(y);
    adj.entry(y).or_default().push(x);
}

/// Verifier-scoped identity path between `a` and `b` over bindings asserted
/// by trust-listed parties: `identity.bind` attestations plus grounded
/// EQUIVALENT relationship edges with a verified, trusted attester.
/// Only lifecycle-ACTIVE assertions count: expired, revoked, superseded, or
/// compromised bindings/edges merge nothing (fail closed on stale identity).
/// Undirected, cycle-safe, reflexive (`a == b` passes). The core never merges
/// globally — this answers one verifier's question under its trust list.
fn identity_path(
    state: &VerifiedState,
    inputs: &EvalInputs,
    a: &str,
    b: &str,
) -> Option<Vec<String>> {
    if a == b {
        return Some(vec![a.to_string()]);
    }
    let trusted_list = &inputs.trusted_issuers;
    let trusted = |issuer: &str| trusted_list.iter().any(|t| t == issuer);
    let active: HashSet<&str> = state
        .active_attestation_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for binding in &state.identity_bindings {
        if trusted(&binding.asserter) && active.contains(binding.attestation_id.as_str()) {
            link_edge(
                &mut adj,
                binding.subject.as_str(),
                binding.equivalent.as_str(),
            );
        }
    }
    for edge in &state.edges {
        if edge.rel_type.as_str() != RelType::EQUIVALENT {
            continue;
        }
        // Backed by a verified, trusted, ACTIVE attestation — all three, or
        // the edge carries no identity authority.
        let live = edge.attestation.as_deref().is_some_and(|aref| {
            active.contains(aref)
                && edge
                    .attester
                    .as_deref()
                    .is_some_and(|t| trusted_list.iter().any(|x| x.as_str() == t))
        });
        if live {
            link_edge(&mut adj, edge.from.as_str(), edge.to.as_str())
        }
    }
    let mut prev: HashMap<&str, &str> = HashMap::new();
    let mut seen: HashSet<&str> = HashSet::from([a]);
    let mut queue: VecDeque<&str> = VecDeque::from([a]);
    while let Some(cur) = queue.pop_front() {
        if cur == b {
            let mut path = vec![b.to_string()];
            let mut at = b;
            while at != a {
                let p = prev.get(at).copied().unwrap_or(a);
                path.push(p.to_string());
                at = p;
            }
            path.reverse();
            return Some(path);
        }
        if let Some(nexts) = adj.get(cur) {
            for n in nexts {
                if seen.insert(n) {
                    prev.insert(n, cur);
                    queue.push_back(n);
                }
            }
        }
    }
    None
}

/// Transparency inclusion: a `transparency_receipt` evidence item bound
/// (`attestation_ref`) to a currently-ACTIVE `transparency.checkpoint`
/// attestation issued by `log`. Registration/inclusion cryptography beneath
/// (Merkle proofs, consistency) verifies in adapters against the receipt
/// digest; the core checks presence, binding, issuer, and checkpoint
/// freshness (validity window), which is the portable, offline-verifiable
/// part of the SCITT-style model.
fn transparency_binding(state: &VerifiedState, log: &str) -> Option<String> {
    use proof_core::model::EvidenceKind;
    let active: std::collections::HashSet<&str> = state
        .active_attestation_ids
        .iter()
        .map(|s| s.as_str())
        .collect();
    // Checkpoint attestations by this log that are currently valid.
    let checkpoints: Vec<&str> = state
        .claims
        .iter()
        .filter(|c| {
            c.claim_type == proof_crypto::claim::CLAIM_TRANSPARENCY_CHECKPOINT
                && c.issuer == log
                && active.contains(c.attestation_id.as_str())
        })
        .map(|c| c.attestation_id.as_str())
        .collect();
    if checkpoints.is_empty() {
        return None;
    }
    // A receipt bound to one of those checkpoints completes inclusion.
    for entry in &state.evidence_statuses {
        if entry.kind.as_str() != EvidenceKind::TRANSPARENCY_RECEIPT {
            continue;
        }
        if let Some(aref) = entry.attestation_ref.as_deref() {
            if checkpoints.contains(&aref) {
                return Some(format!(
                    "transparency receipt {} bound to active checkpoint by {log}",
                    entry.id
                ));
            }
        }
    }
    None
}
