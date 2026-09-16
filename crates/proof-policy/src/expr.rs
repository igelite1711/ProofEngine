// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Policy v2 expressions (`policy_version: 2`): boolean connectives and
//! thresholds over requirement leaves, including the nine V2 adjudication
//! leaves (delegation, identity, transparency, conflict, vocabulary,
//! usability, composition refs, claim-field predicates). V1 (`requirements`
//! implicit AND over the ten frozen leaves) is untouched and parses
//! byte-identically.
//!
//! Semantics are boolean over evaluated leaves with INDETERMINATE reserved
//! for unevaluated policy (broken proof preconditions, exactly like v1):
//! leaves never evaluate to indeterminate once the guard passes, so `all`
//! fails on any failing leaf, `any` passes on any passing leaf, `not`
//! inverts, and `threshold{k}` passes on ≥ k passing leaves. Deterministic,
//! no I/O, no code execution.

use proof_core::{ErrorCode, ProofError};

use crate::policy::{parse_requirement_v2_leaf, Requirement};

/// A v2 policy expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyExpr {
    Leaf(Requirement),
    All(Vec<PolicyExpr>),
    Any(Vec<PolicyExpr>),
    Not(Box<PolicyExpr>),
    Threshold { k: usize, options: Vec<PolicyExpr> },
}

impl PolicyExpr {
    /// Stable rendering for results and explanations.
    pub fn describe(&self) -> String {
        match self {
            Self::Leaf(r) => r.describe(),
            Self::All(cs) => {
                format!(
                    "all[{}]",
                    cs.iter()
                        .map(|c| c.describe())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Self::Any(cs) => {
                format!(
                    "any[{}]",
                    cs.iter()
                        .map(|c| c.describe())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
            Self::Not(c) => format!("not({})", c.describe()),
            Self::Threshold { k, options } => format!(
                "threshold({}/{})[{}]",
                k,
                options.len(),
                options
                    .iter()
                    .map(|c| c.describe())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Total node count (leaves + connectives), bounded at parse time.
    pub fn node_count(&self) -> usize {
        match self {
            Self::Leaf(_) => 1,
            Self::All(cs) | Self::Any(cs) => 1 + cs.iter().map(|c| c.node_count()).sum::<usize>(),
            Self::Not(c) => 1 + c.node_count(),
            Self::Threshold { options, .. } => {
                1 + options.iter().map(|c| c.node_count()).sum::<usize>()
            }
        }
    }
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

/// Parse a v2 expression with a remaining node budget (DoS prevention: deep
/// or wide trees fail closed with LIMIT_EXCEEDED, never stack-exhaust).
pub fn parse_expression(
    v: &serde_json::Value,
    what: &str,
    budget: &mut usize,
) -> Result<PolicyExpr, ProofError> {
    if *budget == 0 {
        return Err(ErrorCode::LimitExceeded.err(format!("{what}: policy expression too large")));
    }
    *budget -= 1;
    let obj = v
        .as_object()
        .ok_or_else(|| ErrorCode::PolicyInvalid.err(format!("{what} must be an object")))?;
    if obj.contains_key("type") {
        // Leaf: requirement shape validated by the shared leaf parser, which
        // rejects connective keys as unknown fields.
        return Ok(PolicyExpr::Leaf(parse_requirement_v2_leaf(obj, what)?));
    }
    let mut kinds = ["all", "any", "not", "threshold"]
        .into_iter()
        .filter(|k| obj.contains_key(*k));
    let kind = kinds.next().ok_or_else(|| {
        ErrorCode::PolicyInvalid.err(format!(
            "{what}: expected one of all|any|not|threshold or a requirement leaf"
        ))
    })?;
    if kinds.next().is_some() {
        return Err(ErrorCode::PolicyInvalid.err(format!(
            "{what}: exactly one connective per expression object"
        )));
    }
    match kind {
        "all" | "any" => {
            reject_extra_keys(obj, &[kind], what)?;
            let items = obj[kind].as_array().ok_or_else(|| {
                ErrorCode::PolicyInvalid.err(format!("{what}: {kind} must be an array"))
            })?;
            if items.is_empty() {
                // Vacuous truth (`all[]`) would PASS everything and vacuous
                // `any[]` can never pass: refuse both, like v1 empty lists.
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: {kind} must not be empty"))
                );
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                out.push(parse_expression(
                    item,
                    &format!("{what}.{kind}[{i}]"),
                    budget,
                )?);
            }
            Ok(if kind == "all" {
                PolicyExpr::All(out)
            } else {
                PolicyExpr::Any(out)
            })
        }
        "not" => {
            reject_extra_keys(obj, &["not"], what)?;
            Ok(PolicyExpr::Not(Box::new(parse_expression(
                &obj["not"],
                &format!("{what}.not"),
                budget,
            )?)))
        }
        "threshold" => {
            reject_extra_keys(obj, &["threshold"], what)?;
            let t = obj["threshold"].as_object().ok_or_else(|| {
                ErrorCode::PolicyInvalid.err(format!("{what}: threshold must be an object"))
            })?;
            reject_extra_keys(t, &["k", "of"], &format!("{what}.threshold"))?;
            let k = t.get("k").and_then(|n| n.as_u64()).ok_or_else(|| {
                ErrorCode::PolicyInvalid
                    .err(format!("{what}: threshold.k must be a positive integer"))
            })?;
            let options = t.get("of").and_then(|n| n.as_array()).ok_or_else(|| {
                ErrorCode::PolicyInvalid.err(format!("{what}: threshold.of must be an array"))
            })?;
            if options.is_empty() {
                return Err(
                    ErrorCode::PolicyInvalid.err(format!("{what}: threshold.of must not be empty"))
                );
            }
            if k == 0 || (k as usize) > options.len() {
                // k=0 is vacuous truth; k>n can never pass (likely a typo):
                // refuse both at parse time instead of shipping dead policy.
                return Err(ErrorCode::PolicyInvalid.err(format!(
                    "{what}: threshold.k must satisfy 1 <= k <= len(of) (got k={k}, n={})",
                    options.len()
                )));
            }
            let mut out = Vec::with_capacity(options.len());
            for (i, item) in options.iter().enumerate() {
                out.push(parse_expression(
                    item,
                    &format!("{what}.threshold.of[{i}]"),
                    budget,
                )?);
            }
            Ok(PolicyExpr::Threshold {
                k: k as usize,
                options: out,
            })
        }
        _ => Err(ErrorCode::PolicyInvalid.err(format!("{what}: unknown connective"))),
    }
}

/// Canonical CBOR for an expression (deterministic key order via encoder).
pub fn expression_to_cbor(expr: &PolicyExpr) -> proof_format::CborValue {
    use proof_format::CborValue;
    match expr {
        PolicyExpr::Leaf(r) => super::policy::requirement_to_cbor(r),
        PolicyExpr::All(cs) => CborValue::Map(vec![(
            CborValue::Text("all".into()),
            CborValue::Array(cs.iter().map(expression_to_cbor).collect()),
        )]),
        PolicyExpr::Any(cs) => CborValue::Map(vec![(
            CborValue::Text("any".into()),
            CborValue::Array(cs.iter().map(expression_to_cbor).collect()),
        )]),
        PolicyExpr::Not(c) => {
            CborValue::Map(vec![(CborValue::Text("not".into()), expression_to_cbor(c))])
        }
        PolicyExpr::Threshold { k, options } => CborValue::Map(vec![(
            CborValue::Text("threshold".into()),
            CborValue::Map(vec![
                (CborValue::Text("k".into()), CborValue::Uint(*k as u64)),
                (
                    CborValue::Text("of".into()),
                    CborValue::Array(options.iter().map(expression_to_cbor).collect()),
                ),
            ]),
        )]),
    }
}
