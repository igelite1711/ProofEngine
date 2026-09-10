// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! proof-graph: typed directed-graph validation over VERIFIED records.
//! This crate never touches bytes or signatures. Callers must verify artifact
//! ids (canonical form + schema + id binding) BEFORE constructing `EdgeRecord`s
//! — typically via `proof-crypto::build`. Topology checks here assume authentic inputs.

use proof_core::{
    model::{RelType, Relationship},
    ErrorCode, Limits, ProofError,
};
use std::collections::{HashMap, HashSet};

/// A relationship whose bytes have already been verified (id binding checked).
#[derive(Debug, Clone)]
pub struct EdgeRecord {
    pub content: Relationship,
    pub id: String,
}

impl EdgeRecord {
    /// Construct from already-verified parts. CALLER MUST have checked the id
    /// binding first (e.g. `proof-crypto::build::verify_relationship`); this
    /// constructor cannot tell a forged id from a real one.
    pub fn new(content: Relationship, id: String) -> Self {
        Self { content, id }
    }
}

/// All known artifact ids (events, attestations, evidence) that edges may reference.
#[derive(Debug, Clone, Default)]
pub struct NodeSet {
    ids: HashSet<String>,
}

impl NodeSet {
    pub fn new(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            ids: ids.into_iter().collect(),
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

/// Successful validation summary. The validated edge ids are returned so the
/// pipeline can prove exactly which edges passed (explanation support).
#[derive(Debug, Clone)]
pub struct ValidatedGraph {
    pub edge_ids: Vec<String>,
    pub node_count: usize,
    pub edge_count: usize,
    pub longest_supersedes_chain: usize,
}

/// Validate edge topology:
/// 1. counts within limits; 2. endpoints + refs resolve; 3. trust-relevant
///    edges grounded; 4. SUPERSEDES subgraph linear, acyclic, depth-bounded.
// PE-GRAPH-001 (grounding) · PE-GRAPH-002 (dangling) · PE-GRAPH-004 (limits).
pub fn validate_graph(
    edges: &[EdgeRecord],
    nodes: &NodeSet,
    limits: &Limits,
) -> Result<ValidatedGraph, ProofError> {
    if edges.len() > limits.max_edges {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "edges {} > max_edges {}",
            edges.len(),
            limits.max_edges
        )));
    }

    let mut endpoints: HashSet<&str> = HashSet::new();
    for e in edges {
        let r = &e.content;
        if r.v != 1 {
            return Err(ErrorCode::UnsupportedVersion.err("only relationship v=1 supported"));
        }
        if r.from.is_empty() || r.to.is_empty() {
            return Err(ErrorCode::DanglingReference.err("empty endpoint"));
        }
        if r.from == r.to {
            return Err(ErrorCode::SchemaViolation.err("self-edge forbidden"));
        }
        if !nodes.contains(&r.from) {
            return Err(ErrorCode::DanglingReference.err(format!("unknown from {}", r.from)));
        }
        if !nodes.contains(&r.to) {
            return Err(ErrorCode::DanglingReference.err(format!("unknown to {}", r.to)));
        }
        if r.rel_type.requires_grounding()
            && r.evidence_ref.is_none()
            && r.attestation_ref.is_none()
        {
            return Err(ErrorCode::RelationshipUngrounded.err(format!(
                "edge {} ({}) lacks backing evidence",
                e.id,
                r.rel_type.as_str()
            )));
        }
        for label in ["evidence_ref", "attestation_ref"] {
            let opt = if label == "evidence_ref" {
                &r.evidence_ref
            } else {
                &r.attestation_ref
            };
            if let Some(id) = opt {
                if id.is_empty() {
                    return Err(ErrorCode::SchemaViolation.err(format!("empty {label}")));
                }
                if !nodes.contains(id) {
                    return Err(ErrorCode::DanglingReference.err(format!("unknown {label} {id}")));
                }
            }
        }
        endpoints.insert(r.from.as_str());
        endpoints.insert(r.to.as_str());
    }
    if endpoints.len() > limits.max_nodes {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "nodes {} > max_nodes {}",
            endpoints.len(),
            limits.max_nodes
        )));
    }

    let longest = check_supersedes(edges, limits)?;

    Ok(ValidatedGraph {
        edge_ids: edges.iter().map(|e| e.id.clone()).collect(),
        node_count: endpoints.len(),
        edge_count: edges.len(),
        longest_supersedes_chain: longest,
    })
}

/// SUPERSEDES subgraph must be a set of linear chains: acyclic, indegree ≤ 1,
/// outdegree ≤ 1, longest chain ≤ max_depth. Iterative (no recursion on hostile input).
// PE-GRAPH-003 (SUPERSEDES acyclic/linear/depth-bounded).
fn check_supersedes(edges: &[EdgeRecord], limits: &Limits) -> Result<usize, ProofError> {
    let sup: Vec<(&str, &str)> = edges
        .iter()
        .filter(|e| e.content.rel_type.as_str() == RelType::SUPERSEDES)
        .map(|e| (e.content.from.as_str(), e.content.to.as_str()))
        .collect();
    if sup.is_empty() {
        return Ok(0);
    }
    let mut out_deg: HashMap<&str, usize> = HashMap::new();
    let mut in_deg: HashMap<&str, usize> = HashMap::new();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut nodes: HashSet<&str> = HashSet::new();
    for (a, b) in &sup {
        *out_deg.entry(a).or_insert(0) += 1;
        *in_deg.entry(b).or_insert(0) += 1;
        nodes.insert(a);
        nodes.insert(b);
        adj.entry(a).or_default().push(b);
    }
    for n in &nodes {
        if out_deg.get(n).copied().unwrap_or(0) > 1 || in_deg.get(n).copied().unwrap_or(0) > 1 {
            return Err(ErrorCode::SchemaViolation
                .err(format!("supersedes must be linear chains (branch at {n})")));
        }
    }
    // Kahn's algorithm: longest path + cycle detection.
    let mut indeg = in_deg.clone();
    let mut dist: HashMap<&str, usize> = nodes.iter().map(|n| (*n, 1)).collect();
    let mut stack: Vec<&str> = nodes
        .iter()
        .filter(|n| indeg.get(*n).copied().unwrap_or(0) == 0)
        .copied()
        .collect();
    let mut seen = 0usize;
    let mut longest = 1usize;
    while let Some(n) = stack.pop() {
        seen += 1;
        let d = dist[&n];
        if let Some(nexts) = adj.get(n) {
            for m in nexts {
                let dm = dist.get_mut(m).expect("node");
                if *dm < d + 1 {
                    *dm = d + 1;
                    longest = longest.max(d + 1);
                }
                let e = indeg.get_mut(m).expect("node");
                *e -= 1;
                if *e == 0 {
                    stack.push(m);
                }
            }
        }
    }
    if seen != nodes.len() {
        return Err(ErrorCode::CycleDetected.err("cycle in SUPERSEDES subgraph"));
    }
    if longest > limits.max_depth {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "supersedes chain {longest} > max_depth {}",
            limits.max_depth
        )));
    }
    Ok(longest)
}

// Test-only sugar to vary edge ids while reusing one content shape.
#[cfg(test)]
impl EdgeRecord {
    fn clone_with_id(&self, id: &str) -> Self {
        Self {
            content: self.content.clone(),
            id: id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: &str, t: RelType, to: &str, grounded: bool) -> EdgeRecord {
        let (ev, at) = if grounded {
            (Some("evd:v1:g".to_string()), None)
        } else {
            (None, None)
        };
        EdgeRecord::new(
            Relationship {
                v: 1,
                from: from.into(),
                rel_type: t,
                to: to.into(),
                evidence_ref: ev,
                attestation_ref: at,
            },
            format!("rel:v1:{from}-{to}"),
        )
    }

    fn nodes(ids: &[&str]) -> NodeSet {
        NodeSet::new(
            ids.iter()
                .map(|s| s.to_string())
                .chain(["evd:v1:g".to_string()]),
        )
    }

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn valid_chain_passes() {
        // Company OWNS Account CREATED Payment SETTLES Invoice (all grounded).
        let n = nodes(&["obj:co", "obj:acct", "obj:pay", "obj:inv"]);
        let edges = vec![
            edge("obj:co", RelType::new(RelType::OWNS), "obj:acct", true),
            edge("obj:acct", RelType::new(RelType::CREATED), "obj:pay", true),
            edge("obj:pay", RelType::new(RelType::SETTLES), "obj:inv", true),
        ];
        let g = validate_graph(&edges, &n, &lim()).unwrap();
        assert_eq!(g.edge_count, 3);
        assert_eq!(g.node_count, 4);
        assert_eq!(g.edge_ids.len(), 3);
    }

    #[test]
    fn ungrounded_settles_rejected() {
        let n = nodes(&["obj:pay", "obj:inv"]);
        let e = edge("obj:pay", RelType::new(RelType::SETTLES), "obj:inv", false);
        let err = validate_graph(&[e], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::RelationshipUngrounded);
    }

    #[test]
    fn ungrounded_references_allowed() {
        // Non-trust-relevant types may be bare (logged, not rejected).
        let n = nodes(&["a", "b"]);
        let e = edge("a", RelType::new(RelType::REFERENCES), "b", false);
        validate_graph(&[e], &n, &lim()).unwrap();
    }

    #[test]
    fn dangling_endpoint_rejected() {
        let n = nodes(&["a"]);
        let e = edge("a", RelType::new(RelType::REFERENCES), "ghost", false);
        let err = validate_graph(&[e], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::DanglingReference);
    }

    #[test]
    fn dangling_ref_rejected() {
        let n = nodes(&["a", "b"]);
        let mut e = edge("a", RelType::new(RelType::CREATED), "b", false);
        e.content.evidence_ref = Some("evd:v1:ghost".into());
        let err = validate_graph(&[e], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::DanglingReference);
    }

    #[test]
    fn supersedes_cycle_rejected() {
        let n = nodes(&["v1", "v2"]);
        let edges = vec![
            edge("v1", RelType::new(RelType::SUPERSEDES), "v2", false),
            edge("v2", RelType::new(RelType::SUPERSEDES), "v1", false),
        ];
        let err = validate_graph(&edges, &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::CycleDetected);
    }

    #[test]
    fn supersedes_branch_rejected() {
        let n = nodes(&["v1", "v2", "v3"]);
        let edges = vec![
            edge("v1", RelType::new(RelType::SUPERSEDES), "v2", false),
            edge("v1", RelType::new(RelType::SUPERSEDES), "v3", false),
        ];
        let err = validate_graph(&edges, &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::SchemaViolation);
    }

    #[test]
    fn supersedes_linear_chain_ok() {
        let n = nodes(&["v1", "v2", "v3"]);
        let edges = vec![
            edge("v1", RelType::new(RelType::SUPERSEDES), "v2", false),
            edge("v2", RelType::new(RelType::SUPERSEDES), "v3", false),
        ];
        let g = validate_graph(&edges, &n, &lim()).unwrap();
        assert_eq!(g.longest_supersedes_chain, 3);
    }

    #[test]
    fn non_supersedes_cycles_allowed() {
        // REFERENCES cycles are not forbidden in V0.1 (only SUPERSEDES is).
        let n = nodes(&["a", "b"]);
        let edges = vec![
            edge("a", RelType::new(RelType::REFERENCES), "b", false),
            edge("b", RelType::new(RelType::REFERENCES), "a", false),
        ];
        validate_graph(&edges, &n, &lim()).unwrap();
    }

    #[test]
    fn edge_limit_enforced() {
        // Plan acceptance: 300 edges against default max_edges=256.
        let lim = lim();
        assert_eq!(lim.max_edges, 256);
        let n = NodeSet::new(["n0".to_string(), "n1".to_string()]);
        let edges: Vec<_> = (0..300)
            .map(|i| {
                edge("n0", RelType::new(RelType::REFERENCES), "n1", false)
                    .clone_with_id(&format!("e{i}"))
            })
            .collect();
        let err = validate_graph(&edges, &n, &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::LimitExceeded);
    }

    #[test]
    fn depth_limit_enforced() {
        let mut lim = lim();
        lim.max_depth = 2;
        let n = nodes(&["v1", "v2", "v3"]);
        let edges = vec![
            edge("v1", RelType::new(RelType::SUPERSEDES), "v2", false),
            edge("v2", RelType::new(RelType::SUPERSEDES), "v3", false),
        ];
        let err = validate_graph(&edges, &n, &lim).unwrap_err();
        assert_eq!(err.code, ErrorCode::LimitExceeded);
    }
}
