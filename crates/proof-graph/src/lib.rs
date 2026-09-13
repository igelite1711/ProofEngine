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

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
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

/// Validate edge topology.
/// Counts enforced within limits; endpoints and refs resolve (EQUIVALENT
/// edges may name identity refs — non-member strings — as endpoints, with
/// shaped ids still required to resolve and free strings accepted as
/// asserted); trust-relevant edges grounded; SUPERSEDES subgraph linear,
/// acyclic, depth-bounded.
// PE-GRAPH-001 (grounding) · PE-GRAPH-002 (dangling) · PE-GRAPH-004 (limits).
pub fn validate_graph(
    edges: &[EdgeRecord],
    nodes: &NodeSet,
    limits: &Limits,
) -> Result<ValidatedGraph, ProofError> {
    validate_graph_with_grounding(edges, nodes, limits, None)
}

/// Same as [`validate_graph`] but with a caller-supplied trust-relevant edge
/// set. `extra_grounded` adds to the default `requires_grounding()` set, so
/// future vocabularies declare their own trust-relevant kinds without a core
/// change (AUDIT §5). Pass `None` for V1 defaults.
/// Provenance DAG profile (V1.1 F4 fix). When the caller opts in
/// (`VerifyCtx::require_acyclic_provenance`), the full member-endpoint graph
/// must be acyclic — not just the SUPERSEDES subgraph. Iterative DFS over
/// member endpoints (EQUIVALENT free-string identity refs excluded, as they
/// are asserted aliases, not derivation steps). V1 default is off:
/// REFERENCES cycles remain linkage-valid unless the caller asks for DAG.
/// Runs after `validate_graph_with_grounding` succeeds; fails closed with
/// `CYCLE_DETECTED` on any directed cycle.
pub fn check_acyclic_provenance(edges: &[EdgeRecord], nodes: &NodeSet) -> Result<(), ProofError> {
    use std::collections::{HashMap, HashSet};
    // Member-only adjacency: EQUIVALENT free refs are not derivation.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut all: HashSet<&str> = HashSet::new();
    for e in edges {
        if e.content.rel_type.as_str() == RelType::EQUIVALENT {
            continue;
        }
        // Only member endpoints participate (pipeline guarantees resolution;
        // direct callers may include free strings — skip non-members here).
        if !nodes.contains(&e.content.from) || !nodes.contains(&e.content.to) {
            continue;
        }
        adj.entry(e.content.from.as_str())
            .or_default()
            .push(e.content.to.as_str());
        all.insert(e.content.from.as_str());
        all.insert(e.content.to.as_str());
    }
    // Iterative DFS with explicit stack (no recursion on hostile input).
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;
    let mut color: HashMap<&str, u8> = all.iter().map(|n| (*n, WHITE)).collect();
    for start in all.clone() {
        if color[&start] != WHITE {
            continue;
        }
        let mut stack: Vec<(&str, bool)> = vec![(start, false)];
        while let Some((n, processed)) = stack.pop() {
            if processed {
                color.insert(n, BLACK);
                continue;
            }
            if color[&n] == BLACK {
                continue;
            }
            if color[&n] == GRAY {
                return Err(ErrorCode::CycleDetected.err(format!(
                    "cycle detected in provenance graph at {n} (DAG profile)"
                )));
            }
            color.insert(n, GRAY);
            stack.push((n, true));
            if let Some(nexts) = adj.get(n) {
                for m in nexts {
                    match color.get(m).copied().unwrap_or(WHITE) {
                        BLACK => {}
                        GRAY => {
                            return Err(ErrorCode::CycleDetected.err(format!(
                                "cycle detected in provenance graph at {m} (DAG profile)"
                            )));
                        }
                        _ => stack.push((m, false)),
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn validate_graph_with_grounding(
    edges: &[EdgeRecord],
    nodes: &NodeSet,
    limits: &Limits,
    extra_grounded: Option<&std::collections::HashSet<String>>,
) -> Result<ValidatedGraph, ProofError> {
    if edges.len() > limits.max_edges {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "edges {} > max_edges {}",
            edges.len(),
            limits.max_edges
        )));
    }
    // Bound total member ids as well as edge endpoints: direct library
    // callers can construct an arbitrary NodeSet, and the pipeline's
    // endpoint-only check would miss a huge set with few edges.
    if nodes.len() > limits.max_nodes {
        return Err(ErrorCode::LimitExceeded.err(format!(
            "nodes {} > max_nodes {}",
            nodes.len(),
            limits.max_nodes
        )));
    }

    let mut endpoints: HashSet<&str> = HashSet::new();
    let mut seen_edge_ids: HashSet<&str> = HashSet::new();
    for e in edges {
        // Duplicate member ids (same rel twice) would double-count trust:
        // union semantics require set membership, so reject repeats.
        if !seen_edge_ids.insert(e.id.as_str()) {
            return Err(ErrorCode::SchemaViolation.err(format!("duplicate edge id {}", e.id)));
        }
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
        if r.rel_type.as_str() == RelType::EQUIVALENT {
            // Identity assertions name external identifiers: shaped ids must
            // resolve (else DANGLING), free strings ride as asserted — the
            // backing attestation (grounding, required) is where trust lives.
            for (label, ep) in [("from", &r.from), ("to", &r.to)] {
                if looks_like_artifact_id(ep) && !nodes.contains(ep) {
                    return Err(ErrorCode::DanglingReference.err(format!("unknown {label} {ep}")));
                }
                // Member endpoints count toward node limits; identity refs
                // are bounded by proof size instead.
                if nodes.contains(ep) {
                    endpoints.insert(ep.as_str());
                }
            }
        } else {
            if !nodes.contains(&r.from) {
                return Err(ErrorCode::DanglingReference.err(format!("unknown from {}", r.from)));
            }
            if !nodes.contains(&r.to) {
                return Err(ErrorCode::DanglingReference.err(format!("unknown to {}", r.to)));
            }
            endpoints.insert(r.from.as_str());
            endpoints.insert(r.to.as_str());
        }
        let grounded = r.rel_type.requires_grounding()
            || extra_grounded
                .map(|s| s.contains(r.rel_type.as_str()))
                .unwrap_or(false);
        if grounded && r.evidence_ref.is_none() && r.attestation_ref.is_none() {
            return Err(ErrorCode::RelationshipUngrounded.err(format!(
                "edge {} ({}) lacks backing evidence",
                e.id,
                r.rel_type.as_str()
            )));
        }
        // Backing refs are typed: evidence_ref must name evd:v1:…,
        // attestation_ref must name att:v1:…. An evt: id in either slot
        // passes `contains` but is a type error — fail closed here.
        for (label, prefix) in [("evidence_ref", "evd:v1:"), ("attestation_ref", "att:v1:")] {
            let opt = if label == "evidence_ref" {
                &r.evidence_ref
            } else {
                &r.attestation_ref
            };
            if let Some(id) = opt {
                if id.is_empty() {
                    return Err(ErrorCode::SchemaViolation.err(format!("empty {label}")));
                }
                if !id.starts_with(prefix) {
                    return Err(ErrorCode::SchemaViolation
                        .err(format!("{label} {id} must start with {prefix}")));
                }
                if !nodes.contains(id) {
                    return Err(ErrorCode::DanglingReference.err(format!("unknown {label} {id}")));
                }
            }
        }
        // NOTE: endpoint accounting happens per-type above (EQUIVALENT counts
        // member endpoints only); nothing is inserted here.
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

/// Shape heuristic: `<prefix>:vN:<suffix>` names a proof member (or a
/// future-version member) and must resolve; anything else in an EQUIVALENT
/// endpoint is an external identity ref, accepted as asserted. Treating any
/// `vN` as shaped fails closed on `evt:v2:x` instead of accepting it as a
/// free string.
fn looks_like_artifact_id(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(p), Some(v), Some(rest)) => {
            let versioned = v.len() > 1
                && v.as_bytes()[0] == b'v'
                && v[1..].bytes().all(|b| b.is_ascii_digit())
                && !rest.is_empty();
            // Known V1 prefixes always shaped; any other `xxx:vN:...` shape
            // is also treated as shaped so unknown versions fail closed
            // (DANGLING/UNSUPPORTED) rather than riding as asserted identity.
            (matches!(p, "evt" | "att" | "evd" | "rel" | "prf") && !rest.is_empty())
                || (versioned && !p.is_empty() && !p.contains(' '))
        }
        _ => false,
    }
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
        let d = *dist.get(n).ok_or_else(|| {
            ErrorCode::Malformed.err("supersedes graph invariant violated: missing distance")
        })?;
        if let Some(nexts) = adj.get(n) {
            for m in nexts {
                let dm = dist.get_mut(*m).ok_or_else(|| {
                    ErrorCode::Malformed.err("supersedes graph invariant violated: missing node")
                })?;
                if *dm < d + 1 {
                    *dm = d + 1;
                    longest = longest.max(d + 1);
                }
                let e = indeg.get_mut(*m).ok_or_else(|| {
                    ErrorCode::Malformed
                        .err("supersedes graph invariant violated: missing indegree")
                })?;
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
    fn equivalent_identity_refs_accepted_when_grounded() {
        // Identity refs are not members: accepted as asserted, trust carried
        // by the required grounding — the core never merges globally.
        let n = nodes(&["obj:co"]);
        let e = edge(
            "did:example:alice",
            RelType::new(RelType::EQUIVALENT),
            "account:alice-1",
            true,
        );
        let g = validate_graph(&[e], &n, &lim()).unwrap();
        assert_eq!(g.edge_count, 1);
        // Member endpoints still count; identity refs do not inflate nodes.
        assert_eq!(g.node_count, 0);
    }

    #[test]
    fn equivalent_bare_edges_rejected() {
        // EQUIVALENT is trust-relevant: bare edges fail like SETTLES.
        let n = nodes(&["a"]);
        let e = edge("a", RelType::new(RelType::EQUIVALENT), "b", false);
        let err = validate_graph(&[e], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::RelationshipUngrounded);
    }

    #[test]
    fn equivalent_shaped_but_unknown_rejected() {
        // Shaped ids must resolve even on EQUIVALENT edges (else DANGLING).
        let n = nodes(&["a"]);
        let e = edge(
            "a",
            RelType::new(RelType::EQUIVALENT),
            "evt:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            true,
        );
        let err = validate_graph(&[e], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::DanglingReference);
    }

    #[test]
    fn contradicts_requires_grounding_and_resolves() {
        let n = nodes(&["att:v1:a", "att:v1:b"]);
        let mut e = edge(
            "att:v1:a",
            RelType::new(RelType::CONTRADICTS),
            "att:v1:b",
            false,
        );
        let err = validate_graph(&[e.clone()], &n, &lim()).unwrap_err();
        assert_eq!(err.code, ErrorCode::RelationshipUngrounded);
        e.content.evidence_ref = Some("evd:v1:g".to_string());
        // Grounded but to a resolvable ref: passes shape validation here
        // (pipeline decides attestation-ness for conflict recording).
        validate_graph(&[e], &n, &lim()).unwrap();
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
        // REFERENCES cycles are not forbidden by default (only SUPERSEDES
        // is); the provenance DAG profile (`check_acyclic_provenance`) is
        // opt-in for derivation chains.
        let n = nodes(&["a", "b"]);
        let edges = vec![
            edge("a", RelType::new(RelType::REFERENCES), "b", false),
            edge("b", RelType::new(RelType::REFERENCES), "a", false),
        ];
        validate_graph(&edges, &n, &lim()).unwrap();
        let err = check_acyclic_provenance(&edges, &n).unwrap_err();
        assert_eq!(err.code, ErrorCode::CycleDetected);
    }

    #[test]
    fn provenance_dag_allows_chains_rejects_cycles() {
        let n = nodes(&["a", "b", "c"]);
        let chain = vec![
            edge("a", RelType::new(RelType::REFERENCES), "b", false),
            edge("b", RelType::new(RelType::REFERENCES), "c", false),
        ];
        check_acyclic_provenance(&chain, &n).unwrap();
        let cycle = vec![
            edge("a", RelType::new(RelType::REFERENCES), "b", false),
            edge("b", RelType::new(RelType::REFERENCES), "c", false),
            edge("c", RelType::new(RelType::REFERENCES), "a", false),
        ];
        let err = check_acyclic_provenance(&cycle, &n).unwrap_err();
        assert_eq!(err.code, ErrorCode::CycleDetected);
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
