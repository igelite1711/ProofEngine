// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden graph vectors (09 valid chain, 10 supersedes cycle).
//! Re-verifies every edge's id binding before topology validation — the same
//! order the Phase 4 pipeline will use.

use proof_core::Limits;
use proof_crypto::build::verify_relationship;
use proof_graph::{validate_graph, EdgeRecord, NodeSet};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn load(name: &str) -> serde_json::Value {
    let p = fixtures().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
    serde_json::from_str(&s).unwrap()
}

fn lim() -> Limits {
    Limits::default()
}

fn load_graph(name: &str) -> (Vec<EdgeRecord>, NodeSet) {
    let v = load(name);
    let nodes = NodeSet::new(
        v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string()),
    );
    let mut edges = vec![];
    for e in v["edges"].as_array().unwrap() {
        let canon = hex::decode(e["canonical_hex"].as_str().unwrap()).unwrap();
        let (content, id) =
            verify_relationship(&canon, Some(e["id"].as_str().unwrap()), &lim()).unwrap();
        edges.push(EdgeRecord::new(content, id));
    }
    (edges, nodes)
}

#[test]
fn golden_09_valid_chain() {
    let v = load("golden-09.json");
    let (edges, nodes) = load_graph("golden-09.json");
    let g = validate_graph(&edges, &nodes, &lim()).expect("09 must validate");
    assert_eq!(
        g.edge_count,
        v["expected"]["edge_count"].as_u64().unwrap() as usize
    );
}

#[test]
fn golden_10_supersedes_cycle() {
    let v = load("golden-10.json");
    let (edges, nodes) = load_graph("golden-10.json");
    let e = validate_graph(&edges, &nodes, &lim()).unwrap_err();
    assert_eq!(e.code.as_str(), v["expected"]["code"].as_str().unwrap());
}
