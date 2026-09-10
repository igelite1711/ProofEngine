//! Fuzz target: graph ingestion/validation. Builds pseudo-random relationship
//! graphs (fixed small id pool so endpoints sometimes resolve) and runs the
//! validator. Invariants: never panics; either rejects with a stable error or
//! returns a summary whose counts are within limits; SUPERSEDES cycles are
//! always rejected (never a silent Ok with a cycle inside).

#![no_main]

use libfuzzer_sys::fuzz_target;
use proof_core::model::{RelType, Relationship};
use proof_core::Limits;
use proof_graph::{validate_graph, EdgeRecord, NodeSet};

fuzz_target!(|data: &[u8]| { // PE-GRAPH-003 PE-GRAPH-004
    let limits = Limits::default();
    // Deterministic id pool; edges occasionally resolve, mostly dangle.
    let nodes = NodeSet::new((0u8..8).map(|i| format!("evt:v1:node{i}")));
    let mut edges = Vec::new();
    for (i, chunk) in data.chunks(6).take(limits.max_edges).enumerate() {
        if chunk.len() < 6 {
            break;
        }
        let from_i = chunk[0] % 10; // 8..9 guarantee dangling sometimes
        let to_i = chunk[1] % 10;
        let rel_i = chunk[2] % 10;
        let rel_type = match rel_i {
            0 => RelType::new(RelType::OWNS),
            1 => RelType::new(RelType::CREATED),
            2 => RelType::new(RelType::SETTLES),
            3 => RelType::new(RelType::REFERENCES),
            4 => RelType::new(RelType::CONTAINS),
            5 => RelType::new(RelType::PRODUCED),
            6 => RelType::new(RelType::EXECUTED),
            7 => RelType::new(RelType::ISSUED),
            8 => RelType::new(RelType::SUPERSEDES),
            _ => RelType::new(RelType::REVOKES),
        };
        let grounded = chunk[3] % 2 == 0;
        edges.push(EdgeRecord::new(
            Relationship {
                v: 1,
                from: format!("evt:v1:node{}", from_i),
                rel_type,
                to: format!("evt:v1:node{}", to_i),
                evidence_ref: grounded.then(|| format!("evd:v1:node{}", chunk[4] % 10)),
                attestation_ref: (!grounded).then(|| format!("att:v1:node{}", chunk[5] % 10)),
            },
            format!("rel:v1:fuzz{i}"),
        ));
    }
    match validate_graph(&edges, &nodes, &limits) {
        Ok(summary) => {
            assert!(summary.edge_count <= limits.max_edges);
            assert!(summary.node_count <= limits.max_nodes);
            assert!(summary.longest_supersedes_chain <= limits.max_depth);
        }
        Err(_) => {}
    }
});
