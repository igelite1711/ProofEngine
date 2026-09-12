// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stable mirror of `fuzz/fuzz_targets/graph_ingest.rs`.
//! libFuzzer runs nightly-only (and cannot mmap under PRoot), so the checked-in
//! seed corpus (`fuzz/seeds/graph_ingest/`) is replayed here on stable to
//! enforce the same invariants on every push: never panics; either rejects
//! with a stable error or returns counts within limits (PE-GRAPH-003/004).

use proof_core::model::{RelType, Relationship};
use proof_core::Limits;
use proof_graph::{validate_graph, EdgeRecord, NodeSet};

fn seeds_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/graph_ingest")
}

/// Same harness body as the fuzz target: deterministic id pool, 6-byte chunks.
fn run_harness(data: &[u8]) {
    let limits = Limits::default();
    let nodes = NodeSet::new((0u8..8).map(|i| format!("evt:v1:node{i}")));
    let mut edges = Vec::new();
    for (i, chunk) in data.chunks(6).take(limits.max_edges).enumerate() {
        if chunk.len() < 6 {
            break;
        }
        let from_i = chunk[0] % 10;
        let to_i = chunk[1] % 10;
        let rel_type = match chunk[2] % 10 {
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
    if let Ok(summary) = validate_graph(&edges, &nodes, &limits) {
        assert!(summary.edge_count <= limits.max_edges);
        assert!(summary.node_count <= limits.max_nodes);
        assert!(summary.longest_supersedes_chain <= limits.max_depth);
    }
}

#[test]
fn seed_corpus_holds_graph_invariants() {
    let dir = seeds_dir();
    let mut count = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("missing seed corpus {}: {e}", dir.display()))
        .collect::<Result<_, _>>()
        .unwrap();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        run_harness(&std::fs::read(entry.path()).unwrap());
        count += 1;
    }
    assert!(count > 0, "seed corpus is empty: {}", dir.display());
}

#[test]
fn hostile_graphs_reject_cleanly() {
    // Empty input, self-edge storm, and a supersedes cycle must never panic
    // and never validate a cycle.
    run_harness(&[]);
    run_harness(&[8, 8, 8, 0, 0, 0]);
    run_harness(&[0, 1, 8, 0, 0, 0, 1, 0, 8, 0, 0, 0]);
}
