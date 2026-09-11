// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-process benchmark harness (P5). No new dependencies: std timing,
//! `/proc` peak-RSS on Linux, JSON baseline files for the regression gate.
//!
//! What each scenario isolates (nothing here changes semantics):
//! creation (event builder), signing (attest), canonicalization
//! (deterministic encode), hashing (content ids), verification (full
//! pipeline: small/large/wide/deep), graph validation alone, policy
//! evaluation alone, serialization round-trip.
//!
//! Usage:
//!   cargo run --release -p proof-bench -- [--iters N] [--scenario NAME]...
//!     [--json] [--write-baseline FILE] [--check-baseline FILE]
//!     [--tolerance PCT]
//! Counts scale with `--iters` (default 20); memory-heavy scenarios use
//! fixed modest shapes so a laptop stays comfortable.
//!
//! Failure handling: every fallible step propagates as `Err` to `main`
//! (exit 1) — no `unwrap`/`expect`/`panic!` anywhere, per PE-SEC-004.

use std::collections::HashMap;
use std::time::Instant;

use proof_core::model::{
    AttestationContent, Claim, EventContent, EventType, EvidenceKind, Proposition, RelType,
    Relationship,
};
use proof_core::{HashAlgorithm, HashRef, Limits};
use proof_crypto::build::{
    attest, create_event, fixtures, make_evidence, make_relationship, supersede_attestation,
    to_signed_status,
};
use proof_verify::{verify_proof, ProofBuilder, VerifyCtx};

const CLOCK: u64 = 1_700_000_200;

fn limits() -> Limits {
    Limits::default()
}

fn ctx() -> VerifyCtx {
    VerifyCtx {
        verified_at: CLOCK,
        clock_skew_leeway: 300,
        revocations_known_at: Some(CLOCK),
        ..Default::default()
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Peak RSS in KiB (Linux `/proc`; `None` elsewhere — memory dimension
/// skipped, never faked).
fn peak_rss_kb() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines().find_map(|l| {
        let rest = l.strip_prefix("VmHWM:")?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

struct Scenario {
    name: &'static str,
    ms_per_op: f64,
    ops: usize,
    peak_rss_kb: Option<u64>,
}

fn bench<F>(name: &'static str, iters: usize, mut f: F) -> Result<Scenario, String>
where
    F: FnMut() -> Result<(), String>,
{
    f().map_err(|e| format!("warmup {name}: {e}"))?; // caches hot first
    let t0 = Instant::now();
    for _ in 0..iters {
        f()?;
    }
    let dt = t0.elapsed();
    Ok(Scenario {
        name,
        ms_per_op: dt.as_secs_f64() * 1000.0 / iters as f64,
        ops: iters,
        peak_rss_kb: peak_rss_kb(),
    })
}

fn event(tag: &str, i: usize, lim: &Limits) -> Result<proof_crypto::build::CreatedEvent, String> {
    create_event(
        EventContent {
            v: 1,
            event_type: EventType::new("test.event.occurred"),
            subject: format!("test:{tag}-{i}"),
            effective_at: 1_700_000_000,
            payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).map_err(err)?,
            metadata: vec![],
        },
        lim,
    )
    .map_err(err)
}

fn statement(
    key: &proof_crypto::Ed25519Key,
    subject: &str,
    lim: &Limits,
) -> Result<proof_crypto::build::CreatedAttestation, String> {
    attest(
        AttestationContent {
            v: 1,
            issuer: key.key_ref(),
            subject: subject.into(),
            claim: Claim {
                claim_type: "test.occurred".into(),
                fields: vec![],
            },
            issued_at: 1_700_000_100,
            expires_at: None,
            evidence_ref: None,
        },
        key,
        lim,
    )
    .map_err(err)
}

fn small_proof() -> Result<(Vec<u8>, proof_verify::BuiltProof), String> {
    let lim = limits();
    let key = fixtures::test_key();
    let ev = event("small", 0, &lim)?;
    let att = statement(&key, "test:small-0", &lim)?;
    let mut b = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "test.proposition".into(),
            subject: "test:small-0".into(),
            predicate: "occurred".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK,
    );
    b.add_event(ev);
    b.add_attestation(att);
    let built = b.build(&lim).map_err(err)?;
    Ok((built.canonical.clone(), built))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("proof-bench: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut iters = 20usize;
    let mut only: Vec<String> = vec![];
    let mut json = false;
    let mut write_baseline: Option<String> = None;
    let mut check_baseline: Option<String> = None;
    let mut tolerance = 25.0f64;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(20);
                i += 1;
            }
            "--scenario" => {
                if let Some(s) = args.get(i + 1) {
                    only.push(s.clone());
                }
                i += 1;
            }
            "--json" => json = true,
            "--write-baseline" => {
                write_baseline = args.get(i + 1).cloned();
                i += 1;
            }
            "--check-baseline" => {
                check_baseline = args.get(i + 1).cloned();
                i += 1;
            }
            "--tolerance" => {
                tolerance = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(25.0);
                i += 1;
            }
            other => return Err(format!("unknown flag {other}")),
        }
        i += 1;
    }
    let want = |name: &str| only.is_empty() || only.iter().any(|s| s == name);

    let lim = limits();
    let key = fixtures::test_key();
    let (small_bytes, small_built) = small_proof()?;
    let small_ctx = ctx();

    // Large proof: 16 events + 16 attestations + 8 grounded edges.
    let mut lb = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "test.proposition".into(),
            subject: "test:large".into(),
            predicate: "occurred".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK,
    );
    let mut large_evs = vec![];
    for n in 0..16 {
        let ev = event("large", n, &lim)?;
        large_evs.push(ev.id.clone());
        lb.add_event(ev);
        lb.add_attestation(statement(&key, &format!("test:large-{n}"), &lim)?);
    }
    for n in 0..8 {
        lb.add_relationship(
            make_relationship(
                Relationship {
                    v: 1,
                    from: large_evs[n].clone(),
                    rel_type: RelType::new("REFERENCES"),
                    to: large_evs[n + 8].clone(),
                    evidence_ref: None,
                    attestation_ref: None,
                },
                &lim,
            )
            .map_err(err)?,
        );
    }
    let large_bytes = lb.build(&lim).map_err(err)?.canonical;

    // Deep proof: 8 attestations + 7 supersessions (status-supplied).
    let mut deep_atts = vec![];
    for n in 0..8 {
        deep_atts.push(statement(&key, &format!("test:deep-{n}"), &lim)?);
    }
    let mut deep_status = vec![];
    for n in 1..8 {
        let s = supersede_attestation(
            &deep_atts[n - 1].id,
            &deep_atts[n].id,
            &key,
            1_700_000_150,
            &lim,
        )
        .map_err(err)?;
        deep_status.push(to_signed_status(&s).map_err(err)?);
    }
    let mut db = ProofBuilder::new(
        Proposition {
            v: 1,
            kind: "test.proposition".into(),
            subject: "test:deep".into(),
            predicate: "occurred".into(),
            object: None,
            at_time: Some(1_700_000_100),
            context: vec![],
        },
        CLOCK,
    );
    db.add_event(event("deep", 0, &lim)?);
    for a in &deep_atts {
        db.add_attestation(a.clone());
    }
    let deep_bytes = db.build(&lim).map_err(err)?.canonical;
    let mut deep_ctx = ctx();
    deep_ctx.status_objects = deep_status;

    // Graph-only inputs: 48 edges over 8 nodes.
    let mut g_edges = vec![];
    let mut g_ids = vec![];
    for n in 0..8 {
        let ev = event("graph", n, &lim)?;
        g_ids.push(ev.id.clone());
    }
    for n in 0..48 {
        g_edges.push(proof_graph::EdgeRecord::new(
            Relationship {
                v: 1,
                from: g_ids[n % 8].clone(),
                rel_type: RelType::new("REFERENCES"),
                to: g_ids[(n + 1) % 8].clone(),
                evidence_ref: None,
                attestation_ref: None,
            },
            format!("rel:bench:{n}"),
        ));
    }
    let g_nodes = proof_graph::NodeSet::new(g_ids);

    // Policy evaluation input: verified state + minimal v1 policy.
    let small_report = verify_proof(&small_bytes, &small_ctx).map_err(err)?;
    let small_state = proof_policy::state_from_report_and_proof(&small_report, &small_built.proof)
        .map_err(err)?;
    let small_policy = proof_policy::parse_policy(
        &serde_json::json!({
            "policy_version": 1,
            "policy_id": "bench",
            "requirements": [
                {"type": "signature_valid"},
                {"type": "issuer_trusted", "issuer": key.key_ref()},
                {"type": "not_expired"},
                {"type": "not_revoked"},
            ],
        }),
        &lim,
    )
    .map_err(err)?;
    let small_inputs = proof_policy::EvalInputs {
        trusted_issuers: vec![key.key_ref()],
        verified_at: CLOCK,
        ..Default::default()
    };

    // Serialization pair for the small proof.
    let small_value = proof_format::decode_strict(&small_bytes, &lim).map_err(err)?;

    let mut out = vec![];
    if want("create-event") {
        out.push(bench("create-event", iters, || {
            event("bench", 0, &lim)?;
            Ok(())
        })?);
    }
    if want("attest-sign") {
        out.push(bench("attest-sign", iters, || {
            statement(&key, "test:bench-0", &lim)?;
            Ok(())
        })?);
    }
    if want("canonical-encode") {
        out.push(bench("canonical-encode", iters, || {
            proof_format::encode_canonical(&small_value);
            Ok(())
        })?);
    }
    if want("hash-ids") {
        out.push(bench("hash-ids", iters, || {
            let content = proof_core::model::EventContent {
                v: 1,
                event_type: EventType::new("test.event.occurred"),
                subject: "test:bench-0".into(),
                effective_at: 1_700_000_000,
                payload_ref: HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).map_err(err)?,
                metadata: vec![],
            };
            let canon = proof_format::encode_canonical(
                &proof_format::event_to_cbor(&content).map_err(err)?,
            );
            let _ = proof_crypto::id::event_id(&canon);
            Ok(())
        })?);
    }
    if want("verify-small") {
        out.push(bench("verify-small", iters, || {
            verify_proof(&small_bytes, &small_ctx).map_err(err)?;
            Ok(())
        })?);
    }
    if want("verify-large") {
        out.push(bench("verify-large", iters, || {
            verify_proof(&large_bytes, &small_ctx).map_err(err)?;
            Ok(())
        })?);
    }
    if want("verify-deep") {
        out.push(bench("verify-deep", iters, || {
            verify_proof(&deep_bytes, &deep_ctx).map_err(err)?;
            Ok(())
        })?);
    }
    if want("graph-wide") {
        out.push(bench("graph-wide", iters, || {
            proof_graph::validate_graph(&g_edges, &g_nodes, &lim).map_err(err)?;
            Ok(())
        })?);
    }
    if want("policy-eval") {
        out.push(bench("policy-eval", iters, || {
            proof_policy::evaluate_policy(&small_state, &small_policy, &small_inputs);
            Ok(())
        })?);
    }
    if want("serde-roundtrip") {
        out.push(bench("serde-roundtrip", iters, || {
            let v = proof_format::decode_strict(&small_bytes, &lim).map_err(err)?;
            let p = proof_format::cbor_to_proof(&v, &lim).map_err(err)?;
            let _ = proof_format::proof_to_cbor(&p).map_err(err)?;
            Ok(())
        })?);
    }
    if want("evidence-make") {
        out.push(bench("evidence-make", iters, || {
            make_evidence(
                EvidenceKind::new("measurement"),
                HashRef::new(HashAlgorithm::Sha256, vec![0xABu8; 32]).map_err(err)?,
                None,
                None,
                &lim,
            )
            .map_err(err)?;
            Ok(())
        })?);
    }

    if json {
        println!(
            "{{{}}}",
            out.iter()
                .map(|s| format!("\"{}\":{:.4}", s.name, s.ms_per_op))
                .collect::<Vec<_>>()
                .join(",")
        );
    } else {
        println!("proof-bench (release recommended; N={iters} default 20):");
        for s in &out {
            match s.peak_rss_kb {
                Some(rss) => println!(
                    "  {:<18} {:>9.3} ms/op ({} ops, peak RSS {} KB)",
                    s.name, s.ms_per_op, s.ops, rss
                ),
                None => println!(
                    "  {:<18} {:>9.3} ms/op ({} ops, RSS n/a)",
                    s.name, s.ms_per_op, s.ops
                ),
            }
        }
    }

    if let Some(path) = write_baseline {
        let mut map = HashMap::new();
        for s in &out {
            map.insert(s.name.to_string(), s.ms_per_op);
        }
        write_baseline_file(&path, &map)?;
        eprintln!("baseline written to {path}");
    }
    if let Some(path) = check_baseline {
        let base = read_baseline_file(&path);
        let mut failed = false;
        for s in &out {
            match base.get(s.name) {
                Some(b) => {
                    let limit = b * (1.0 + tolerance / 100.0);
                    if s.ms_per_op > limit {
                        eprintln!(
                            "REGRESSION: {} {:.3} ms/op > baseline {:.3} + {tolerance}% ({limit:.3})",
                            s.name, s.ms_per_op, b
                        );
                        failed = true;
                    }
                }
                None => eprintln!("note: {} has no baseline entry (skipped)", s.name),
            }
        }
        if failed {
            return Err("baseline gate failed".into());
        }
        eprintln!("baseline gate passed (tolerance {tolerance}%)");
    }
    Ok(())
}

fn write_baseline_file(path: &str, map: &HashMap<String, f64>) -> Result<(), String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    let body = keys
        .iter()
        .map(|k| format!("\"{k}\":{:.4}", map[*k]))
        .collect::<Vec<_>>()
        .join(",");
    std::fs::write(path, format!("{{{body}}}\n")).map_err(|e| e.to_string())
}

fn read_baseline_file(path: &str) -> HashMap<String, f64> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut map = HashMap::new();
    for part in text
        .trim_matches(|c| c == '{' || c == '}' || c == '\n')
        .split(',')
    {
        let mut kv = part.splitn(2, ':');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if let (Ok(val), name) = (
                v.trim().parse::<f64>(),
                k.trim().trim_matches('"').to_string(),
            ) {
                if !name.is_empty() {
                    map.insert(name, val);
                }
            }
        }
    }
    map
}
