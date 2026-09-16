// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Portability commands: export / import / convert / compose (P3).
//!
//! No trust logic: every path re-derives ids and re-verifies signatures
//! through the library crates. Files are transport, never authority.

use crate::artifact::input_list;
use crate::check::load_proof;
use crate::Cli;
use proof_core::model::Proposition;
use proof_format::{ArtifactEnvelope, ArtifactKind, CONTAINER_VERSION};
use std::collections::{HashMap, HashSet};

fn read_json_text(path: &str) -> Result<serde_json::Value, String> {
    let (text, label) = crate::read_input_text(path)?;
    serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))
}

/// `export`: CLI artifact JSON → standardized `ArtifactEnvelope` JSON.
/// Re-verifies the id from canonical bytes; advisory fields are regenerated.
pub fn export(cli: &Cli) -> Result<(), String> {
    let src = cli.proof_path()?;
    let out = cli.req("out")?;
    let v = read_json_text(&src)?;
    let kind_str = v
        .get("kind")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "export: missing `kind`".to_string())?;
    let kind = ArtifactKind::parse(kind_str)
        .ok_or_else(|| format!("export: unknown kind `{kind_str}`"))?;
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "export: missing `id`".to_string())?
        .to_string();
    let cbor_hex = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "export: missing `cbor`".to_string())?
        .to_string();
    let limits = crate::limits();
    let env = ArtifactEnvelope {
        container_version: CONTAINER_VERSION,
        kind,
        id: id.clone(),
        cbor_hex: cbor_hex.clone(),
        sign1_b64u: v
            .get("sign1_b64")
            .or_else(|| v.get("sign1"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
    };
    // Re-derive: envelope verification is the authority, not the file.
    proof_crypto::verify_envelope(&env, &limits, None, None)
        .map_err(|e| format!("export: envelope does not verify: {e}"))?;
    let sign1 = env.sign1_b64u.clone();
    let out_v = serde_json::json!({
        "container_version": CONTAINER_VERSION,
        "kind": kind.as_str(),
        "id": id,
        "cbor": cbor_hex,
        "sign1": sign1,
    });
    crate::artifact::write_json(&out, out_v)?;
    if !cli.quiet() {
        eprintln!("exported {} {} -> {out}", kind.as_str(), env.id);
    }
    Ok(())
}

/// `import`: `ArtifactEnvelope` JSON → CLI artifact JSON (validated).
/// Unknown envelope versions and id mismatches fail closed.
pub fn import(cli: &Cli) -> Result<(), String> {
    let src = cli.proof_path()?;
    let out = cli.req("out")?;
    let v = read_json_text(&src)?;
    let kind_str = v
        .get("kind")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "import: missing `kind`".to_string())?;
    let kind = ArtifactKind::parse(kind_str)
        .ok_or_else(|| format!("import: unknown kind `{kind_str}`"))?;
    let cv = v
        .get("container_version")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    if cv != CONTAINER_VERSION as u64 {
        // Legacy CLI files without container_version are still importable when
        // they carry kind/id/cbor; anything else fails closed.
        let legacy_ok = v.get("container_version").is_none()
            && v.get("id").is_some()
            && v.get("cbor").is_some();
        if !legacy_ok {
            return Err(format!(
                "import: unsupported container_version {cv} (expected {})",
                CONTAINER_VERSION
            ));
        }
    }
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "import: missing `id`".to_string())?
        .to_string();
    let cbor_hex = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "import: missing `cbor`".to_string())?
        .to_string();
    let sign1 = v
        .get("sign1")
        .or_else(|| v.get("sign1_b64"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let env = ArtifactEnvelope {
        container_version: CONTAINER_VERSION,
        kind,
        id: id.clone(),
        cbor_hex: cbor_hex.clone(),
        sign1_b64u: sign1.clone(),
    };
    let limits = crate::limits();
    proof_crypto::verify_envelope(&env, &limits, None, None)
        .map_err(|e| format!("import: envelope does not verify: {e}"))?;
    // Write CLI shape (kind/id/cbor + sign1_b64 for attestations).
    let mut out_v = serde_json::json!({"kind": kind.as_str(), "id": id, "cbor": cbor_hex});
    if let Some(s) = sign1 {
        out_v["sign1_b64"] = serde_json::Value::String(s);
    }
    // Preserve issuer hint for attestations when present (advisory).
    if let Some(iss) = v.get("issuer") {
        out_v["issuer"] = iss.clone();
    }
    crate::artifact::write_json(&out, out_v)?;
    if !cli.quiet() {
        eprintln!("imported {} {} -> {out}", kind.as_str(), env.id);
    }
    Ok(())
}

/// `convert`: normalize legacy artifact JSON idempotently.
/// - Adds missing `container_version` where the file is already an envelope.
/// - Normalizes `sign1` ↔ `sign1_b64` so both spellings verify.
/// - Re-canonicalizes `cbor` hex case (lowercase) without touching bytes.
pub fn convert(cli: &Cli) -> Result<(), String> {
    let src = cli.proof_path()?;
    let out = cli.req("out")?;
    let mut v = read_json_text(&src)?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "convert: not an object".to_string())?;
    if obj.contains_key("kind")
        && obj.contains_key("cbor")
        && !obj.contains_key("container_version")
    {
        obj.insert(
            "container_version".into(),
            serde_json::Value::from(CONTAINER_VERSION),
        );
    }
    // Unify signature field spellings (keep both populated when either exists).
    let s = obj
        .get("sign1")
        .or_else(|| obj.get("sign1_b64"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    if let Some(s) = s {
        obj.insert("sign1".into(), serde_json::Value::String(s.clone()));
        obj.insert("sign1_b64".into(), serde_json::Value::String(s));
    }
    if let Some(cbor) = obj.get("cbor").and_then(|x| x.as_str()).map(str::to_string) {
        obj.insert(
            "cbor".into(),
            serde_json::Value::String(cbor.to_lowercase()),
        );
    }
    crate::artifact::write_json(&out, serde_json::Value::Object(obj.clone()))?;
    if !cli.quiet() {
        eprintln!("converted {src} -> {out}");
    }
    Ok(())
}

/// `compose`: union member sets from multiple proofs into one composite proof
/// (SPEC §7 v1 semantics: content-addressed members cost nothing to reuse).
/// Provenance preserved: each member keeps its own id/signature; the new
/// `proof_id` binds the exact union. Missing/corrupt inputs fail closed.
pub fn compose(cli: &Cli) -> Result<String, String> {
    let quiet = cli.quiet();
    let paths = input_list(cli, "proofs")?;
    if paths.is_empty() {
        return Err("compose: missing --proofs a.json,b.json".to_string());
    }
    let context = crate::parse_fields(cli.opt("context"))?;
    let proposition = Proposition {
        v: 1,
        kind: cli.req("kind")?,
        subject: cli.req("subject")?,
        predicate: cli.req("predicate")?,
        object: cli.opt("object"),
        at_time: cli.opt_u64("at-time")?,
        context,
    };
    let limits = crate::limits();
    let mut events: HashMap<String, proof_core::model::EventContent> = HashMap::new();
    let mut attestations: HashMap<String, proof_crypto::build::CreatedAttestation> = HashMap::new();
    let mut evidence: HashMap<String, proof_core::model::Evidence> = HashMap::new();
    let mut relationships: HashMap<String, proof_core::model::Relationship> = HashMap::new();
    let mut seen_proofs: HashSet<String> = HashSet::new();

    for path in &paths {
        let loaded = load_proof(path, quiet)?;
        if !seen_proofs.insert(loaded.proof.proof_id.clone()) {
            continue; // idempotent on repeated inputs
        }
        for e in &loaded.proof.events {
            let canon = proof_format::encode_canonical(
                &proof_format::event_to_cbor(e).map_err(|e| e.to_string())?,
            );
            let id = proof_crypto::id::event_id(&canon);
            events.entry(id).or_insert_with(|| e.clone());
        }
        for a in &loaded.proof.attestations {
            let canon =
                proof_format::encode_canonical(&proof_format::attestation_to_cbor(&a.content));
            let id = proof_crypto::id::attestation_id(&canon);
            if attestations.contains_key(&id) {
                continue;
            }
            // Re-verify signature binding through the crypto crate.
            let (content, vid) = proof_crypto::build::verify_attestation(
                &a.sign1,
                &a.content.issuer,
                &proof_crypto::AllowedAlgs::strict(),
                &limits,
            )
            .map_err(|e| format!("compose: attestation in {path} rejected: {e}"))?;
            if vid != id || content != a.content {
                return Err(format!("compose: attestation id mismatch in {path}"));
            }
            attestations.insert(
                id.clone(),
                proof_crypto::build::CreatedAttestation {
                    content: a.content.clone(),
                    canonical: canon,
                    id,
                    sign1: a.sign1.clone(),
                },
            );
        }
        for e in &loaded.proof.evidence {
            let canon = proof_format::encode_canonical(&proof_format::evidence_to_cbor(e));
            let id = proof_crypto::id::evidence_id(&canon);
            evidence.entry(id).or_insert_with(|| e.clone());
        }
        for r in &loaded.proof.relationships {
            let canon = proof_format::encode_canonical(&proof_format::relationship_to_cbor(r));
            let id = proof_crypto::id::relationship_id(&canon);
            relationships.entry(id).or_insert_with(|| r.clone());
        }
    }

    // ---- Detect divergent claims across composed attestations ----
    // SPEC §9.3: divergent_claims is a native, first-class state. Composition
    // must propagate it so a verifier never receives a silently-contradictory
    // composite. Detect same (claim.type, subject) with differing fields.
    let mut divergent_pairs: Vec<(String, String, String, String)> = Vec::new();
    {
        let mut by_claim: HashMap<
            (String, String),
            Vec<(String, proof_crypto::build::CreatedAttestation)>,
        > = HashMap::new();
        for (_id, a) in &attestations {
            let key = (
                a.content.claim.claim_type.clone(),
                a.content.subject.clone(),
            );
            by_claim
                .entry(key)
                .or_default()
                .push((_id.clone(), a.clone()));
        }
        for ((claim_type, subject), mut group) in by_claim {
            group.sort_by(|a, b| a.0.cmp(&b.0));
            let base = &group[0];
            for candidate in group.iter().skip(1) {
                if base.1.content.claim.fields != candidate.1.content.claim.fields {
                    divergent_pairs.push((
                        claim_type.clone(),
                        subject.clone(),
                        base.0.clone(),
                        candidate.0.clone(),
                    ));
                }
            }
        }
    }
    // Composition linkage: record every distinct source proof id. The binding
    // covers the set, so dropping or swapping a source changes the id. A
    // composition byte-identical to its own source is rejected as a
    // self-reference (nothing new to link) rather than silently unwound.
    let mut sources: Vec<String> = seen_proofs.into_iter().collect();
    sources.sort();
    let mut b = proof_verify::ProofBuilder::new(proposition, cli.req_u64("created-at")?);
    for id in &sources {
        b.add_referenced_proof(id.clone())
            .map_err(|e| format!("compose: bad source id: {e}"))?;
    }
    for (_, e) in events {
        let created = proof_crypto::build::create_event(e, &limits).map_err(|e| e.to_string())?;
        b.add_event(created);
    }
    for (_, a) in attestations {
        b.add_attestation(a);
    }
    for (_, e) in evidence {
        let created = proof_crypto::build::make_evidence(
            e.kind,
            e.digest,
            e.attestation_ref,
            e.hint,
            &limits,
        )
        .map_err(|e| e.to_string())?;
        b.add_evidence(created);
    }
    for (_, r) in relationships {
        let created =
            proof_crypto::build::make_relationship(r, &limits).map_err(|e| e.to_string())?;
        b.add_relationship(created);
    }
    // ---- Union coherence (fail-closed composition) ----
    // A composition claims its members combine coherently, so the UNION graph
    // is validated here — grounding, dangling refs, SUPERSEDES linearity, and
    // derivation acyclicity — with no clock needed. Cross-proof cycles and
    // branches (acyclic alone, cyclic/branched together) fail here with
    // CYCLE_DETECTED/SCHEMA_VIOLATION instead of surfacing later at verify.
    // TIME/REVOCATION currency stays verify-time by design (composing
    // historical members is legitimate; relying on them is the verifier's
    // decision — use --production at verify). Single-proof `build` stays
    // structural-only so negative-test vectors remain constructible at the
    // library layer; compose asserts coherence. Custom trust-relevant kinds
    // ride `--extra-grounded` like verify.
    {
        use proof_graph::{check_derivation_acyclic, validate_graph_with_grounding};
        use proof_graph::{EdgeRecord, NodeSet};
        let extra = crate::make::extra_grounded(cli);
        let extra_set: Option<std::collections::HashSet<String>> = if extra.is_empty() {
            None
        } else {
            Some(extra.into_iter().collect())
        };
        // Member ids are content-addressed: recompute exactly as the builder
        // will, so the checked graph IS the assembled graph. Shared members
        // dedup by id (union semantics, mirroring the maps above) so
        // composing overlapping proofs never trips duplicate-edge rejection.
        let mut node_ids: Vec<String> = vec![];
        let mut edges: Vec<EdgeRecord> = vec![];
        let mut seen_edges: std::collections::HashSet<String> = std::collections::HashSet::new();
        for path in &paths {
            let loaded = load_proof(path, true)?;
            for e in &loaded.proof.events {
                let canon = proof_format::encode_canonical(
                    &proof_format::event_to_cbor(e).map_err(|e| e.to_string())?,
                );
                node_ids.push(proof_crypto::id::event_id(&canon));
            }
            for a in &loaded.proof.attestations {
                let canon =
                    proof_format::encode_canonical(&proof_format::attestation_to_cbor(&a.content));
                node_ids.push(proof_crypto::id::attestation_id(&canon));
            }
            for e in &loaded.proof.evidence {
                let canon = proof_format::encode_canonical(&proof_format::evidence_to_cbor(e));
                node_ids.push(proof_crypto::id::evidence_id(&canon));
            }
            for r in &loaded.proof.relationships {
                let canon = proof_format::encode_canonical(&proof_format::relationship_to_cbor(r));
                let rid = proof_crypto::id::relationship_id(&canon);
                if seen_edges.insert(rid.clone()) {
                    edges.push(EdgeRecord::new(r.clone(), rid));
                }
            }
        }
        let nodes = NodeSet::new(node_ids);
        validate_graph_with_grounding(&edges, &nodes, &limits, extra_set.as_ref())
            .map_err(|e| format!("compose: union graph invalid: {e}"))?;
        check_derivation_acyclic(&edges, &nodes)
            .map_err(|e| format!("compose: union derivation cycle: {e}"))?;
    }
    let built = b.build(&limits).map_err(|e| format!("compose: {e}"))?;
    let out = cli.req("out")?;
    crate::artifact::write_proof_file(&out, &built.id, &built.canonical)?;

    // Surface divergent claims detected during composition. SPEC §9.3: conflict
    // is a native, first-class state; a composite must never silently bury it.
    // Write a sidecar conflicts file next to the proof so automated consumers
    // can read it without re-parsing the CBOR.
    if !divergent_pairs.is_empty() {
        let n_divergent = divergent_pairs.len();
        let conflicts_json = serde_json::json!({
            "conflicts": divergent_pairs
                .into_iter()
                .map(|(claim_type, subject, att_a, att_b)| {
                    serde_json::json!({
                        "kind": "divergent_claims",
                        "claim_type": claim_type,
                        "subject": subject,
                        "attestation_a": att_a,
                        "attestation_b": att_b,
                    })
                })
                .collect::<Vec<_>>(),
        });
        let conflicts_path = format!("{}.conflicts.json", out.trim_end_matches(".json"));
        crate::artifact::write_json(&conflicts_path, conflicts_json)?;
        if !quiet {
            eprintln!(
                "compose: {} divergent claim(s) detected — write sidecar -> {}",
                n_divergent, conflicts_path
            );
        }
    } else if !quiet {
        eprintln!("compose: no divergent claims detected across composed attestations");
    }

    if !quiet {
        eprintln!(
            "composed {} proof(s) ({} events, {} attestations, {} evidence, {} relationships, {} refs) -> {}",
            sources.len(),
            built.proof.events.len(),
            built.proof.attestations.len(),
            built.proof.evidence.len(),
            built.proof.relationships.len(),
            built.proof.referenced_proofs.len(),
            out
        );
    }
    Ok(built.id)
}

/// `resolve`: fetch-and-verify transitive composition linkage (P4).
/// Bundle-layer only: the root verifies exactly as `verify` reports it;
/// every transitively referenced proof is fetched from a file store and
/// re-verified under the same context, with depth accounting. Exit 0 iff
/// every reachable reference resolved; exit 1 (via Err) on engine/usage
/// errors. Incomplete resolution is reported, never valid-by-assumption.
pub fn resolve(cli: &Cli) -> Result<i32, String> {
    use proof_verify::{resolve_proof_chain, UnresolvedReason};
    let proof = load_proof(&cli.proof_path()?, cli.quiet())?;
    let c = crate::make::common(cli)?;
    let statuses: Vec<proof_crypto::SignedStatus> = cli
        .many("status")
        .iter()
        .map(|p| crate::artifact::load_status(p, &crate::limits(), cli.quiet()))
        .collect::<Result<_, _>>()?;
    let store_dir = cli.req("store")?;
    let store = crate::store::FileStore::open(&store_dir)?;
    let max_depth: usize = cli
        .opt("depth")
        .map(|v| v.parse().map_err(|_| "--depth must be a u64".to_string()))
        .transpose()?
        .unwrap_or(8);
    let vp = crate::make::verifier_policy(cli)?;
    let ctx = proof_verify::VerifyCtx {
        verified_at: c.verified_at,
        clock_skew_leeway: c.skew,
        trusted_issuers: cli.many("trusted"),
        status_objects: statuses,
        revocation_authorities: cli.many("authority"),
        revocations_known_at: c.revocations_known_at,
        allowed_algs: vp.allowed_algs,
        report_all_failures: vp.report_all_failures,
        accepted_vocabularies: vp.accepted_vocabularies,
        extra_grounded: vp.extra_grounded,
        require_acyclic_provenance: vp.require_acyclic_provenance,
        require_status_feed: vp.require_status_feed,
        ..Default::default()
    };
    let rep = resolve_proof_chain(&proof.canonical, &store, &ctx, max_depth)
        .map_err(|e| format!("resolve: {e}"))?;
    let reason_word = |r: &UnresolvedReason| match r {
        UnresolvedReason::Unavailable => "UNAVAILABLE".to_string(),
        UnresolvedReason::IdMismatch { found } => format!("ID_MISMATCH(found={found})"),
        UnresolvedReason::DepthExceeded => "DEPTH_EXCEEDED".to_string(),
        UnresolvedReason::OverBudget => "OVER_BUDGET".to_string(),
        UnresolvedReason::Store(e) => format!("STORE_ERROR({e})"),
    };
    let v = serde_json::json!({
        "root": rep.root.proof_id,
        "root_currently_acceptable": crate::check::is_currently_acceptable(&rep.root),
        "complete": rep.complete(),
        "max_depth": max_depth,
        "resolved": rep.resolved.iter().map(|r| serde_json::json!({
            "id": r.id,
            "depth": r.depth,
            "cryptographic_validity": format!("{:?}", r.report.cryptographic_validity),
            "evidence_validity": format!("{:?}", r.report.evidence_validity),
            "currently_acceptable": crate::check::is_currently_acceptable(&r.report),
        })).collect::<Vec<_>>(),
        "unresolved": rep.unresolved.iter().map(|u| serde_json::json!({
            "id": u.id,
            "depth": u.depth,
            "reason": reason_word(&u.reason),
        })).collect::<Vec<_>>(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
    );
    if !cli.quiet() {
        eprintln!(
            "resolved {} proof(s), {} unresolved (complete={})",
            rep.resolved.len(),
            rep.unresolved.len(),
            rep.complete()
        );
    }
    Ok(if rep.complete() {
        crate::EXIT_OK
    } else {
        crate::EXIT_FAIL
    })
}
