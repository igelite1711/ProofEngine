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
                &proof_crypto::AllowedAlgs::default(),
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

    let mut b = proof_verify::ProofBuilder::new(proposition, cli.req_u64("created-at")?);
    // Composition linkage: record every distinct source proof id. The binding
    // covers the set, so dropping or swapping a source changes the id. A
    // composition byte-identical to its own source is rejected as a
    // self-reference (nothing new to link) rather than silently unwound.
    let mut sources: Vec<String> = seen_proofs.into_iter().collect();
    sources.sort();
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
    let built = b.build(&limits).map_err(|e| format!("compose: {e}"))?;
    let out = cli.req("out")?;
    crate::artifact::write_proof_file(&out, &built.id, &built.canonical)?;
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
