// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `inspect`: read-only view of a proof's contents. No trust decisions are
//! made — this answers "what's inside this proof?" not "is it valid?".

use crate::Cli;
use proof_core::model::{EventContent, Evidence, MetaValue, Proof, Relationship};
use proof_core::HashRef;

/// Inspect a proof or single artifact: display contents without verification.
/// Accepts `-` for stdin, like `verify`. Proofs print the full member view;
/// single artifacts (`event`/`attestation`/`evidence`/`relationship`/`status`)
/// print their id and fields. Nothing here is trusted — use `verify` for
/// validity.
pub fn inspect(cli: &Cli) -> Result<String, String> {
    let proof_path = cli.proof_path()?;
    let (text, label) = crate::read_input_text(&proof_path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))?;

    // Single-artifact dispatch (V1.1 F8 fix): the wrapper `kind` selects the
    // decoder. Proofs fall through to the full view below.
    if let Some(kind) = v.get("kind").and_then(|x| x.as_str()) {
        match kind {
            "event" | "attestation" | "evidence" | "relationship" | "status" => {
                return inspect_artifact(&v, kind, &label, cli);
            }
            "proof" => {}
            _ => {}
        }
    }

    let hex_str = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{label}: missing `cbor`"))?;
    let bytes = hex::decode(hex_str).map_err(|e| format!("{label}: bad hex: {e}"))?;
    let limits = crate::limits();
    let value =
        proof_format::decode_strict(&bytes, &limits).map_err(|e| format!("{label}: {e}"))?;
    let proof = proof_format::schema::cbor_to_proof(&value, &limits)
        .map_err(|e| format!("{label}: {e}"))?;

    let quiet = cli.quiet();
    if !quiet {
        eprintln!("loaded proof {} ({label})", proof.proof_id);
    }

    let out = format!(
        r#"Proof Engine — Inspection (read-only, not verified)

Proof
  ID          {}
  Version     {}
  Proposition
    Kind      {}
    Subject   {}
    Predicate {}"#,
        crate::sanitize(&proof.proof_id),
        proof.v,
        crate::sanitize(&proof.proposition.kind),
        crate::sanitize(&proof.proposition.subject),
        crate::sanitize(&proof.proposition.predicate),
    );

    let out = if let Some(ref object) = proof.proposition.object {
        format!(
            "{}
    Object    {}",
            out,
            crate::sanitize(object)
        )
    } else {
        out
    };

    let out = if let Some(at_time) = proof.proposition.at_time {
        format!(
            "{}
    At time   {}",
            out, at_time
        )
    } else {
        out
    };

    let out = format!(
        "{}

Members
  Events        {}
  Attestations  {}
  Evidence      {}
  Relationships {}

Created
  {}",
        out,
        proof.events.len(),
        proof.attestations.len(),
        proof.evidence.len(),
        proof.relationships.len(),
        proof.created_at,
    );

    let out = if !proof.events.is_empty() {
        let events: Vec<String> = proof
            .events
            .iter()
            .map(|e| format!("    {}", crate::sanitize(&e.subject)))
            .collect();
        format!(
            "{}

Events
{}",
            out,
            events.join("\n")
        )
    } else {
        out
    };

    let out = if !proof.attestations.is_empty() {
        let attestations: Vec<String> = proof
            .attestations
            .iter()
            .map(|a| {
                format!(
                    "    {} (issuer: {})",
                    crate::sanitize(&a.content.subject),
                    crate::sanitize(&a.content.issuer)
                )
            })
            .collect();
        format!(
            "{}

Attestations
{}",
            out,
            attestations.join("\n")
        )
    } else {
        out
    };

    let out = if !proof.evidence.is_empty() {
        let evidence: Vec<String> = proof
            .evidence
            .iter()
            .map(|e| format!("    {}", crate::sanitize(e.kind.as_str())))
            .collect();
        format!(
            "{}

Evidence
{}",
            out,
            evidence.join("\n")
        )
    } else {
        out
    };

    let out = if !proof.relationships.is_empty() {
        let relationships: Vec<String> = proof
            .relationships
            .iter()
            .map(|r| {
                format!(
                    "    {} → {} ({})",
                    crate::sanitize(&r.from),
                    crate::sanitize(&r.to),
                    crate::sanitize(r.rel_type.as_str())
                )
            })
            .collect();
        format!(
            "{}

Relationships
{}",
            out,
            relationships.join("\n")
        )
    } else {
        out
    };

    if cli.has("json") {
        // Machine-readable projection of the decoded proof (same data as the
        // prose view; stdout carries only this document).
        let v = proof_json(&proof, &label);
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
        return Ok(label);
    }

    println!("{}", out);
    Ok(out)
}

fn meta_json(fields: &[(String, MetaValue)]) -> serde_json::Value {
    serde_json::Value::Array(
        fields
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    MetaValue::Text(s) => serde_json::Value::String(s.clone()),
                    MetaValue::Uint(n) => serde_json::Value::from(*n),
                    MetaValue::Bool(b) => serde_json::Value::from(*b),
                };
                serde_json::json!({"key": k, "value": value})
            })
            .collect(),
    )
}

fn hash_json(h: &HashRef) -> serde_json::Value {
    serde_json::json!({"alg": h.alg.name(), "digest_hex": hex::encode(&h.digest)})
}

fn event_json(e: &EventContent) -> serde_json::Value {
    serde_json::json!({
        "type": e.event_type.as_str(),
        "subject": e.subject,
        "effective_at": e.effective_at,
        "payload_ref": hash_json(&e.payload_ref),
        "metadata": meta_json(&e.metadata),
    })
}

fn evidence_json(e: &Evidence) -> serde_json::Value {
    serde_json::json!({
        "kind": e.kind.as_str(),
        "digest": hash_json(&e.digest),
        "attestation_ref": e.attestation_ref,
        "hint": e.hint,
    })
}

fn relationship_json(r: &Relationship) -> serde_json::Value {
    serde_json::json!({
        "from": r.from,
        "type": r.rel_type.as_str(),
        "to": r.to,
        "evidence_ref": r.evidence_ref,
        "attestation_ref": r.attestation_ref,
    })
}

/// Machine-readable projection of a decoded proof (no trust decisions;
/// the pipeline remains the authority on validity).
pub fn proof_json(proof: &Proof, label: &str) -> serde_json::Value {
    serde_json::json!({
        "source": label,
        "proof_id": proof.proof_id,
        "v": proof.v,
        "proposition": {
            "kind": proof.proposition.kind,
            "subject": proof.proposition.subject,
            "predicate": proof.proposition.predicate,
            "object": proof.proposition.object,
            "at_time": proof.proposition.at_time,
            "context": meta_json(&proof.proposition.context),
        },
        "created_at": proof.created_at,
        "events": proof.events.iter().map(event_json).collect::<Vec<_>>(),
        "attestations": proof.attestations.iter().map(|a| {
            serde_json::json!({
                "issuer": a.content.issuer,
                "subject": a.content.subject,
                "claim_type": a.content.claim.claim_type,
                "claim_fields": meta_json(&a.content.claim.fields),
                "issued_at": a.content.issued_at,
                "expires_at": a.content.expires_at,
                "evidence_ref": a.content.evidence_ref,
            })
        }).collect::<Vec<_>>(),
        "evidence": proof.evidence.iter().map(evidence_json).collect::<Vec<_>>(),
        "relationships": proof.relationships.iter().map(relationship_json).collect::<Vec<_>>(),
    })
}

/// Single-artifact view (V1.1 F8): decode one artifact wrapper by its `kind`
/// and print id + fields. Read-only; ids are recomputed from bytes (a file
/// whose bytes do not match its id is rejected, never displayed as valid).
fn inspect_artifact(
    v: &serde_json::Value,
    kind: &str,
    label: &str,
    cli: &Cli,
) -> Result<String, String> {
    let hex_str = v
        .get("cbor")
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("{label}: missing `cbor`"))?;
    let bytes = hex::decode(hex_str).map_err(|e| format!("{label}: bad hex: {e}"))?;
    let limits = crate::limits();
    let value =
        proof_format::decode_strict(&bytes, &limits).map_err(|e| format!("{label}: {e}"))?;
    let claimed = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
    let out = match kind {
        "event" => {
            let e = proof_format::schema::cbor_to_event(&value, &limits)
                .map_err(|e| format!("{label}: {e}"))?;
            format!(
                "Artifact (read-only, not verified)\n\n  Kind      event\n  ID        {}\n  Type      {}\n  Subject   {}\n  Effective {}\n  Payload   {}:{}\n  Metadata  {} entries",
                crate::sanitize(claimed),
                crate::sanitize(e.event_type.as_str()),
                crate::sanitize(&e.subject),
                e.effective_at,
                e.payload_ref.alg.name(),
                hex::encode(&e.payload_ref.digest),
                e.metadata.len(),
            )
        }
        "attestation" => {
            let a = proof_format::schema::cbor_to_attestation(&value, &limits)
                .map_err(|e| format!("{label}: {e}"))?;
            format!(
                "Artifact (read-only, not verified)\n\n  Kind      attestation\n  ID        {}\n  Issuer    {}\n  Subject   {}\n  Claim     {}\n  Issued    {}\n  Expires   {}",
                crate::sanitize(claimed),
                crate::sanitize(&a.issuer),
                crate::sanitize(&a.subject),
                crate::sanitize(&a.claim.claim_type),
                a.issued_at,
                a.expires_at.map_or("none".to_string(), |t| t.to_string()),
            )
        }
        "evidence" => {
            let e = proof_format::schema::cbor_to_evidence(&value, &limits)
                .map_err(|e| format!("{label}: {e}"))?;
            format!(
                "Artifact (read-only, not verified)\n\n  Kind      evidence\n  ID        {}\n  EKind     {}\n  Digest    {}:{}\n  AttRef    {}\n  Hint      {}",
                crate::sanitize(claimed),
                crate::sanitize(e.kind.as_str()),
                e.digest.alg.name(),
                hex::encode(&e.digest.digest),
                e.attestation_ref.as_deref().unwrap_or("none"),
                e.hint.as_deref().unwrap_or("none"),
            )
        }
        "relationship" => {
            let r = proof_format::schema::cbor_to_relationship(&value, &limits)
                .map_err(|e| format!("{label}: {e}"))?;
            format!(
                "Artifact (read-only, not verified)\n\n  Kind      relationship\n  ID        {}\n  Edge      {} → {} ({})\n  EvdRef    {}\n  AttRef    {}",
                crate::sanitize(claimed),
                crate::sanitize(&r.from),
                crate::sanitize(&r.to),
                crate::sanitize(r.rel_type.as_str()),
                r.evidence_ref.as_deref().unwrap_or("none"),
                r.attestation_ref.as_deref().unwrap_or("none"),
            )
        }
        "status" => {
            let a = proof_format::schema::cbor_to_attestation(&value, &limits)
                .map_err(|e| format!("{label}: {e}"))?;
            format!(
                "Artifact (read-only, not verified)\n\n  Kind      status ({})\n  ID        {}\n  Issuer    {}\n  Subject   {}\n  Issued    {}",
                crate::sanitize(&a.claim.claim_type),
                crate::sanitize(claimed),
                crate::sanitize(&a.issuer),
                crate::sanitize(&a.subject),
                a.issued_at,
            )
        }
        _ => return Err(format!("{label}: unknown artifact kind `{kind}`")),
    };
    if cli.has("json") {
        println!(
            "{}",
            serde_json::json!({"source": label, "kind": kind, "id": claimed, "view": out})
        );
        return Ok(label.to_string());
    }
    println!("{out}");
    println!("\nINSPECTED is not VERIFIED. Use `verify` to check validity.");
    Ok(out)
}
