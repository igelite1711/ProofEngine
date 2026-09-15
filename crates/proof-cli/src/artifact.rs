// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Artifact files: JSON wrappers around canonical CBOR bytes (hex).
//! JSON is transport-only; the canonical CBOR is the artifact of record
//! (FORMAT §7). Every load re-verifies bytes against schema and recomputes
//! the id — a file whose bytes do not match its id is rejected, never used.

use crate::Cli;
use proof_core::model::{AttestationContent, EventContent, Evidence, Relationship};
use proof_core::{Limits, ProofError};
use proof_crypto::CreatedAttestation;
use serde_json::json;

/// Write a JSON artifact: to the file at `path`, or to stdout when `path`
/// is `-` (Unix streaming; stdout then carries only the document).
pub fn write_json(path: &str, value: serde_json::Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
    if path == "-" {
        println!("{text}");
        return Ok(());
    }
    std::fs::write(
        path,
        text + "
",
    )
    .map_err(|e| format!("write {path}: {e}"))
}

fn read_json(path: &str) -> Result<serde_json::Value, String> {
    let text = crate::read_input_file(path)?;
    serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))
}

pub fn cbor_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Required comma/colon-separated list flag → owned strings.
/// `--evidence ""` is accepted as "no members" (attestations-only proofs);
/// every other list must be non-empty.
fn list(cli: &Cli, name: &str) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for item in cli.many(name) {
        // Explicit empty string = intentional empty list (only meaningful
        // for --evidence today; harmless elsewhere since the builder then
        // just adds zero members of that kind).
        if item.is_empty() {
            continue;
        }
        for f in item.split([',', ':']) {
            if f.is_empty() {
                return Err(format!("--{name} has an empty entry"));
            }
            out.push(f.to_string());
        }
    }
    if out.is_empty() {
        if cli.many(name).iter().any(|s| s.is_empty()) {
            return Ok(out);
        }
        let hint = if name == "evidence" {
            " (attestations-only proof? pass --evidence \"\" for no evidence)"
        } else {
            ""
        };
        return Err(format!("missing required flag --{name}{hint}"));
    }
    Ok(out)
}

/// Optional comma/colon-separated list flag → owned strings.
/// Unlike [`list`], a missing flag means "no members" (no error): `build`
/// accepts omitted `--evidence` / `--relationships` exactly like an explicit
/// `--evidence ""`. Events, attestations, and `--proofs` stay required via
/// [`list`] so a forgotten input file still fails fast instead of silently
/// building an empty proof.
fn opt_list(cli: &Cli, name: &str) -> Result<Vec<String>, String> {
    if cli.many(name).is_empty() {
        return Ok(vec![]);
    }
    list(cli, name)
}

fn req_str(v: &serde_json::Value, file: &str, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{file}: missing `{key}`"))
}

fn opt_str(v: &serde_json::Value, file: &str, key: &str) -> Result<Option<String>, String> {
    match v.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(x) => Ok(Some(
            x.as_str()
                .ok_or_else(|| format!("{file}: `{key}` must be a string"))?
                .to_string(),
        )),
    }
}

// ---------------------------------------------------------------- writers

/// `create-event`: validate, canonicalize, id, write event artifact.
/// DX: `--payload-hex <64|96 hex>` OR `--payload-file <path>` (file bytes are
/// hashed with SHA-256; digest plumbing hidden). `--payload-file -` reads stdin.
pub fn write_event(cli: &Cli) -> Result<String, String> {
    let payload_ref = if let Some(path) = cli.opt("payload-file") {
        let bytes = crate::read_input_bytes(&path)
            .map_err(|e| format!("create-event payload-file: {e}"))?;
        // SHA-256 over file bytes; SHA-384 via --payload-hex for the 48B case.
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).to_vec()
        };
        proof_core::HashRef::new(proof_core::HashAlgorithm::Sha256, digest)
            .map_err(|e| e.to_string())?
    } else {
        hash_ref_from_hex(&cli.req("payload-hex").map_err(|_| {
            "missing required flag --payload-hex (or --payload-file <path> to hash a file)"
                .to_string()
        })?)?
    };
    let content = EventContent {
        v: 1,
        event_type: proof_core::model::EventType::new(cli.req("type")?),
        subject: cli.req("subject")?,
        effective_at: cli.req_u64("effective-at")?,
        payload_ref,
        metadata: crate::parse_fields(cli.opt("meta"))?,
    };
    let created = proof_crypto::build::create_event(content, &crate::limits())
        .map_err(|e| format!("create-event: {e}"))?;
    let out = cli.req("out")?;
    write_json(
        &out,
        json!({
            "kind": "event",
            "id": created.id,
            "cbor": cbor_to_hex(&created.canonical),
        }),
    )?;
    crate::progress(cli.quiet(), &format!("event   {} -> {out}", created.id));
    if !cli.quiet() {
        eprintln!(
            "  next: proof-cli attest --seed <test|hex|file> --subject <id> --claim-type <type> --claim k=v --issued-at <u64> --out att.json  (use id {} as subject or edge endpoint)",
            created.id
        );
    }
    Ok(created.id)
}

/// `attest`: bind issuer to the signing key, sign, write attestation artifact.
pub fn write_attestation(cli: &Cli) -> Result<String, String> {
    let key = crate::load_key_opt(cli)?;
    if let Some(r) = cli.opt("evidence-ref") {
        if !r.starts_with("evd:v1:") {
            return Err(format!(
                "`--evidence-ref {r}` must start with evd:v1: (typed reference; wrong-typed ids fail closed)"
            ));
        }
    }
    let fields = crate::parse_fields(cli.opt("claim"))?;
    // Fail-fast for opt-in semantic binding (Fix 5): a malformed
    // `evidence_digest` claim field or a digest without `--evidence-ref`
    // is guaranteed to fail later at verify with EVIDENCE
    // (SCHEMA_VIOLATION/DANGLING_REFERENCE) — catch the typo now with the
    // slot named. Non-text values cannot encode hex by construction
    // (parse_fields types bare numbers/bools), so reject those here too.
    for (k, v) in &fields {
        if k == "evidence_digest" {
            match v {
                proof_core::model::MetaValue::Text(s) => {
                    let norm = s
                        .strip_prefix("0x")
                        .or_else(|| s.strip_prefix("0X"))
                        .unwrap_or(s)
                        .to_lowercase();
                    if !((norm.len() == 64 || norm.len() == 96)
                        && norm.bytes().all(|b| b.is_ascii_hexdigit()))
                    {
                        return Err(format!(
                            "`--claim evidence_digest={s}` must be 64 (sha-256) or 96 (sha-384) hex chars (optional 0x); mismatched/malformed digests fail EVIDENCE closed at verify"
                        ));
                    }
                    if cli.opt("evidence-ref").is_none() {
                        return Err(
                            "`--claim evidence_digest=…` requires `--evidence-ref <evd:v1:…>` to bind it to (digest without a bound evidence fails EVIDENCE closed at verify)"
                                .to_string(),
                        );
                    }
                }
                _ => {
                    return Err(
                        "`--claim evidence_digest=…` must be text hex (numbers/bools cannot encode a digest; non-text fails EVIDENCE closed at verify)"
                            .to_string(),
                    );
                }
            }
        }
    }
    let content = AttestationContent {
        v: 1,
        issuer: key.key_ref(),
        subject: cli.req("subject")?,
        claim: proof_core::model::Claim {
            claim_type: cli.req("claim-type")?,
            fields,
        },
        issued_at: cli.req_u64("issued-at")?,
        expires_at: cli.opt_u64("expires-at")?,
        evidence_ref: cli.opt("evidence-ref"),
    };
    let created = proof_crypto::build::attest(content, &key, &crate::limits())
        .map_err(|e| format!("attest: {e}"))?;
    let out = cli.req("out")?;
    write_json(
        &out,
        json!({
            "kind": "attestation",
            "id": created.id,
            "issuer": created.content.issuer,
            "cbor": cbor_to_hex(&created.canonical),
            "sign1_b64": proof_crypto::id::b64u_nopad(&created.sign1),
        }),
    )?;
    crate::progress(
        cli.quiet(),
        &format!(
            "attest  {} (issuer {}) -> {out}",
            created.id, created.content.issuer
        ),
    );
    if !cli.quiet() {
        eprintln!(
            "  next: proof-cli add-evidence --kind <kind> --digest-hex <hex> --attestation-ref {} --out evd.json",
            created.id
        );
        eprintln!(
            "  next: proof-cli init-policy --attestation {out} --proof proof.json --out policy.json  (after build; kinds inferred)"
        );
    }
    Ok(created.id)
}

/// `add-evidence`: evidence is id-bound only (no signature of its own).
/// DX: `--digest-hex <64|96 hex>` OR `--digest-file <path|->` (file bytes are
/// hashed with SHA-256; mirrors `create-event --payload-file`, no manual
/// hashlib plumbing). `--digest-file -` reads stdin.
pub fn write_evidence(cli: &Cli) -> Result<String, String> {
    let digest = if let Some(path) = cli.opt("digest-file") {
        let bytes =
            crate::read_input_bytes(&path).map_err(|e| format!("add-evidence digest-file: {e}"))?;
        // SHA-256 over file bytes; SHA-384 via --digest-hex for the 48B case.
        let d = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).to_vec()
        };
        proof_core::HashRef::new(proof_core::HashAlgorithm::Sha256, d).map_err(|e| e.to_string())?
    } else {
        hash_ref_from_hex(&cli.req("digest-hex").map_err(|_| {
            "missing required flag --digest-hex (or --digest-file <path> to hash a file)"
                .to_string()
        })?)?
    };
    if let Some(r) = cli.opt("attestation-ref") {
        if !r.starts_with("att:v1:") {
            return Err(format!(
                "`--attestation-ref {r}` must start with att:v1: (typed reference; wrong-typed ids fail closed)"
            ));
        }
    }
    let created = proof_crypto::build::make_evidence(
        proof_core::model::EvidenceKind::new(cli.req("kind")?),
        digest,
        cli.opt("attestation-ref"),
        cli.opt("hint"),
        &crate::limits(),
    )
    .map_err(|e| format!("add-evidence: {e}"))?;
    let out = cli.req("out")?;
    write_json(
        &out,
        json!({
            "kind": "evidence",
            "id": created.id,
            "cbor": cbor_to_hex(&created.canonical),
        }),
    )?;
    crate::progress(cli.quiet(), &format!("evidence {} -> {out}", created.id));
    if !cli.quiet() {
        eprintln!(
            "  next: proof-cli relate --from <evt:id> --type <TYPE> --to <evt:id> --evidence-ref {} --attestation-ref <att:id> --out rel.json",
            created.id
        );
    }
    Ok(created.id)
}

/// `relate`: bind a relationship edge to its id.
/// Fix 8: trust-relevant edges fail fast here when ungrounded (previously
/// they built successfully and only failed later at `verify` with
/// RELATIONSHIP_UNGROUNDED). Endpoints must be full artifact ids; grounding
/// (--evidence-ref and/or --attestation-ref) is required now for
/// OWNS/CREATED/SETTLES/EXECUTED/EQUIVALENT/CONTRADICTS. Non-trust types
/// (REFERENCES/CONTAINS/ISSUED/PRODUCED/...) may stay bare as linkage.
/// Use --allow-ungrounded to intentionally create a negative-test vector
/// (verify will still fail closed).
/// Exception (V1.1 F3 fix): `EQUIVALENT` endpoints may name external identity
/// refs (e.g. `did:org:acme`) as asserted — the backing attestation (required
/// grounding) is where trust lives, mirroring `proof-graph` semantics.
pub fn write_relationship(cli: &Cli) -> Result<String, String> {
    let rel_type = cli.req("type")?;
    let is_equivalent = rel_type == proof_core::model::RelType::EQUIVALENT;
    for flag in ["from", "to"] {
        let v = cli.req(flag)?;
        if looks_like_artifact_id(&v) {
            continue;
        }
        if is_equivalent && is_free_identity_ref(&v) {
            continue;
        }
        if is_equivalent && looks_shaped(&v) {
            return Err(format!(
                "`--{flag} {v}` looks like an artifact id but is malformed (want `evt:…`, `att:…` or `evd:…`); shaped ids must resolve — free identity refs must not contain `:vN:`"
            ));
        }
        return Err(format!(
            "`--{flag} {v}` is not an artifact id (want `evt:…`, `att:…` or `evd:…`); bare labels like `invoice:i9` never resolve — create the artifact first (e.g. `create-event`) and use its id{}",
            if is_equivalent {
                "; for EQUIVALENT identity refs use free strings like `did:org:acme` (grounding still required)"
            } else {
                ""
            }
        ));
    }
    for flag in ["evidence-ref", "attestation-ref"] {
        if let Some(v) = cli.opt(flag) {
            if !looks_like_artifact_id(&v) {
                return Err(format!(
                    "`--{flag} {v}` is not an artifact id (want `evd:…` / `att:…`); use the id from the artifact file"
                ));
            }
            // F4/F5: typed refs fail fast (schema would reject later with the
            // same message, but creation-time guidance names the slot).
            let want = if flag == "evidence-ref" {
                "evd:v1:"
            } else {
                "att:v1:"
            };
            if !v.starts_with(want) {
                return Err(format!(
                    "`--{flag} {v}` must start with {want} (typed reference; wrong-typed ids fail closed)"
                ));
            }
        }
    }
    let content = Relationship {
        v: 1,
        rel_type: proof_core::model::RelType::new(cli.req("type")?),
        from: cli.req("from")?,
        to: cli.req("to")?,
        evidence_ref: cli.opt("evidence-ref"),
        attestation_ref: cli.opt("attestation-ref"),
    };
    // Fix 8: fail fast on ungrounded trust-relevant edges (verify would fail
    // closed later with RELATIONSHIP_UNGROUNDED; creating them is almost
    // always a CLI plumbing mistake). --allow-ungrounded keeps the old
    // verify-time failure for negative tests.
    if !cli.has("allow-ungrounded")
        && content.rel_type.requires_grounding()
        && content.evidence_ref.is_none()
        && content.attestation_ref.is_none()
    {
        return Err(format!(
            "`--type {}` is trust-relevant and requires grounding (--evidence-ref <evd:v1:…> and/or --attestation-ref <att:v1:…>); bare {} edges always fail at verify with RELATIONSHIP_UNGROUNDED — add backing or pass --allow-ungrounded for an intentional negative-test vector",
            content.rel_type.as_str(),
            content.rel_type.as_str()
        ));
    }
    let created = proof_crypto::build::make_relationship(content, &crate::limits())
        .map_err(|e| format!("relate: {e}"))?;
    let out = cli.req("out")?;
    write_json(
        &out,
        json!({
            "kind": "relationship",
            "id": created.id,
            "cbor": cbor_to_hex(&created.canonical),
        }),
    )?;
    crate::progress(cli.quiet(), &format!("relate  {} -> {out}", created.id));
    if !cli.quiet() {
        eprintln!(
            "  next: proof-cli build --kind <k> --subject <evt:id> --predicate <p> --created-at <u64> --events a.json,b.json --attestations c.json --evidence d.json --relationships {out} --out proof.json"
        );
    }
    Ok(created.id)
}

/// `revoke` / `supersede`: signed lifecycle status objects.
pub fn write_status_object(cli: &Cli, kind: &str) -> Result<String, String> {
    let key = crate::load_key_opt(cli)?;
    let at = cli.req_u64("at")?;
    let created = if kind == "revoke" {
        proof_crypto::build::revoke_attestation(
            &cli.req("target")?,
            cli.opt("reason").as_deref(),
            &key,
            at,
            &crate::limits(),
        )
    } else if kind == "withdraw" {
        proof_crypto::build::withdraw_attestation(
            &cli.req("target")?,
            cli.opt("reason").as_deref(),
            &key,
            at,
            &crate::limits(),
        )
    } else if kind == "compromise" {
        let at_time = cli.req_u64("compromised-at")?;
        proof_crypto::build::compromise_attestation(
            &cli.req("target")?,
            at_time,
            cli.opt("reason").as_deref(),
            &key,
            at,
            &crate::limits(),
        )
    } else {
        // Accepts --old/--new; --target/--successor are aliases (external
        // review: revoke uses --target, so supersede accepts it too).
        let old = cli
            .opt("old")
            .or_else(|| cli.opt("target"))
            .ok_or_else(|| "supersede: missing required flag --old (alias --target)".to_string())?;
        let new = cli
            .opt("new")
            .or_else(|| cli.opt("successor"))
            .ok_or_else(|| {
                "supersede: missing required flag --new (alias --successor)".to_string()
            })?;
        proof_crypto::build::supersede_attestation(&old, &new, &key, at, &crate::limits())
    }
    .map_err(|e| format!("{kind}: {e}"))?;
    let out = cli.req("out")?;
    write_json(
        &out,
        json!({
            "kind": "status",
            "id": created.id,
            "issuer": created.content.issuer,
            "claim_type": created.content.claim.claim_type,
            "cbor": cbor_to_hex(&created.canonical),
            "sign1_b64": proof_crypto::id::b64u_nopad(&created.sign1),
        }),
    )?;
    crate::progress(
        cli.quiet(),
        &format!("status  {} ({}) -> {out}", created.id, kind),
    );
    Ok(created.id)
}

/// Write a proof artifact: the whole canonical proof CBOR plus its id.
pub fn write_proof_file(path: &str, id: &str, canonical: &[u8]) -> Result<(), String> {
    write_json(
        path,
        json!({
            "kind": "proof",
            "id": id,
            "cbor": cbor_to_hex(canonical),
        }),
    )
}

// ---------------------------------------------------------------- loaders

/// Shape heuristic for fail-fast UX: `<prefix>:v1:<suffix>`.
/// Membership is NOT checked here (`relate` runs before the proof exists);
/// the pipeline remains the authority (DANGLING_REFERENCE at verify).
fn looks_like_artifact_id(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(p), Some("v1"), Some(rest)) => {
            matches!(p, "evt" | "att" | "evd" | "rel" | "prf") && !rest.is_empty()
        }
        _ => false,
    }
}

/// Any `xxx:vN:…` shape (mirrors `proof-graph` fail-closed rule): shaped ids
/// must resolve, never ride as asserted identity — even unknown versions.
fn looks_shaped(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(p), Some(v), Some(rest)) => {
            !p.is_empty()
                && !p.contains(' ')
                && !p.contains('/')
                && v.len() > 1
                && v.as_bytes()[0] == b'v'
                && v[1..].bytes().all(|b| b.is_ascii_digit())
                && !rest.is_empty()
        }
        _ => false,
    }
}

/// Free identity ref for EQUIVALENT endpoints: non-empty, no whitespace,
/// bounded length, and NOT shaped (shaped must resolve). Trust lives in the
/// required grounding attestation, never in the string.
fn is_free_identity_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.bytes().any(|b| b.is_ascii_whitespace())
        && !looks_shaped(s)
}

/// Digest hex (64 chars = SHA-256, 96 = SHA-384) → HashRef.
pub fn hash_ref_from_hex(s: &str) -> Result<proof_core::HashRef, String> {
    let d = hex::decode(s).map_err(|e| format!("bad digest hex: {e}"))?;
    let alg = match d.len() {
        32 => proof_core::HashAlgorithm::Sha256,
        48 => proof_core::HashAlgorithm::Sha384,
        _ => return Err("digest must be 64 (SHA-256) or 96 (SHA-384) hex chars".into()),
    };
    proof_core::HashRef::new(alg, d).map_err(|e| e.to_string())
}

/// Load + fully re-verify an event artifact. The file's `id`, if present,
/// must match the id recomputed from the bytes. `quiet` suppresses the
/// progress note (`--quiet` must silence all nonessential stderr).
// PE-CLI-002: re-verify on load; files are transport, never authority.
pub fn load_event(path: &str, limits: &Limits, quiet: bool) -> Result<EventContent, String> {
    let v = read_json(path)?;
    let bytes =
        hex::decode(req_str(&v, path, "cbor")?).map_err(|e| format!("{path}: bad hex: {e}"))?;
    let expect = opt_str(&v, path, "id")?;
    let (_, id) = proof_crypto::build::verify_event(&bytes, expect.as_deref(), limits)
        .map_err(|e: ProofError| format!("{path}: {e}"))?;
    let content = proof_format::schema::cbor_to_event(
        &proof_format::cbor::decode_strict(&bytes, limits).map_err(|e| format!("{path}: {e}"))?,
        limits,
    )
    .map_err(|e| format!("{path}: {e}"))?;
    if !quiet {
        eprintln!("loaded event {id} ({path})");
    }
    Ok(content)
}

/// Load + fully re-verify a signed attestation artifact: COSE envelope,
/// issuer binding, canonical bytes, payload agreement, and id binding.
/// `quiet` suppresses the progress note.
pub fn load_attestation(
    path: &str,
    limits: &Limits,
    quiet: bool,
) -> Result<CreatedAttestation, String> {
    let v = read_json(path)?;
    let bytes =
        hex::decode(req_str(&v, path, "cbor")?).map_err(|e| format!("{path}: bad hex: {e}"))?;
    let sign1 = proof_crypto::id::b64u_decode(&req_str(&v, path, "sign1_b64")?)
        .map_err(|e| format!("{path}: bad sign1_b64: {e}"))?;
    let issuer = opt_str(&v, path, "issuer")?.ok_or_else(|| format!("{path}: missing `issuer`"))?;
    let (content, id) = proof_crypto::build::verify_attestation(
        &sign1,
        &issuer,
        &proof_crypto::AllowedAlgs::strict(),
        limits,
    )
    .map_err(|e: ProofError| format!("{path}: {e}"))?;
    if let Some(expect) = opt_str(&v, path, "id")? {
        if expect != id {
            return Err(format!(
                "{path}: id mismatch (file says {expect}, bytes are {id})"
            ));
        }
    }
    // The standalone `cbor` field must be canonical and must describe the
    // same attestation the envelope authenticates.
    let value =
        proof_format::cbor::decode_strict(&bytes, limits).map_err(|e| format!("{path}: {e}"))?;
    if proof_format::cbor::encode_canonical(&value) != bytes {
        return Err(format!("{path}: attestation CBOR is not canonical"));
    }
    let content2 = proof_format::schema::cbor_to_attestation(&value, limits)
        .map_err(|e| format!("{path}: {e}"))?;
    if content2 != content {
        return Err(format!(
            "{path}: envelope payload does not match CBOR bytes"
        ));
    }
    if !quiet {
        eprintln!("loaded attestation {id} ({path})");
    }
    Ok(CreatedAttestation {
        content,
        canonical: bytes,
        id,
        sign1,
    })
}

/// Load + fully re-verify an evidence artifact.
/// `quiet` suppresses the progress note.
pub fn load_evidence(path: &str, limits: &Limits, quiet: bool) -> Result<Evidence, String> {
    let v = read_json(path)?;
    let bytes =
        hex::decode(req_str(&v, path, "cbor")?).map_err(|e| format!("{path}: bad hex: {e}"))?;
    let expect = opt_str(&v, path, "id")?;
    let (_, id) = proof_crypto::build::verify_evidence(&bytes, expect.as_deref(), limits)
        .map_err(|e: ProofError| format!("{path}: {e}"))?;
    let content = proof_format::schema::cbor_to_evidence(
        &proof_format::cbor::decode_strict(&bytes, limits).map_err(|e| format!("{path}: {e}"))?,
        limits,
    )
    .map_err(|e| format!("{path}: {e}"))?;
    if !quiet {
        eprintln!("loaded evidence {id} ({path})");
    }
    Ok(content)
}

/// Load + fully re-verify a relationship artifact.
/// `quiet` suppresses the progress note.
pub fn load_relationship(path: &str, limits: &Limits, quiet: bool) -> Result<Relationship, String> {
    let v = read_json(path)?;
    let bytes =
        hex::decode(req_str(&v, path, "cbor")?).map_err(|e| format!("{path}: bad hex: {e}"))?;
    let expect = opt_str(&v, path, "id")?;
    let (_, id) = proof_crypto::build::verify_relationship(&bytes, expect.as_deref(), limits)
        .map_err(|e: ProofError| format!("{path}: {e}"))?;
    let content = proof_format::schema::cbor_to_relationship(
        &proof_format::cbor::decode_strict(&bytes, limits).map_err(|e| format!("{path}: {e}"))?,
        limits,
    )
    .map_err(|e| format!("{path}: {e}"))?;
    if !quiet {
        eprintln!("loaded relationship {id} ({path})");
    }
    Ok(content)
}

/// Load a status artifact as a signed object (signature is verified here;
/// authority/trust decisions happen later in the pipeline).
/// `quiet` suppresses the progress note.
pub fn load_status(
    path: &str,
    limits: &Limits,
    quiet: bool,
) -> Result<proof_crypto::SignedStatus, String> {
    let v = read_json(path)?;
    let sign1 = proof_crypto::id::b64u_decode(&req_str(&v, path, "sign1_b64")?)
        .map_err(|e| format!("{path}: bad sign1_b64: {e}"))?;
    let issuer = req_str(&v, path, "issuer")?;
    // The file states who must have signed; the signature, the kid binding,
    // and the payload issuer are all checked against it inside (a mismatch
    // fails closed here, and authority is decided later by the pipeline).
    let content = proof_crypto::build::verify_status_object(
        &sign1,
        &issuer,
        &proof_crypto::AllowedAlgs::strict(),
        limits,
    )
    .map_err(|e: ProofError| format!("{path}: {e}"))?;
    if !quiet {
        // subject is attacker-controlled text; sanitize before the terminal
        // (external-review unsafe-logging finding).
        eprintln!(
            "loaded status {} ({path})",
            crate::sanitize(&content.subject)
        );
    }
    Ok(proof_crypto::SignedStatus { content, sign1 })
}

/// Comma/colon list helper for `build` inputs.
pub fn input_list(cli: &Cli, name: &str) -> Result<Vec<String>, String> {
    list(cli, name)
}

/// Optional list helper for `build --evidence` / `--relationships`.
/// Omitted flags mean zero members (no `--evidence ""` incantation needed;
/// the explicit empty string keeps working for scripts that already use it).
pub fn opt_input_list(cli: &Cli, name: &str) -> Result<Vec<String>, String> {
    opt_list(cli, name)
}
