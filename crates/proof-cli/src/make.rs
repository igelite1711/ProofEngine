// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Creation commands: build artifacts and assemble/verify proofs.
//! Every command re-derives ids and signatures through the library crates;
//! this module contains no trust logic of its own.

use crate::artifact::{
    input_list, load_attestation, load_event, load_evidence, load_relationship, load_status,
};
use crate::Cli;
use proof_core::model::Proposition;
use proof_crypto::build::{CreatedEvent, CreatedEvidence, CreatedRelationship};
use proof_verify::builder::ProofBuilder;

fn created_event(content: proof_core::model::EventContent) -> Result<CreatedEvent, String> {
    proof_crypto::build::create_event(content, &crate::limits()).map_err(|e| e.to_string())
}

fn created_evidence(content: proof_core::model::Evidence) -> Result<CreatedEvidence, String> {
    proof_crypto::build::make_evidence(
        content.kind,
        content.digest.clone(),
        content.attestation_ref,
        content.hint,
        &crate::limits(),
    )
    .map_err(|e| e.to_string())
}

fn created_relationship(
    content: proof_core::model::Relationship,
) -> Result<CreatedRelationship, String> {
    proof_crypto::build::make_relationship(content, &crate::limits()).map_err(|e| e.to_string())
}

/// `build`: assemble proof artifacts into a canonical, id-bound proof file.
/// Topology validation (grounding, dangling refs) is proof-graph's job and
/// runs inside `ProofBuilder::build` — the CLI adds nothing on top.
pub fn build(cli: &Cli) -> Result<String, String> {
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
    let quiet = cli.quiet();
    let mut b = ProofBuilder::new(proposition, cli.req_u64("created-at")?);
    for path in input_list(cli, "events")? {
        let content = load_event(&path, &crate::limits(), quiet)?;
        b.add_event(created_event(content)?);
    }
    for path in input_list(cli, "attestations")? {
        b.add_attestation(load_attestation(&path, &crate::limits(), quiet)?);
    }
    for path in input_list(cli, "evidence")? {
        let content = load_evidence(&path, &crate::limits(), quiet)?;
        b.add_evidence(created_evidence(content)?);
    }
    for path in input_list(cli, "relationships")? {
        let content = load_relationship(&path, &crate::limits(), quiet)?;
        b.add_relationship(created_relationship(content)?);
    }
    let built = b
        .build(&crate::limits())
        .map_err(|e| format!("build: {e}"))?;
    let out = cli.req("out")?;
    crate::artifact::write_proof_file(&out, &built.id, &built.canonical)?;
    // `--out -` streams the proof JSON on stdout: keep stdout pure by moving
    // the progress note to stderr.
    if out == "-" {
        eprintln!("proof   {} -> stdout", built.id);
    } else {
        println!("proof   {} -> {out}", built.id);
    }
    Ok(built.id)
}

/// Flags shared by verify/evaluate/explain: an explicit clock is mandatory —
/// the CLI never reads the wall clock (PROPOSAL rule 4).
pub struct CommonInputs {
    pub verified_at: u64,
    pub skew: u64,
    pub revocations_known_at: Option<u64>,
}

// PE-CLI-003: explicit clock mandatory; wall clock never read.
pub fn common(cli: &Cli) -> Result<CommonInputs, String> {
    Ok(CommonInputs {
        verified_at: cli.req_u64("clock")?,
        skew: cli
            .opt("skew")
            .map(|v| v.parse().map_err(|_| "--skew must be a u64".to_string()))
            .transpose()?
            .unwrap_or(300),
        revocations_known_at: cli.opt_u64("revocations-known-at")?,
    })
}

/// Verifier-policy flags shared by verify/evaluate/batch-verify/resolve.
/// Previously the CLI hardcoded `..Default::default()` here, pinning every
/// run to Ed25519-only + fail-fast + no vocab notes. Now the full
/// `VerifyCtx` surface is reachable:
/// `--esp256`, `--historical`, `--report-all`,
/// `--accepted-vocab ns:max,...` (repeatable),
/// `--extra-grounded TYPE,...` (repeatable).
pub struct VerifierPolicy {
    pub allowed_algs: proof_crypto::AllowedAlgs,
    pub report_all_failures: bool,
    pub accepted_vocabularies: Vec<proof_core::model::VocabularyAccept>,
    pub extra_grounded: Vec<String>,
}

pub fn verifier_policy(cli: &Cli) -> Result<VerifierPolicy, String> {
    let mut allowed = proof_crypto::AllowedAlgs::strict();
    if cli.has("esp256") {
        allowed = allowed.with_esp256();
    }
    if cli.has("historical") || cli.has("allow-deprecated") {
        allowed = allowed.with_deprecated();
    }
    let mut accepted_vocabularies = vec![];
    for item in cli.many("accepted-vocab") {
        for entry in item.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (ns, max) = entry.split_once(':').ok_or_else(|| {
                "--accepted-vocab must be ns:max_version (e.g. `acme:2`), got `{entry}`".to_string()
            })?;
            let ns = ns.trim();
            if ns.is_empty() {
                return Err("--accepted-vocab namespace must not be empty".to_string());
            }
            let max_version: u64 = max
                .trim()
                .parse()
                .map_err(|_| format!("--accepted-vocab max_version must be u64, got `{max}`"))?;
            accepted_vocabularies.push(proof_core::model::VocabularyAccept {
                ns: ns.to_string(),
                max_version,
            });
        }
    }
    let mut extra_grounded = vec![];
    for item in cli.many("extra-grounded") {
        extra_grounded.extend(
            item.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    Ok(VerifierPolicy {
        allowed_algs: allowed,
        report_all_failures: cli.has("report-all"),
        accepted_vocabularies,
        extra_grounded,
    })
}

/// All trust inputs are explicit flags; nothing is guessed from the proof.
pub fn eval_inputs(cli: &Cli, c: &CommonInputs) -> proof_policy::EvalInputs {
    let mut revoked: Vec<String> = vec![];
    for item in cli.many("revoked") {
        revoked.extend(item.split(',').map(str::to_string));
    }
    proof_policy::EvalInputs {
        trusted_issuers: cli.many("trusted"),
        revocations: proof_policy::RevocationSet::new(revoked),
        verified_at: c.verified_at,
        skew_leeway: c.skew,
    }
}

/// `verify`: run the 10-stage pipeline. Authority keyrefs must be supplied
/// explicitly via --authority; revocation status objects via --status.
/// stdout = JSON report (machine contract); stderr = human summary.
pub fn verify(cli: &Cli) -> Result<i32, String> {
    let proof = crate::check::load_proof(&cli.proof_path()?, cli.quiet())?;
    let c = common(cli)?;
    let vp = verifier_policy(cli)?;
    let statuses: Vec<proof_crypto::SignedStatus> = cli
        .many("status")
        .iter()
        .map(|p| load_status(p, &crate::limits(), cli.quiet()))
        .collect::<Result<_, _>>()?;
    let authorities = cli.many("authority");
    let report = proof_verify::verify_proof(
        &proof.canonical,
        &proof_verify::VerifyCtx {
            verified_at: c.verified_at,
            clock_skew_leeway: c.skew,
            trusted_issuers: cli.many("trusted"),
            status_objects: statuses,
            revocation_authorities: authorities,
            revocations_known_at: c.revocations_known_at,
            allowed_algs: vp.allowed_algs,
            report_all_failures: vp.report_all_failures,
            accepted_vocabularies: vp.accepted_vocabularies,
            extra_grounded: vp.extra_grounded,
            ..Default::default()
        },
    )
    .map_err(|e| format!("verify: {e}"))?;
    // Fail-closed UX: lifecycle UNKNOWN (no --revocations-known-at) is the
    // #1 first-run surprise. The pipeline is correct to fail closed; add the
    // re-run hint on stderr so machine-readable stdout stays pure.
    if c.revocations_known_at.is_none()
        && report
            .lifecycle
            .iter()
            .any(|l| l.status == proof_core::LifecycleStatus::Unknown)
    {
        eprintln!(
            "hint: lifecycle UNKNOWN — no revocation info supplied; if your revocation info is fresh, re-run with `--revocations-known-at {}` (must be within --skew of --clock)",
            c.verified_at
        );
    }
    crate::check::emit_report(&report, cli.opt("out"), cli.quiet())?;
    if !cli.quiet() {
        crate::check::emit_human_summary(&report);
    }
    Ok(crate::check::verdict_exit(&report))
}

/// `batch-verify`: verify many proofs under one shared context (scale track).
/// Each member verifies independently with identical semantics to `verify`;
/// batching amortizes invocation overhead only. Exit 0 iff every member is
/// crypto-Valid and evidence-Valid; exit 1 otherwise; exit 2 on usage/engine
/// errors. Policy stays per-proof and caller-side, as always.
pub fn batch_verify(cli: &Cli) -> Result<i32, String> {
    use crate::artifact::input_list;
    let paths = input_list(cli, "proofs")?;
    if paths.is_empty() {
        return Err("batch-verify: missing --proofs a.json,b.json".to_string());
    }
    let c = common(cli)?;
    let statuses: Vec<proof_crypto::SignedStatus> = cli
        .many("status")
        .iter()
        .map(|p| load_status(p, &crate::limits(), cli.quiet()))
        .collect::<Result<_, _>>()?;
    let authorities = cli.many("authority");
    let max_batch: usize = cli
        .opt("max-batch")
        .map(|v| {
            v.parse()
                .map_err(|_| "--max-batch must be a u64".to_string())
        })
        .transpose()?
        .unwrap_or(256);
    let mut canonicals = Vec::with_capacity(paths.len());
    for path in &paths {
        let proof = crate::check::load_proof(path, cli.quiet())?;
        canonicals.push(proof.canonical);
    }
    let vp = verifier_policy(cli)?;
    let rep = proof_verify::verify_batch(
        &canonicals,
        &proof_verify::VerifyCtx {
            verified_at: c.verified_at,
            clock_skew_leeway: c.skew,
            trusted_issuers: cli.many("trusted"),
            status_objects: statuses,
            revocation_authorities: authorities,
            revocations_known_at: c.revocations_known_at,
            allowed_algs: vp.allowed_algs,
            report_all_failures: vp.report_all_failures,
            accepted_vocabularies: vp.accepted_vocabularies,
            extra_grounded: vp.extra_grounded,
            ..Default::default()
        },
        max_batch,
    )
    .map_err(|e| format!("batch-verify: {e}"))?;
    let v = serde_json::json!({
        "complete": rep.complete(paths.len()),
        "all_valid": rep.all_valid(),
        "crypto_valid_count": rep.crypto_valid_count,
        "evidence_valid_count": rep.evidence_valid_count,
        "members": rep.members.iter().map(|m| serde_json::json!({
            "index": m.index,
            "proof_id": m.report.proof_id,
            "cryptographic_validity": format!("{:?}", m.report.cryptographic_validity),
            "evidence_validity": format!("{:?}", m.report.evidence_validity),
            "codes": m.report.failure_codes().iter().map(|c| format!("{c:?}")).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    });
    match cli.opt("out") {
        None => println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        ),
        Some(path) => crate::artifact::write_json(&path, v)?,
    }
    if !cli.quiet() {
        eprintln!(
            "batch: {}/{} crypto-valid, {}/{} evidence-valid",
            rep.crypto_valid_count,
            rep.members.len(),
            rep.evidence_valid_count,
            rep.members.len()
        );
    }
    Ok(if rep.all_valid() {
        crate::EXIT_OK
    } else {
        crate::EXIT_FAIL
    })
}

/// `evaluate` / `explain`: pipeline + declarative policy over its output.
// PE-CLI-006: explain prints prose only, never JSON over prose.
pub fn evaluate(cli: &Cli, explain: bool) -> Result<i32, String> {
    let proof = crate::check::load_proof(&cli.proof_path()?, cli.quiet())?;
    let c = common(cli)?;
    let policy_path = cli.req("policy")?;
    let policy_text =
        crate::read_input_file(&policy_path).map_err(|e| format!("read policy: {e}"))?;
    // Fail fast on un-substituted example placeholders (the classic
    // `key:ed25519:key:ed25519:…` footgun comes from sed-replacing the whole
    // `key:ed25519:REPLACE_WITH_YOUR_ISSUER_KEY` string with the full issuer
    // instead of just the suffix — see examples/policies/README.md).
    if policy_text.contains("REPLACE_WITH") {
        return Err(format!(
            "{policy_path}: still contains a REPLACE_WITH placeholder; replace only the suffix after `key:ed25519:` with your issuer's key id (e.g. `key:ed25519:<id-from-attest>`), keeping the `key:ed25519:` prefix exactly once"
        ));
    }
    let policy_val: serde_json::Value =
        serde_json::from_str(&policy_text).map_err(|e| format!("parse policy: {e}"))?;
    let policy = proof_policy::parse_policy(&policy_val, &crate::limits())
        .map_err(|e| format!("policy: {e}"))?;
    let statuses: Vec<proof_crypto::SignedStatus> = cli
        .many("status")
        .iter()
        .map(|p| load_status(p, &crate::limits(), cli.quiet()))
        .collect::<Result<_, _>>()?;
    let vp = verifier_policy(cli)?;
    let report = proof_verify::verify_proof(
        &proof.canonical,
        &proof_verify::VerifyCtx {
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
            ..Default::default()
        },
    )
    .map_err(|e| format!("verify: {e}"))?;
    let state = proof_policy::state_from_report_and_proof(&report, &proof.proof)
        .map_err(|e| format!("state: {e}"))?;
    let outcome = proof_policy::evaluate_policy(&state, &policy, &eval_inputs(cli, &c));
    // Same UNKNOWN-lifecycle hint as `verify` (stderr only, stdout stays pure).
    if c.revocations_known_at.is_none()
        && report
            .lifecycle
            .iter()
            .any(|l| l.status == proof_core::LifecycleStatus::Unknown)
    {
        eprintln!(
            "hint: lifecycle UNKNOWN — no revocation info supplied; if your revocation info is fresh, re-run with `--revocations-known-at {}` (must be within --skew of --clock)",
            c.verified_at
        );
    }
    // Report emission: `evaluate` prints JSON to stdout unless --out is
    // given; `explain` never dumps JSON on top of the prose (file via --out
    // is still honored).
    // Report emission: prose mode keeps the historical stdout report (then
    // the decision text below); `--json` owns stdout exclusively so stdout is
    // one script-parsable document; `--out` always writes the report file and
    // `explain` never mixes JSON with prose (PE-CLI-006).
    let json_mode = cli.has("json") && !explain;
    match (explain, cli.opt("out")) {
        (false, Some(path)) => crate::check::emit_report(&report, Some(path), cli.quiet())?,
        (false, None) if json_mode => {}
        (false, None) => crate::check::emit_report(&report, None, cli.quiet())?,
        (true, Some(path)) => crate::check::emit_report(&report, Some(path), cli.quiet())?,
        (true, None) => {}
    }
    if explain {
        print!(
            "{}{}",
            proof_policy::explain_policy(&policy),
            proof_policy::explain_full(&report, &outcome)
        );
    } else if cli.has("json") {
        // PE-CLI-007: machine-readable policy decision. Same exit-code
        // contract as prose mode; `explain` never takes this path (PE-CLI-006).
        let merged = serde_json::json!({
            "policy_outcome": crate::check::outcome_json(&outcome),
            "report": crate::check::report_json(&report),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())?
        );
        if !cli.quiet() {
            crate::check::emit_human_summary(&report);
        }
    } else {
        // Prose mode: INDETERMINATE means "no decision made" (proof-side
        // preconditions unmet), NOT "decided no". Say so explicitly, plus the
        // exit-code meaning, so `decision indeterminate` is never misread.
        if outcome.decision == proof_verify::PolicyDecision::Indeterminate {
            println!(
                "decision indeterminate (no decision made — proof invalid or report/proof mismatch; requirements neither satisfied nor refuted{})",
                outcome
                    .note
                    .as_deref()
                    .map_or_else(String::new, |n| format!(": {n}"))
            );
        } else {
            println!("decision {}", outcome.decision.as_str());
        }
        for r in &outcome.results {
            println!(
                "  [{}] {} — {}",
                if r.passed { "ok" } else { "NO" },
                r.requirement,
                r.message
            );
        }
        eprintln!("exit 1 = FAIL/INDETERMINATE verdict (0 = PASS, 2 = usage/engine error)");
    }
    Ok(match outcome.decision {
        proof_verify::PolicyDecision::Pass => crate::EXIT_OK,
        proof_verify::PolicyDecision::Fail | proof_verify::PolicyDecision::Indeterminate => {
            crate::EXIT_FAIL
        }
    })
}
