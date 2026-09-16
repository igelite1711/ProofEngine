// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Human-first presentation layer (UX pass).
//!
//! Core principle: «The CLI must explain the result to a human before
//! exposing the implementation details that produced the result.»
//!
//! Three output levels:
//!   DEFAULT   — human answer (this module, concise layers)
//!   --verbose — explanation (translated stages, identifiers, feeds)
//!   --json    — machine contract (`check::report_json`; never routed here)
//!
//! Two semantic axes are ALWAYS shown separately and never collapsed into a
//! bare `RESULT VALID`: PROOF INTEGRITY (structural/cryptographic) and CLAIM
//! DECISION (adjudication). A proof can be intact while its claim stays
//! undecided — presentation must make that impossible to misread.
//!
//! Presentation ONLY: everything is derived from an existing `VerifyReport`
//! (plus the proposition the caller already loaded). No decision logic lives
//! here. Color never carries meaning (✓/⚠/✗ marks do); `use_color()` gates
//! decoration on TTY + NO_COLOR + TERM, and piped stdout stays plain.

use proof_core::model::Proposition;
use proof_verify::report::{CheckRecord, VerifyReport};

/// Marks carry the meaning (accessibility: never color alone).
pub const MARK_OK: &str = "✓";
pub const MARK_WARN: &str = "⚠";
pub const MARK_BAD: &str = "✗";

/// One rendered line of human output (colorized where applicable).
pub type Line = String;

/// Short proof id for the human layer: scheme + digest head, `…` tail.
/// Full ids stay available in verbose, inspect and JSON modes.
pub fn short_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= 24 {
        id.to_string()
    } else {
        let head: String = chars.iter().take(17).collect();
        format!("{head}…")
    }
}

/// Speak a claim element. `evt:` ids become `event <short-id>`; anything
/// else is sanitized as-is. We never invent semantics we do not have, so an
/// opaque subject stays an opaque (short) subject.
fn speak_element(raw: &str) -> String {
    let s = crate::sanitize(raw);
    if s.starts_with("evt:") {
        format!("event {}", short_id(&s))
    } else {
        s
    }
}

/// Claim-sentence rendering guard: only claims with a plain, identifier-ish
/// predicate become natural language; anything else falls back to the
/// precise structured line (`claim_fallback`). Never fabricate meaning the
/// proof does not carry.
pub fn claim_sentence(p: &Proposition) -> Option<String> {
    let predicate = crate::sanitize(&p.predicate);
    let speakable = !predicate.is_empty()
        && predicate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !speakable {
        return None;
    }
    let subject = speak_element(&p.subject);
    Some(match p.object.as_deref() {
        Some(obj) => format!("{subject} {predicate} {}", speak_element(obj)),
        None => format!("{subject} was {predicate}ed"),
    })
}

/// Fallback proposition line when the structure is not safely speakable.
pub fn claim_fallback(p: &Proposition) -> String {
    format!(
        "proposition kind `{}` about subject `{}` (predicate `{}`){}",
        crate::sanitize(&p.kind),
        crate::sanitize(&p.subject),
        crate::sanitize(&p.predicate),
        p.object
            .as_deref()
            .map(|o| format!(" with object `{}`", crate::sanitize(o)))
            .unwrap_or_default()
    )
}

/// Integrity axis: (mark, label). Reuses the frozen verdict-kind logic
/// (`check::verdict_kind`) plus the strict-mode overlay so presentation
/// never invents a verdict of its own.
pub fn integrity_axis(report: &VerifyReport, strict_fail: bool) -> (&'static str, &'static str) {
    if strict_fail {
        return (
            MARK_BAD,
            "INVALID (historically valid, not currently acceptable)",
        );
    }
    match crate::check::verdict_kind(report) {
        crate::check::VerdictKind::Valid => (MARK_OK, "VALID"),
        crate::check::VerdictKind::Historical => {
            (MARK_OK, "HISTORICALLY_VALID (not currently acceptable)")
        }
        crate::check::VerdictKind::Invalid => (MARK_BAD, "INVALID"),
    }
}

/// Decision axis: (mark, label). What the claim adjudication did (or did
/// not do). Pipeline `verify` never decides (policy INDETERMINATE by
/// design); `evaluate`/`explain` with a policy may reach ACCEPTED/REJECTED.
pub fn decision_axis(decision: proof_verify::PolicyDecision) -> (&'static str, &'static str) {
    match decision {
        proof_verify::PolicyDecision::Indeterminate => (MARK_WARN, "NOT EVALUATED"),
        proof_verify::PolicyDecision::Pass => (MARK_OK, "ACCEPTED"),
        proof_verify::PolicyDecision::Fail => (MARK_BAD, "REJECTED"),
    }
}

/// Overlay the real policy decision onto a pipeline report copy for
/// presentation. Pipeline reports carry `policy_decision: INDETERMINATE` by
/// design (the pipeline never adjudicates), but `evaluate`/`explain` DID
/// evaluate — their human summary must say ACCEPTED/REJECTED, never
/// NOT EVALUATED. Returns a copy; the machine JSON path is never touched.
pub fn with_decision(
    report: &VerifyReport,
    decision: proof_verify::PolicyDecision,
) -> VerifyReport {
    let mut r = report.clone();
    r.policy_decision = decision;
    r
}

/// Render the concise human summary (Layer 1 + optional Layer 2 tail).
///
/// Layer order is fixed: ANSWER → CLAIM → EVIDENCE/CONFLICT → WHY → CHECKS
/// → PROOF → STATUS → NEXT STEP. All content is derived from the report and
/// proposition; nothing here re-decides anything. `verbose` adds the
/// translated stage list and identifiers (Layer 2); `--json` never routes
/// here, so the machine contract cannot be perturbed by presentation.
pub fn emit_summary(report: &VerifyReport, strict_fail: bool, verbose: bool) {
    emit_summary_claimed(report, None, strict_fail, verbose);
}

/// Full renderer with the optional CLAIM layer. `verify`/`explain` already
/// loaded the proof, so they pass its proposition; claims are spoken only
/// when the structure is safe (see `claim_sentence`), otherwise the precise
/// structured fallback is used. `None` → CLAIM block omitted, never fabricated.
pub fn emit_summary_claimed(
    report: &VerifyReport,
    proposition: Option<&Proposition>,
    strict_fail: bool,
    verbose: bool,
) {
    let mut out: Vec<Line> = Vec::new();
    let id = report.proof_id.as_deref().unwrap_or("?");

    // --- Layer 1: the answer, both axes, never collapsed ---
    let (integrity_mark, integrity_label) = integrity_axis(report, strict_fail);
    let (decision_mark, decision_label) = decision_axis(report.policy_decision);
    let integrity_ok =
        !integrity_label.starts_with("INVALID") && !integrity_label.starts_with("HISTORICAL");
    out.push(crate::color_mark(
        integrity_mark,
        &format!("PROOF INTEGRITY: {integrity_label}"),
    ));
    out.push(crate::color_mark(
        decision_mark,
        &format!("CLAIM DECISION: {decision_label}"),
    ));
    if integrity_ok {
        out.push(
            "The proof is cryptographically intact and its evidence is bound to it.".to_string(),
        );
    } else {
        out.push("The proof failed verification; details below.".to_string());
    }
    match decision_label {
        "NOT EVALUATED" => out.push(
            "No claim decision was made (no policy was applied). A valid proof is not automatically a true claim; use `evaluate` with a policy to decide.".to_string(),
        ),
        "ACCEPTED" => out.push("Policy accepted the claim.".to_string()),
        "REJECTED" => out.push("Policy rejected the claim.".to_string()),
        _ => {}
    }

    // --- CLAIM (natural language when safe; structured fallback otherwise) ---
    if let Some(p) = proposition {
        out.push(String::new());
        out.push("CLAIM".to_string());
        if let Some(sentence) = claim_sentence(p) {
            out.push(format!("  {sentence}."));
        } else {
            out.push(format!("  {}", claim_fallback(p)));
        }
        if verbose {
            out.push(format!(
                "  kind: {}  subject: {}",
                crate::sanitize(&p.kind),
                crate::sanitize(&p.subject)
            ));
        }
    }

    summary_evidence_block(report, &mut out);
    summary_why_block(report, integrity_ok, &mut out);
    summary_checks_block(report, verbose, id, &mut out);
    summary_status_block(report, integrity_ok, decision_label, &mut out);
    for line in out {
        eprintln!("{line}");
    }
}

/// EVIDENCE layer: concise counts (no raw ids) + conflicts as a distinct
/// semantic state with the mandatory integrity/decision explanation.
fn summary_evidence_block(report: &VerifyReport, out: &mut Vec<Line>) {
    let n_att = report
        .checks
        .iter()
        .filter(|c| c.stage == "SIGNATURES" && c.object.starts_with("att:"))
        .count();
    let n_evd = report
        .checks
        .iter()
        .filter(|c| c.stage == "EVIDENCE" && c.object.starts_with("evd:"))
        .count();
    if n_att == 0 && n_evd == 0 && report.conflicts.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("EVIDENCE".to_string());
    if n_att > 0 {
        out.push(format!("  {n_att} attestation(s) checked."));
    }
    if n_evd > 0 {
        out.push(format!("  {n_evd} evidence item(s) checked."));
    }
    for c in &report.conflicts {
        out.push(format!(
            "  {} CONFLICTING CLAIMS — {}",
            crate::yellow(MARK_WARN),
            conflict_human(c)
        ));
        out.push(
            "    This does NOT mean the proof is corrupted. Both statements verified; which one to accept is a policy question.".to_string(),
        );
    }
}

/// WHY layer: concise, human-phrased reasons (verbose mode expands below).
fn summary_why_block(report: &VerifyReport, integrity_ok: bool, out: &mut Vec<Line>) {
    let why = why_lines(report, integrity_ok);
    if why.is_empty() {
        return;
    }
    out.push(String::new());
    out.push("WHY".to_string());
    for w in why {
        out.push(format!("  • {w}"));
    }
}

/// CHECKS + PROOF layer. Default: one tally line + short id. Verbose: the
/// translated per-stage list, identifiers, and feed/vocabulary details.
fn summary_checks_block(report: &VerifyReport, verbose: bool, id: &str, out: &mut Vec<Line>) {
    let total = report.checks.len();
    let pass = report.checks.iter().filter(|c| c.ok).count();
    if total > 0 {
        out.push(String::new());
        let tally = if pass == total {
            crate::green(&format!("{pass}/{total} checks passed"))
        } else {
            crate::red(&format!("{pass}/{total} checks passed"))
        };
        out.push(format!("VERIFICATION  {tally}"));
    }
    if verbose {
        out.push("Stages:".to_string());
        for c in &report.checks {
            let mark = if c.ok {
                crate::green(MARK_OK)
            } else {
                crate::red(MARK_BAD)
            };
            out.push(format!(
                "  {mark} {} — {}",
                stage_human(c),
                crate::sanitize(&c.message)
            ));
        }
        out.push(format!("  proof id: {id}"));
        if !report.withdrawn_ids.is_empty() {
            out.push(format!(
                "  withdrawn ids: {}",
                report.withdrawn_ids.join(", ")
            ));
        }
        if !report.status_objects.is_empty() {
            out.push(format!("  status objects: {}", report.status_objects.len()));
        }
        for v in &report.vocabularies {
            out.push(format!("  vocabulary: {} @ {}", v.ns, v.version));
        }
    } else {
        out.push(format!("  Proof: {}", short_id(id)));
    }
}

/// STATUS + NEXT layer: every summary ends with the state in words and what
/// to do next. Exit codes and JSON output remain exactly as before.
fn summary_status_block(
    report: &VerifyReport,
    integrity_ok: bool,
    decision_label: &str,
    out: &mut Vec<Line>,
) {
    out.push(String::new());
    out.push(format!(
        "STATUS  {} • {}",
        integrity_human_word(integrity_ok),
        decision_human_word(decision_label)
    ));
    if decision_label == "NOT EVALUATED" && integrity_ok {
        out.push(
            "NEXT    run `proof-cli evaluate --policy <file> …` to decide the claim (or `explain` for reasoning).".to_string(),
        );
    } else if !integrity_ok && !report.failure_codes().is_empty() {
        out.push(
            "NEXT    see the failed checks above; `proof-cli explain --policy <file> …` gives the full reasoning.".to_string(),
        );
    }
}

/// Translate a conflict record into one human sentence.
fn conflict_human(c: &proof_verify::report::ConflictRecord) -> String {
    let what = if c.subject.is_empty() {
        format!("about claim type `{}`", crate::sanitize(&c.claim_type))
    } else {
        format!(
            "about `{}` (claim type `{}`)",
            crate::sanitize(&c.subject),
            crate::sanitize(&c.claim_type)
        )
    };
    match c.kind {
        proof_verify::report::ConflictKind::DivergentClaims => {
            format!("two or more verified attestations disagree {what}.")
        }
        proof_verify::report::ConflictKind::Denial => {
            format!("one verified statement denies another {what}.")
        }
        proof_verify::report::ConflictKind::Contradiction => {
            format!("a verified contradiction edge connects the statements {what}.")
        }
    }
}

/// Translate stage vocabulary into human phrasing. Raw stage names remain
/// available in JSON and `--verbose` keeps the mapping visible.
fn stage_human(c: &CheckRecord) -> String {
    match c.stage {
        "PARSE" => "structure",
        "SCHEMA" => "schema",
        "CANONICAL" => "canonical encoding",
        "IDENTIFIERS" => "identifiers",
        "SIGNATURES" => "signatures",
        "KEYS" => "signing keys",
        "TIME" => "time validity",
        "REVOCATION" => "revocation",
        "STATUS" => "status feed",
        "EVIDENCE" => "evidence",
        "RELATIONSHIPS" => "relationships",
        "GRAPH" => "provenance graph",
        "VOCABULARY" => "vocabularies",
        "POLICY" => "policy",
        other => other,
    }
    .to_string()
}

/// Concise WHY reasons, human phrasing, derived only from report facts.
fn why_lines(report: &VerifyReport, integrity_ok: bool) -> Vec<String> {
    let mut why = Vec::new();
    if !integrity_ok {
        for f in report.failure_codes() {
            let human = match f.as_str() {
                "ID_MISMATCH" => "the wrapper's id does not match the id bound in the bytes (tampered or mixed-up files).",
                "SIGNATURE_INVALID" => "a digital signature did not verify.",
                "EXPIRED" => "an attestation's validity window had ended at the verification clock.",
                "REVOKED" => "a valid signed revocation covers this proof.",
                "COMPROMISED" => "a signing key was reported compromised.",
                "WITHDRAWN" => "the backing evidence was withdrawn.",
                "REVOCATION_UNKNOWN" => "no revocation information was supplied, so current status could not be established (fail closed).",
                "MALFORMED" => "the proof file could not be read as a proof (truncated, corrupted, or not proof content).",
                "SCHEMA_VIOLATION" => "the proof's structure does not follow the required schema.",
                "NON_CANONICAL" => "the proof's encoding is not the required canonical form.",
                "UNSUPPORTED_VERSION" => "the proof uses a version this engine does not support.",
                "LIMIT_EXCEEDED" => "the proof exceeds a size or complexity limit.",
                "CYCLE_DETECTED" => "the proof's provenance graph contains a forbidden cycle.",
                other => other,
            };
            why.push(human.to_string());
        }
    }
    for c in &report.conflicts {
        why.push(format!("conflicting evidence: {}", conflict_human(c)));
    }
    if !report.status_inputs_valid {
        why.push(
            "the status feed itself had errors (proof validity unaffected; feed quality did not)."
                .to_string(),
        );
    }
    why
}

/// One-word human status for the integrity axis.
fn integrity_human_word(integrity_ok: bool) -> &'static str {
    if integrity_ok {
        "valid proof"
    } else {
        "invalid proof"
    }
}

/// One-word human status for the decision axis.
fn decision_human_word(label: &str) -> &'static str {
    match label {
        "ACCEPTED" => "claim accepted",
        "REJECTED" => "claim rejected",
        _ => "claim undecided",
    }
}
