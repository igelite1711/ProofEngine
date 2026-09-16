// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `graph`: visualize proof relationships in text, dot, or mermaid format.

use crate::Cli;
use std::collections::HashMap;

/// Graph a proof: display its relationships as a visual graph.
/// Accepts `-` for stdin, like `verify`.
pub fn graph(cli: &Cli) -> Result<String, String> {
    let proof_path = cli.proof_path()?;
    let (text, label) = crate::read_input_text(&proof_path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {label}: {e}"))?;

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

    // Build edges from relationships (sanitized: ids come from untrusted files).
    let mut edges: Vec<(String, String, String)> = Vec::new();
    for rel in &proof.relationships {
        edges.push((
            crate::sanitize(&rel.from),
            crate::sanitize(rel.rel_type.as_str()).to_string(),
            crate::sanitize(&rel.to),
        ));
    }

    let format = cli.opt("format").unwrap_or_else(|| "text".to_string());
    let subject = crate::sanitize(&proof.proposition.subject);
    let predicate = crate::sanitize(&proof.proposition.predicate);
    let out = match format.as_str() {
        "dot" => render_dot(&subject, &predicate, &edges),
        "mermaid" => render_mermaid(&subject, &predicate, &edges),
        other if other != "text" => {
            return Err(format!(
                "unknown --format `{other}` (expected text|dot|mermaid)"
            ))
        }
        _ => render_text(&subject, &predicate, &edges),
    };

    println!("{}", out);
    Ok(out)
}

/// Render graph as text (terminal-friendly ASCII art).
/// `pub(crate)` so the interactive demo reuses the same renderer.
pub(crate) fn render_text(
    subject: &str,
    predicate: &str,
    edges: &[(String, String, String)],
) -> String {
    if edges.is_empty() {
        return format!(
            r#"Proof Engine — Relationship Graph

Subject: {} → {}
No relationships found."#,
            subject, predicate
        );
    }

    let mut out = format!(
        r#"Proof Engine — Relationship Graph

Subject: {} → {}

Relationships:"#,
        subject, predicate
    );

    for (from, rel_type, to) in edges {
        out = format!(
            "{}
  {}
      │
    {}
      ↓
  {}",
            out, from, rel_type, to
        );
    }

    out
}

/// Escape a label for a double-quoted Graphviz string: backslashes and
/// quotes from untrusted proof content must not break out of the label.
pub fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Escape a label for Mermaid node/edge labels. `#` goes first so literal
/// entity-looking input stays literal; the rest use decimal entities.
pub fn mermaid_escape(s: &str) -> String {
    s.replace('#', "#35;")
        .replace('"', "#34;")
        .replace('|', "#124;")
        .replace('<', "#60;")
        .replace('>', "#62;")
        .replace('[', "#91;")
        .replace(']', "#93;")
        .replace('{', "#123;")
        .replace('}', "#125;")
}

/// Mermaid node id: alphanumerics and underscores only.
fn mermaid_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Render graph as Graphviz dot format.
fn render_dot(subject: &str, predicate: &str, edges: &[(String, String, String)]) -> String {
    let mut out = format!(
        r#"digraph Proof {{
    rankdir=TB;
    node [shape=box, style=filled, fillcolor=lightblue];
    subject [label="{} → {}"];
"#,
        dot_escape(subject),
        dot_escape(predicate)
    );

    let mut nodes: HashMap<String, bool> = HashMap::new();
    for (from, _, to) in edges {
        nodes.insert(from.clone(), true);
        nodes.insert(to.clone(), true);
    }

    for node in nodes.keys() {
        if node == subject {
            continue;
        }
        out = format!(
            "{}    \"{}\" [label=\"{}\"];
",
            out,
            dot_escape(node),
            dot_escape(node)
        );
    }

    for (from, rel_type, to) in edges {
        out = format!(
            "{}    \"{}\" -> \"{}\" [label=\"{}\", color=blue];
",
            out,
            dot_escape(from),
            dot_escape(to),
            dot_escape(rel_type)
        );
    }

    out = format!(
        "{}}}
",
        out
    );

    out
}

/// Render graph as Mermaid diagram.
fn render_mermaid(subject: &str, predicate: &str, edges: &[(String, String, String)]) -> String {
    let mut out = format!(
        r#"graph TD
    subject["{} → {}"]
"#,
        mermaid_escape(subject),
        mermaid_escape(predicate)
    );

    let mut nodes: HashMap<String, bool> = HashMap::new();
    for (from, _, to) in edges {
        nodes.insert(from.clone(), true);
        nodes.insert(to.clone(), true);
    }

    for node in nodes.keys() {
        if node == subject {
            continue;
        }
        out = format!(
            "{}    {}[\"{}\"]
",
            out,
            mermaid_id(node),
            mermaid_escape(node)
        );
    }

    for (from, rel_type, to) in edges {
        out = format!(
            "{}    {} -->|{}| {}
",
            out,
            mermaid_id(from),
            mermaid_escape(rel_type),
            mermaid_id(to)
        );
    }

    out
}
