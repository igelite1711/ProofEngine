# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Proof Engine neutrality gate (capability CAP-006; ids PE-NEUT-001,
PE-NEUT-002, PE-NEUT-004; the constructive proof is PE-NEUT-003 in
domains/proof-domains; the capability spec is PE-NEUT-005,
docs/capability-map.md).

Rules (all must hold, else exit != 0):

  1. Mechanism crate sources (crates/*/src, non-test) MUST NOT use domain
     vocabulary as logic: payment, invoice, merchant, credential, identity,
     license, media, deepfake, transcode, ai/llm/prompt, patient, shipment,
     student, employee, loan, insurance, ...

  2. Exempt by design (documented in docs/NEUTRALITY.md, docs/domains/README.md):
     - crates/proof-core/src/model.rs   -> the closed-vocabulary tables
       (wire labels, VERSIONING.md: churning them risks interop for zero
       mechanism gain; they are data, not logic).
     - crates/proof-cli/src/demo.rs     -> the V1 reference application
       (killer use-case; everything else in proof-cli is scanned).
     - `#[cfg(test)]` modules, `mod tests`, `mod fixtures`, `mod golden` blocks
       -> tests/fixtures are the sanctioned home of domain vocabulary
          (rule 3 of docs/NEUTRALITY.md).

  3. Domain vocabulary may otherwise appear only in tests, fixtures, demos,
     and docs/domains/ - never as code paths in mechanism crates.

  4. The constructive proof of neutrality (PE-NEUT-003) is the domain
     differential test at domains/proof-domains/tests/: the same core
     must carry three unrelated domains to identical verdict shapes.

Stdlib only.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATES = os.path.join(ROOT, "crates")

# Domain-bearing tokens (word-boundary, case-insensitive). Deliberately a
# curated, conservative lexicon: mechanism code must hit NONE of these outside
# the exemptions above.
TOKENS = [
    # Payment domain
    "payment", "invoice", "merchant", "acquirer", "chargeback",
    # Identity / credential domain
    "credential", "idp", "identity_provider",
    # Media / licensing domain
    "license", "licens", "media", "deepfake", "transcode", "broadcast",
    "newsroom", "studio", "video", "streaming",
    # AI-action domain (bare "ai" is excluded: it collides with CBOR's
    # additional-information field; fingerprints below are AI-domain strings)
    "ai.action", "tool_call", "toolcall", "llm", "neural", "prompt",
    # Other verticals the core must never know about
    "patient", "shipment", "student", "employee", "loan", "insurance",
    "healthcare", "sensor",
]

# Closed-vocabulary tables + the V1 reference demo app (NEUTRALITY 2.b).
EXEMPT_BASENAMES = {"model.rs", "demo.rs"}

# Module kinds whose blocks are test/fixture material (downstream domains).
SKIP_MOD = re.compile(r"^\s*(pub\s+)?mod\s+(tests|fixtures|golden|goldens)")
CFG_TEST = re.compile(r"^\s*#\s*\[cfg\(test\)\]")
WORD = re.compile(r"(" + "|".join(TOKENS) + r")", re.IGNORECASE)


def stripped_lines(path):
    """Yield (lineno, text) with exempt test/fixture/golden blocks removed.

    `#[cfg(test)]`, `mod tests`, `mod fixtures`, and `mod golden*` blocks are
    brace-balanced and dropped whole. Declaration/attribute lines are dropped
    too (their bodies never count as mechanism code).
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.strip()
        if CFG_TEST.match(line) or SKIP_MOD.match(line):
            depth = line.count("{") - line.count("}")
            i += 1
            # A mod declaration on the same line as its brace owns no block;
            # the depth count handles `mod tests {` (depth=1) correctly.
            while i < n and depth > 0:
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            continue
        out.append((i + 1, raw))
        i += 1
    return out


def scan_file(path):
    hits = []
    if os.path.basename(path) in EXEMPT_BASENAMES:
        return hits
    for lineno, raw in stripped_lines(path):
        if raw is None:
            continue
        if WORD.search(raw):
            hits.append((lineno, raw.strip()))
    return hits


def main():
    errors = []
    scanned = 0
    for base, _, files in os.walk(CRATES):
        # Mechanism sources live only under <crate>/src/.
        if os.path.basename(base) != "src":
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(base, f)
            rel = os.path.relpath(p, ROOT)
            hits = scan_file(p)
            scanned += 1
            for lineno, text in hits:
                errors.append(f"{rel}:{lineno}: {text}")
    if errors:
        print(f"NEUTRALITY GATE FAILED: {len(errors)} domain-vocabulary hit(s):")
        for e in errors:
            print("  -", e)
        print("  -> docs/NEUTRALITY.md rules 2.b/3; keep domain words in tests/fixtures/docs.")
        return 1
    print(f"neutrality OK: {scanned} mechanism source file(s), zero domain vocab (PE-NEUT-001)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
