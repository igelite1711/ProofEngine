# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Machine-checked requirement traceability (Gate C1).

Rules (all must hold, else exit != 0):
  1. Every PE-XXX-NNN id in docs/requirements-matrix.md appears in code
     (crates/, fuzz/, tools/, interop/, Makefile, deny.toml, workflows, manifests).
  2. Every PE-XXX-NNN id in scanned code appears in the matrix.
  3. Every matrix row resolves at least one test reference:
       `mod::symbol` -> `fn|mod|struct|enum symbol` exists under crates/
       `fuzz::target` -> fuzz/fuzz_targets/target.rs exists
       existing relative path (deny.toml, .github/..., fixtures/...) -> file exists
Cells without backticks are prose and ignored.
Stdlib only.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"PE-[A-Z]+-[0-9]+")
SPAN_RE = re.compile(r"`([^`]+)`")
CODE_DIRS = ("crates", "fuzz", "tools", "interop")
CODE_EXTS = (".rs", ".py", ".sh")
EXTRA_FILES = ("Makefile", "deny.toml", "Cargo.toml", "Cargo.lock")
EXTRA_GLOBS = (".github/workflows",)


def code_files():
    out = []
    for d in CODE_DIRS + ("domains",):
        p = os.path.join(ROOT, d)
        if not os.path.isdir(p):
            continue
        for base, _, files in os.walk(p):
            for f in files:
                if f.endswith(CODE_EXTS):
                    out.append(os.path.join(base, f))
            if os.path.basename(base) == "proof-domains":
                # Domain-suite manifests carry PE- ids (path deps on the core).
                for f in files:
                    if f == "Cargo.toml":
                        out.append(os.path.join(base, f))
    for f in EXTRA_FILES:
        p = os.path.join(ROOT, f)
        if os.path.isfile(p):
            out.append(p)
    for d in EXTRA_GLOBS:
        p = os.path.join(ROOT, d)
        if os.path.isdir(p):
            for f in os.listdir(p):
                out.append(os.path.join(p, f))
    for dirpath, _, files in os.walk(os.path.join(ROOT, "crates")):
        for f in files:
            if f == "Cargo.toml":
                out.append(os.path.join(dirpath, f))
    return out


def symbols():
    """symbol -> True for every fn/mod/struct/enum/trait in crates, domains and
    fuzz rs files."""
    syms = {}
    pat = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:fn|mod|struct|enum|trait|const|static)\s+([A-Za-z_][A-Za-z0-9_]*)")
    for top in ("crates", "domains"):
        for dirpath, _, files in os.walk(os.path.join(ROOT, top)):
            for f in files:
                if not f.endswith(".rs"):
                    continue
                with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                    for line in fh:
                        m = pat.match(line)
                        if m:
                            syms[m.group(1)] = True
    return syms


def resolve(span, syms):
    span = span.strip()
    if "::" in span:
        head, sym = span.rsplit("::", 1)
        sym = re.sub(r"\(.*", "", sym).strip()
        if head == "fuzz":
            return os.path.isfile(os.path.join(ROOT, "fuzz", "fuzz_targets", sym + ".rs"))
        return sym in syms
    if "/" in span or span.endswith((".toml", ".yml", ".md", ".json", ".rs", ".py", ".sh")):
        return os.path.isfile(os.path.join(ROOT, span))
    return None  # prose-ish; caller decides


def main():
    errors = []
    matrix = os.path.join(ROOT, "docs", "requirements-matrix.md")
    rows = []
    with open(matrix, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.startswith("| PE-"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) != 6:
                errors.append(f"malformed row (want 6 cells): {line[:80]}")
                continue
            rows.append((cells[0], cells[4], cells[5]))
    matrix_ids = {r[0] for r in rows}
    if len(matrix_ids) != len(rows):
        errors.append("duplicate requirement id in matrix")

    code_ids = {}
    for path in code_files():
        with open(path, encoding="utf-8", errors="replace") as fh:
            for m in ID_RE.finditer(fh.read()):
                code_ids.setdefault(m.group(0), set()).add(
                    os.path.relpath(path, ROOT)
                )

    for mid in sorted(matrix_ids):
        if mid not in code_ids:
            errors.append(f"{mid} in matrix but in no scanned code file")
    for cid in sorted(code_ids):
        if cid not in matrix_ids:
            errors.append(
                f"{cid} in {sorted(code_ids[cid])[0]} but missing from matrix"
            )

    syms = symbols()
    for mid, pos, neg in rows:
        resolved = False
        unresolved = []
        for cell in (pos, neg):
            for span in SPAN_RE.findall(cell):
                r = resolve(span, syms)
                if r is True:
                    resolved = True
                elif r is False:
                    unresolved.append(f"{mid}: unresolvable `{span}`")
        if not resolved:
            errors.append(f"{mid}: no resolvable test reference in row")
        errors.extend(unresolved)

    if errors:
        print(f"traceability FAILED ({len(errors)}):")
        for e in errors:
            print("  -", e)
        return 1
    print(
        f"traceability OK: {len(matrix_ids)} ids in matrix+code, "
        f"{len(code_ids)} ids in code, all rows test-linked"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
