# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#!/usr/bin/env python3
"""Proof Engine no-panic gate (PE-SEC-004; audit finding F5).

Production paths must never panic on hostile input: no `.unwrap()`,
`.expect(`, `panic!(`, `unreachable!(`, `unimplemented!(`, `todo!(` outside
test code. Tests (`#[cfg(test)]` modules, `tests/`, `examples/`) may use them.

Stdlib only. Exit != 0 with file:line hits on violation.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIRS = [os.path.join(ROOT, "crates", d, "src")
            for d in sorted(os.listdir(os.path.join(ROOT, "crates")))
            if os.path.isdir(os.path.join(ROOT, "crates", d, "src"))]

PAT = re.compile(r"\.(unwrap|expect)\s*\(|panic!\s*\(|unreachable!\s*\(|"
                 r"unimplemented!\s*\(|todo!\s*\(")


def strip_test_modules(lines):
    """Yield (lineno, text) for non-test lines.

    Skips `#[cfg(test)]`-gated modules (rustfmt shape: attribute line,
    then `mod <name> {` ... closing `}` at column 0) and whole files under
    tests/ or examples/ (handled by caller via path filter).
    """
    out = []
    skip = False
    depth = 0
    armed = False
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not skip and s == "#[cfg(test)]":
            armed = True
            continue
        if armed:
            armed = False
            if re.match(r"(pub\s+)?mod\s+\w+", s):
                skip = True
                depth = s.count("{") - s.count("}")
                continue
            if s == "" or s.startswith("//") or s.startswith("/*") or s.startswith("*"):
                armed = True  # doc comments may sit between attribute and `mod`
                continue
        if skip:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                skip = False
            continue
        out.append((i, line))
    return out


def main():
    hits = []
    for src in SRC_DIRS:
        for dirpath, _, files in os.walk(src):
            for fn in sorted(files):
                if not fn.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, encoding="utf-8") as fh:
                    lines = fh.readlines()
                for lineno, text in strip_test_modules(lines):
                    # `debug_assert!` is panic-free in release and allowed.
                    if PAT.search(text):
                        hits.append(f"{os.path.relpath(path, ROOT)}:{lineno}:"
                                    f"{text.strip()[:100]}")
    if hits:
        print("no-panic gate FAILED (PE-SEC-004): panicking calls in "
              "production paths:")
        for h in hits:
            print("  " + h)
        return 1
    print("no-panic gate OK: no unwrap/expect/panic in production paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
