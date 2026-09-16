#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Freeze guard (PE-FREEZE-001): protect the semantic foundation.

Invariant: no file under the frozen paths (docs/freeze-manifest.json) may
differ from the pinned commit unless that difference is covered by an
approved change record. Also asserts the pin tag == the manifest pin and
that the pin is an ancestor of HEAD (the pin commit may never be rewritten).

Usage:
    python3 tools/check_freeze.py

Exit 0 = guard holds. Exit 1 = violation:

* To land a GENERIC EXTENSION / ADAPTER / DOMAIN PROFILE change that touches
  a frozen path, add a change_record to docs/freeze-manifest.json for the
  commit in the same PR that touches the path. (class + layer + files.)
* Any CORE-class change additionally requires
  docs/ARCHITECTURE-CHANGE-PROPOSAL-<topic>.md and an explicit maintainer
  decision per ARCHITECTURE-FREEZE.md §5 before the manifest may name it.

Known limitation (documented, not enforced): approval is keyed by file path,
not by diff content — once a file is named in a change_record, later edits to
that same file are covered by that record. The guard catches *unrecorded*
frozen paths (including uncommitted worktree/staged edits), not diffs within
an already-recorded file; reviewers own the per-commit review of those.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "docs" / "freeze-manifest.json"


def git(*args):
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True
    )


def is_frozen(path, frozen_paths):
    return any(path.startswith(p) for p in frozen_paths)


def main():
    m = json.loads(MANIFEST.read_text())
    pin = m["pin"]
    frozen_paths = m["frozen_paths"]

    # 1. Pin must still exist and name the branch history (never rewritten).
    if git("cat-file", "-e", f"{pin}^{{commit}}").returncode != 0:
        print(f"FAIL: pin {pin} is not a commit in this repository")
        return 1
    if git("merge-base", "--is-ancestor", pin, "HEAD").returncode != 0:
        print(f"FAIL: pin {pin} is not an ancestor of HEAD — the freeze pin "
              f"may never be rewritten or dropped from history")
        return 1

    # 2. The freeze tag (if present) must name the manifest pin.
    tag = git("rev-parse", "--verify", "--quiet", "freeze-candidate-1").stdout.strip()
    if tag and tag != pin:
        print(f"FAIL: tag freeze-candidate-1 is {tag}, manifest pin is {pin} "
              f"— they must agree")
        return 1

    # 3. Frozen-path diffs since the pin must be covered by change records.
    # Tracked changes AND untracked new files: an unrecorded new fixture or
    # module under a frozen path is as much a semantic change as an edit
    # (untracked files were previously invisible to this guard).
    #
    # Uncommitted work must be covered too (pre-launch core audit fix): the
    # guard previously compared only `pin..HEAD`, so a frozen-path edit that
    # had not been committed yet passed as "OK" — the exact state a
    # `make freeze-guard` run inside a feature branch (or CI before commit)
    # is supposed to catch. Working-tree and staged diffs are now included.
    changed = git("diff", "--name-only", f"{pin}..HEAD").stdout.split()
    worktree = git("diff", "--name-only").stdout.split()
    staged = git("diff", "--name-only", "--cached").stdout.split()
    untracked = git(
        "ls-files", "--others", "--exclude-standard"
    ).stdout.split()
    candidates = sorted(
        set(changed) | set(worktree) | set(staged) | set(untracked)
    )
    frozen_changed = sorted(f for f in candidates if is_frozen(f, frozen_paths))
    approved = set()
    for rec in m["change_records"]:
        approved.update(rec["files"])
    unapproved = [f for f in frozen_changed if f not in approved]

    if unapproved:
        print("FAIL: frozen semantic files changed without an approved change record:")
        for f in unapproved:
            print(f"  {f}")
        print("Add a change_record for the responsible commit to "
              "docs/freeze-manifest.json (class GENERIC EXTENSION / ADAPTER / "
              "DOMAIN PROFILE) — CORE changes require an architecture-change-"
              "proposal first (ARCHITECTURE-FREEZE.md §5).")
        return 1

    print("freeze guard OK: pin ancestor of HEAD; tag==manifest; no unapproved "
          f"frozen-path changes ({len(frozen_changed)} approved since pin)")
    return 0


if __name__ == "__main__":
    sys.exit(main())