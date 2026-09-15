#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Self-test for the freeze guard (PE-FREEZE-001).

Regression test for the pre-launch core audit finding: `tools/check_freeze.py`
compared only `pin..HEAD`, so a frozen-path file modified in the working tree
or staged in the index (never committed) passed the guard. The guard must
refuse uncommitted frozen edits and still allow the recorded escape hatch.

Runs entirely in a throwaway git repository (tempdir); the real repository is
never touched. Stdlib only.

Usage:
    python3 tools/check_freeze_selftest.py

Exit 0 = guard behaves (clean pass, uncommitted/staged fail, recorded pass).
Exit 1 = a regression is present (prints which case failed).
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE / "check_freeze.py"


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)


def guard(cwd):
    r = run([sys.executable, "tools/check_freeze.py"], cwd)
    return r.returncode, (r.stdout + r.stderr)


def write_manifest(root, pin, files):
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "freeze-manifest.json").write_text(
        json.dumps(
            {
                "_doc": "selftest manifest",
                "pin": pin,
                "frozen_paths": ["crates/proof-core/src/"],
                "change_records": (
                    [] if not files else [{"commit": "test", "class": "CORE",
                                           "layer": "selftest", "files": files}]
                ),
            },
            indent=2,
        )
    )


def setup(root):
    (root / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copy(GUARD, root / "tools" / "check_freeze.py")
    (root / "crates" / "proof-core" / "src").mkdir(parents=True, exist_ok=True)
    target = root / "crates" / "proof-core" / "src" / "lib.rs"
    target.write_text("// frozen content\n")
    run(["git", "init", "-q"], root)
    run(["git", "config", "user.email", "selftest@example.invalid"], root)
    run(["git", "config", "user.name", "selftest"], root)
    run(["git", "add", "-A"], root)
    run(["git", "commit", "-q", "-m", "pin"], root)
    pin = run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    write_manifest(root, pin, [])
    run(["git", "add", "-A"], root)
    run(["git", "commit", "-q", "-m", "manifest"], root)
    return target


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix="pe-freeze-selftest-") as tmp:
        root = Path(tmp)
        target = setup(root)

        code, out = guard(root)
        if code != 0:
            failures.append(f"clean tree must pass, got exit {code}: {out.strip()}")

        # The regression: an uncommitted frozen edit used to pass silently.
        with target.open("a") as fh:
            fh.write("// uncommitted frozen mutation\n")
        code, out = guard(root)
        if code == 0:
            failures.append(
                "uncommitted frozen edit must FAIL, guard reported OK: "
                f"{out.strip()}"
            )
        elif "lib.rs" not in out:
            failures.append(f"guard must name the offending file, said: {out.strip()}")

        # Staged (index) edits are equally unapproved.
        run(["git", "add", "-A"], root)
        code, out = guard(root)
        if code == 0:
            failures.append(
                f"staged frozen edit must FAIL, guard reported OK: {out.strip()}"
            )

        # Recorded files stay allowed (the documented escape hatch).
        write_manifest(root, run(["git", "rev-parse", "HEAD"], root).stdout.strip(),
                       ["crates/proof-core/src/lib.rs"])
        code, out = guard(root)
        if code != 0:
            failures.append(
                f"recorded frozen edit must pass, got exit {code}: {out.strip()}"
            )

    if failures:
        print("freeze-guard selftest FAILED:")
        for f in failures:
            print(f"  {f}")
        return 1
    print("freeze-guard selftest OK: clean pass, uncommitted/staged fail, recorded pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
