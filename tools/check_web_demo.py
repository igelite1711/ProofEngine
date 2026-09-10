#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Honesty gate for the browser demo.

Regenerates the demo data from scratch through the real proof-cli and
byte-compares it against the data embedded in demo/web/index.html. Any
hand-edited verdict fails loudly: the page may only show what the
core actually computed.

Usage:
    python3 tools/check_web_demo.py
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main():
    page = REPO / "demo" / "web" / "index.html"
    if not page.exists():
        print("missing demo/web/index.html (run `make web-demo` first)")
        return 1
    m = re.search(
        r'<script id="proof-data" type="application/json">(.*?)</script>',
        page.read_text(),
        re.S,
    )
    if not m:
        print("no embedded proof-data block in index.html")
        return 1
    embedded = m.group(1)
    try:
        embedded_canonical = json.dumps(json.loads(embedded), sort_keys=True,
                                        separators=(",", ":"))
    except json.JSONDecodeError as e:
        print(f"embedded data is not valid JSON: {e}")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "w"
        fresh = Path(tmp) / "fresh.json"
        r = subprocess.run(
            [sys.executable, str(REPO / "tools" / "gen_web_demo.py"),
             "--work", str(work), "--data-only", str(fresh)],
            cwd=REPO, capture_output=True, text=True,
        )
        if r.returncode != 0:
            print(f"regeneration failed:\n{r.stderr}")
            return 1
        if fresh.read_text() != embedded_canonical:
            print("MISMATCH: embedded page data differs from fresh CLI output.")
            print("Regenerate with `make web-demo`; never hand-edit verdicts.")
            return 1
    # Spot-check the verdict pattern the demo narrative depends on.
    d = json.loads(embedded_canonical)
    pay = d["examples"]["payment"]
    assert pay["verify_fresh"]["exit"] == 0
    assert pay["tampered"]["exit"] == 1
    assert pay["revoked"]["exit"] == 1
    assert pay["superseded"]["exit"] == 0
    assert [c["exit"] for c in pay["policy_combos"]] == [0, 1, 1, 1]
    assert d["examples"]["software"]["verify_fresh"]["exit"] == 0
    print(f"web demo honest: {len(embedded_canonical)} data bytes "
          "match fresh core output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
