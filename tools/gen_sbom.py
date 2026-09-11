#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate a CycloneDX bill of materials from Cargo.lock (stdlib only).

No network, no new tooling: the lockfile already pins every dependency, so
the SBOM is a deterministic projection of it. Run:
    python3 tools/gen_sbom.py --out sbom.cdx.json
Determinism: same lockfile ⇒ byte-identical SBOM (enforced in CI by
generating twice and diffing).
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def parse_lock(text):
    """Minimal Cargo.lock parser: [[package]] blocks with name/version/source."""
    packages = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current:
                packages.append(current)
            current = {}
        elif current is not None and "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip().strip('"')
    if current:
        packages.append(current)
    return [p for p in packages if "name" in p and "version" in p]


def commit():
    r = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def commit_date():
    """Committer date of HEAD (stable per commit): the SBOM timestamp, so
    the same lockfile + commit always yields byte-identical output."""
    r = subprocess.run(
        ["git", "-C", str(REPO), "log", "-1", "--format=%cI", "HEAD"],
        capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lock", default=str(REPO / "Cargo.lock"))
    ap.add_argument("--timestamp", default=None,
                    help="override SBOM timestamp (default: HEAD committer date)")
    args = ap.parse_args()

    lock_text = Path(args.lock).read_text()
    packages = sorted(parse_lock(lock_text), key=lambda p: (p["name"], p["version"]))
    lock_sha = hashlib.sha256(lock_text.encode()).hexdigest()

    components = []
    for p in packages:
        source = p.get("source", "")
        if "registry" in source:
            scope = "required"
            external = {"type": "distribution", "url": source}
        else:
            scope = "required"
            external = {"type": "website", "url": source or "path:workspace"}
        components.append({
            "type": "library",
            "bom-ref": f"{p['name']}@{p['version']}",
            "name": p["name"],
            "version": p["version"],
            "scope": scope,
            "externalReferences": [external],
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": args.timestamp or commit_date(),
            "tools": [{"name": "gen_sbom.py", "version": "1"}],
            "component": {"type": "application", "name": "proof-engine", "version": commit()},
            "properties": [{"name": "cargo-lock-sha256", "value": lock_sha}],
        },
        "components": components,
    }
    # Compact deterministic encoding is NOT used: pretty + sorted keys keeps
    # the file reviewable and diff-stable across runs.
    Path(args.out).write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    print(f"sbom: {len(components)} components from {args.lock} -> {args.out}")


if __name__ == "__main__":
    sys.exit(main())
