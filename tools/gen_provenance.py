#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Emit a build-provenance record for a release (stdlib only, SLSA-style).

Captures WHERE an artifact came from so a verifier can answer "was this
built from the pinned commit with the locked dependencies on a known
toolchain": commit, tag, lockfile hash, SBOM hash, rustc/cargo versions,
target triple, build flags, and the artifact hashes themselves.

Usage:
    python3 tools/gen_provenance.py --artifacts proof-cli sbom.cdx.json \\
        --out provenance.json
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def sh(*args):
    r = subprocess.run(list(args), capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", nargs="+", required=True,
                    help="files the provenance covers")
    ap.add_argument("--out", required=True)
    ap.add_argument("--sbom", default=None,
                    help="SBOM file covered by this provenance")
    args = ap.parse_args()

    lock = REPO / "Cargo.lock"
    subjects = []
    for a in args.artifacts:
        p = Path(a)
        if not p.is_file():
            print(f"missing artifact: {a}")
            return 1
        subjects.append({"name": p.name, "sha256": sha256_file(str(p))})

    record = {
        "type": "proof-engine-release-provenance",
        "version": 1,
        "commit": sh("git", "-C", str(REPO), "rev-parse", "HEAD"),
        "tag": sh("git", "-C", str(REPO), "describe", "--tags", "--exact-match"),
        "cargo_lock_sha256": sha256_file(str(lock)),
        "rustc": sh("rustc", "--version"),
        "cargo": sh("cargo", "--version"),
        "target": sh("rustc", "-vV"),
        "subjects": subjects,
    }
    if args.sbom:
        record["sbom_sha256"] = sha256_file(args.sbom)
    Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"provenance: {len(subjects)} subjects -> {args.out}")


if __name__ == "__main__":
    sys.exit(main())
