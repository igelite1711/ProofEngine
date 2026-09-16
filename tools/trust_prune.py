#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Trust-list pruning for key rotation (M4 helper, adapter-level).

V1 trust lists carry bare keyrefs — no per-key validity in the core by design
(TRUST.md "Key lifetime"). The caller prunes the list per evaluation time:
supply only roots authoritative at `verified_at`. This tool makes that contract
actionable without touching frozen semantics.

Input: JSON file with rotation registry:
  {"keys": [{"keyref": "key:ed25519:...", "valid_from": 1699000000,
             "valid_until": 1701000000 | null, "note": "2024 issuance key"}, ...]}

  valid_from: first second the key is authoritative (inclusive).
  valid_until: last second authoritative (inclusive), null = still current.

Usage:
  python3 tools/trust_prune.py --registry trust-registry.json --at 1700000300 --out trusted.txt
  python3 tools/trust_prune.py --registry trust-registry.json --at 1700000300 --format cli
    → prints `--trusted k1 --trusted k2` for shell embedding.

Output:
  --out: newline-separated keyrefs authoritative at --at.
  --format cli: shell fragment for proof-cli verify/evaluate.

Exit 0 with pruned list (possibly empty — caller decides; empty fails closed
via issuer_trusted). Exit 2 on usage/registry errors.

Example:
  # Historical evaluation of pre-rotation proof:
  python3 tools/trust_prune.py --registry ops/trust.json --at 1699900000 --out /tmp/trusted.txt
  proof-cli verify --proof old.json --clock 1699900100 --revocations-known-at 1699900100 \
    $(cat /tmp/trusted.txt | sed 's/^/--trusted /' | tr '\n' ' ')
"""
import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser(description="Prune trust registry by evaluation time")
    ap.add_argument("--registry", required=True, help="JSON rotation registry")
    ap.add_argument("--at", required=True, type=int, help="Evaluation time (verified_at)")
    ap.add_argument("--out", help="Write newline-separated keyrefs")
    ap.add_argument("--format", choices=["list", "cli"], default="list")
    args = ap.parse_args()

    try:
        reg = json.load(open(args.registry))
    except Exception as e:
        print(f"trust_prune: read {args.registry}: {e}", file=sys.stderr)
        return 2

    keys = reg.get("keys", [])
    pruned = []
    for k in keys:
        ref = k.get("keyref", "")
        vf = k.get("valid_from", 0)
        vu = k.get("valid_until")
        if not ref:
            continue
        if args.at < vf:
            continue
        if vu is not None and args.at > vu:
            continue
        pruned.append(ref)

    if args.format == "cli":
        frag = " ".join(f"--trusted {r}" for r in pruned)
        print(frag)
    else:
        text = "\n".join(pruned) + ("\n" if pruned else "")
        if args.out:
            open(args.out, "w").write(text)
            print(f"trust_prune: {len(pruned)}/{len(keys)} keys authoritative at {args.at} -> {args.out}", file=sys.stderr)
        else:
            print(text, end="")

    if not pruned:
        print("trust_prune: WARNING empty trust list — every issuer_trusted will FAIL (fail closed, correct for retired keys)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
