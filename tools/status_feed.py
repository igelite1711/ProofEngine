#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Status-feed hygiene helper (M4, adapter-level).

Validates a directory of status artifacts before verification:
- every file must be a signed status envelope (kind=status, sign1_b64 present)
- reports freshness: newest file mtime vs --clock/--skew
- emits the --status/--authority CLI fragment + suggested --revocations-known-at

Usage:
  python3 tools/status_feed.py --dir ops/status --clock 1700000500 --skew 300
  python3 tools/status_feed.py --dir ops/status --clock 1700000500 --format cli
    → prints `--status a.json --status b.json --revocations-known-at 1700000400`

Exit 0 = feed usable (possibly empty — empty is valid, means no revocations
known; caller must still pass --revocations-known-at for freshness).
Exit 1 = feed has problems (caller SHOULD alert; proof validity unaffected
per STATUS isolation, but failure_codes will litter). Exit 2 = usage error.
"""
import argparse, json, sys, os, time
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--clock", required=True, type=int)
    ap.add_argument("--skew", type=int, default=300)
    ap.add_argument("--format", choices=["human", "cli"], default="human")
    args = ap.parse_args()
    d = Path(args.dir)
    if not d.is_dir():
        print(f"status_feed: {args.dir} not a directory", file=sys.stderr)
        return 2
    files = sorted(d.glob("*.json"))
    problems = []
    good = []
    newest = 0
    for f in files:
        try:
            v = json.loads(f.read_text())
        except Exception as e:
            problems.append(f"{f.name}: bad JSON: {e}")
            continue
        if v.get("kind") != "status":
            problems.append(f"{f.name}: kind={v.get('kind')} not status")
            continue
        if not v.get("sign1_b64"):
            problems.append(f"{f.name}: missing sign1_b64 (unsigned lists never trusted)")
            continue
        good.append(str(f))
        try:
            newest = max(newest, int(f.stat().st_mtime))
        except Exception:
            pass
    # Freshness: caller must supply --revocations-known-at; suggest newest mtime
    # clamped to clock (future mtimes are suspicious).
    now_suggest = min(newest if newest else args.clock, args.clock)
    age = args.clock - now_suggest if now_suggest <= args.clock else 0
    stale = age > args.skew
    if args.format == "cli":
        frag = " ".join(f"--status {g}" for g in good)
        frag += f" --revocations-known-at {now_suggest}" if good or True else ""
        print(frag)
        return 0
    print(f"status_feed: {len(good)} signed objects, {len(problems)} problems, suggested known_at={now_suggest} (age {age}s vs skew {args.skew})", file=sys.stderr)
    for p in problems:
        print(f"  problem: {p}", file=sys.stderr)
    if stale:
        print(f"  WARNING: feed stale (age {age}s > skew {args.skew}s) → lifecycle UNKNOWN fail-closed until refreshed", file=sys.stderr)
    if problems:
        print(f"  note: feed problems litter STATUS failure_codes but never flip a good proof (isolation); alert, do not treat as revocation", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
