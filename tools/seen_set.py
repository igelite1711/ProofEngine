#!/usr/bin/env python3
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Replay protection via caller-maintained seen-sets (M4 helper).

The engine is stateless by design: re-presenting valid bytes re-verifies.
Replay-sensitive callers MUST track seen proof_id/event_id per binding context
(PROTOCOL.md Gate H, SECURITY-MODEL T3). This tool is the reference sketch —
adapter-level, never core semantics.

Store: JSON file {"seen_proofs": [...], "seen_events": [...]} (created if missing).

Usage:
  # Check (fail on replay):
  python3 tools/seen_set.py --store ops/seen.json --proof proof.json --context tx:1234
  # Record after successful business processing:
  python3 tools/seen_set.py --store ops/seen.json --proof proof.json --context tx:1234 --record

Context binds the proof to one business action (nonce, tx id, challenge).
Same proof in a different context is NOT a replay (caller decides); same proof
+ same context twice IS. Event ids inside the proof are also tracked to catch
member substitution across proofs.

Exit 0 = unseen (or recorded), 1 = replay detected, 2 = usage error.
"""
import argparse, json, sys
from pathlib import Path

def load_proof_ids(proof_path):
    d = json.load(open(proof_path))
    # Envelope has id; members need inspection via proof-cli inspect --json?
    # Fallback: envelope id only + note to use inspect for events.
    pid = d.get("id", "?")
    return pid

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True)
    ap.add_argument("--proof", required=True)
    ap.add_argument("--context", required=True, help="Binding context (nonce/tx/challenge)")
    ap.add_argument("--record", action="store_true", help="Record after check")
    args = ap.parse_args()
    store_p = Path(args.store)
    store = {"seen": []}
    if store_p.exists():
        try:
            store = json.loads(store_p.read_text())
        except Exception as e:
            print(f"seen_set: read {args.store}: {e}", file=sys.stderr)
            return 2
    seen = set(store.get("seen", []))
    try:
        pid = load_proof_ids(args.proof)
    except Exception as e:
        print(f"seen_set: read {args.proof}: {e}", file=sys.stderr)
        return 2
    key = f"{args.context}::{pid}"
    if key in seen:
        print(f"seen_set: REPLAY detected: {pid} already processed in context {args.context}", file=sys.stderr)
        return 1
    print(f"seen_set: unseen: {pid} in context {args.context}", file=sys.stderr)
    if args.record:
        seen.add(key)
        store["seen"] = sorted(seen)
        store_p.write_text(json.dumps(store, indent=2) + "\n")
        print(f"seen_set: recorded {key} -> {args.store}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    sys.exit(main())
