#!/usr/bin/env bash
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# One-shot quick proof: hides the ID/digest/issuer plumbing behind a single
# command so newcomers get PASS in seconds, not 15 manual steps.
# Usage: bash tools/quick_proof.sh [--work DIR] [--keep]
# Deterministic: fixed timestamps + fixed test seed (demo-grade keys only).
set -euo pipefail
WORK=/tmp/proof-quick
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2;;
    --keep) KEEP=1; shift;;
    *) echo "usage: quick_proof.sh [--work DIR] [--keep]" >&2; exit 2;;
  esac
done
rm -rf "$WORK"; mkdir -p "$WORK"
CLI=(cargo run --quiet --locked -p proof-cli --)
PAYLOAD=$(python3 -c "print('ab'*32)")
"${CLI[@]}" create-event --type payment.created --subject payment:p1 \
  --effective-at 1700000000 --payload-hex "$PAYLOAD" --out "$WORK/ev1.json" >/dev/null
"${CLI[@]}" create-event --type invoice.issued --subject invoice:i9 \
  --effective-at 1700000000 --payload-hex "$(python3 -c "print('cd'*32)")" --out "$WORK/inv1.json" >/dev/null
"${CLI[@]}" attest --seed test --subject payment:p1 --claim-type payment.settled \
  --claim amount=4200 --issued-at 1700000150 --out "$WORK/att.json" >/dev/null
DIGEST=$(python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex('$PAYLOAD')).hexdigest())")
ATT=$(python3 -c "import json; print(json.load(open('$WORK/att.json'))['id'])")
"${CLI[@]}" add-evidence --kind transaction_record --digest-hex "$DIGEST" \
  --attestation-ref "$ATT" --out "$WORK/evd.json" >/dev/null
EVT=$(python3 -c "import json; print(json.load(open('$WORK/ev1.json'))['id'])")
INV=$(python3 -c "import json; print(json.load(open('$WORK/inv1.json'))['id'])")
EVD=$(python3 -c "import json; print(json.load(open('$WORK/evd.json'))['id'])")
"${CLI[@]}" relate --from "$EVT" --type SETTLES --to "$INV" \
  --evidence-ref "$EVD" --attestation-ref "$ATT" --out "$WORK/rel.json" >/dev/null
"${CLI[@]}" build --kind payment.settles-invoice --subject "$EVT" \
  --predicate settles --object "$INV" --at-time 1700000150 \
  --created-at 1700000200 --events "$WORK/ev1.json,$WORK/inv1.json" \
  --attestations "$WORK/att.json" --evidence "$WORK/evd.json" \
  --relationships "$WORK/rel.json" --out "$WORK/proof.json" >/dev/null
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 --revocations-known-at 1700000300
# Policy decision on the same bytes (issuer substituted into the example
# policy, prefix kept exactly once) + human-readable explanation.
ISSUER=$(python3 -c "import json; print(json.load(open('$WORK/att.json'))['issuer'])")
python3 -c "import json; p=json.load(open('examples/policies/settlement.json')); [r.__setitem__('issuer','$ISSUER') for r in p['requirements'] if r.get('type')=='issuer_trusted']; json.dump(p, open('$WORK/policy.json','w'), indent=2)"
"${CLI[@]}" evaluate --proof "$WORK/proof.json" --policy "$WORK/policy.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --trusted "$ISSUER" >/dev/null
"${CLI[@]}" explain --proof "$WORK/proof.json" --policy "$WORK/policy.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --trusted "$ISSUER" | tail -n 8
echo "quick proof PASS: $WORK/proof.json (verify + evaluate + explain)"
if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; fi
