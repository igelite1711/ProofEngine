#!/usr/bin/env bash
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# Pilot integration: legal document execution with supersession.
# A second end-to-end domain walkthrough (payment lives in quick_proof.sh):
# draft → sign → verify PASS → supersede → history preserved but no longer
# current (not_superseded FAILs). Exercises the lifecycle dimension through
# the real CLI. Deterministic: fixed timestamps + fixed test seed
# (demo-grade keys only).
# Usage: bash tools/pilot_legal.sh [--work DIR] [--keep]
set -euo pipefail
WORK=/tmp/proof-pilot-legal
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --work) WORK="$2"; shift 2;;
    --keep) KEEP=1; shift;;
    *) echo "usage: pilot_legal.sh [--work DIR] [--keep]" >&2; exit 2;;
  esac
done
rm -rf "$WORK"; mkdir -p "$WORK"
CLI=(cargo run --quiet --locked -p proof-cli --)
"${CLI[@]}" create-event --type legal.document.drafted --subject matter:m7 \
  --effective-at 1700000000 --payload-hex "$(python3 -c "print('11'*32)")" --out "$WORK/draft.json" >/dev/null
"${CLI[@]}" create-event --type legal.document.signed --subject matter:m7 \
  --effective-at 1700000050 --payload-hex "$(python3 -c "print('22'*32)")" --out "$WORK/signed.json" >/dev/null
"${CLI[@]}" attest --seed test --subject matter:m7 --claim-type legal.document.signed \
  --claim version=1 --issued-at 1700000100 --out "$WORK/att1.json" >/dev/null
ATT1=$(python3 -c "import json; print(json.load(open('$WORK/att1.json'))['id'])")
ISSUER=$(python3 -c "import json; print(json.load(open('$WORK/att1.json'))['issuer'])")
"${CLI[@]}" add-evidence --kind receipt --digest-hex "$(python3 -c "print('33'*32)")" \
  --attestation-ref "$ATT1" --out "$WORK/evd.json" >/dev/null
DRAFT=$(python3 -c "import json; print(json.load(open('$WORK/draft.json'))['id'])")
SIGNED=$(python3 -c "import json; print(json.load(open('$WORK/signed.json'))['id'])")
EVD=$(python3 -c "import json; print(json.load(open('$WORK/evd.json'))['id'])")
"${CLI[@]}" relate --from "$DRAFT" --type PRODUCED --to "$SIGNED" \
  --evidence-ref "$EVD" --out "$WORK/rel.json" >/dev/null
"${CLI[@]}" build --kind legal.document.executed --subject "$DRAFT" \
  --predicate produced --object "$SIGNED" --at-time 1700000100 \
  --created-at 1700000200 --events "$WORK/draft.json,$WORK/signed.json" \
  --attestations "$WORK/att1.json" --evidence "$WORK/evd.json" \
  --relationships "$WORK/rel.json" --out "$WORK/proof.json" >/dev/null
echo "== fresh execution (clock 1700000300) =="
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 --revocations-known-at 1700000300 2>&1 | tail -n 2
# Second signing supersedes the first: history preserved, currentness gone.
"${CLI[@]}" attest --seed test --subject matter:m7 --claim-type legal.document.signed \
  --claim version=2 --issued-at 1700000400 --out "$WORK/att2.json" >/dev/null
ATT2=$(python3 -c "import json; print(json.load(open('$WORK/att2.json'))['id'])")
"${CLI[@]}" supersede --seed test --old "$ATT1" --new "$ATT2" --at 1700000400 --out "$WORK/sup.json" >/dev/null
echo "== after supersession (clock 1700000500, status supplied) =="
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000500 \
  --status "$WORK/sup.json" --revocations-known-at 1700000500 2>&1 | tail -n 3
python3 -c "import json; json.dump({'policy_version':1,'policy_id':'legal_current_v1','requirements':[{'type':'signature_valid'},{'type':'issuer_trusted','issuer':'$ISSUER'},{'type':'not_superseded'}]}, open('$WORK/policy.json','w'), indent=2)"
echo "== current-use policy (not_superseded must FAIL) =="
# Expected verdict is FAIL (exit 1): tolerate it under set -e and assert it.
set +e
OUT=$("${CLI[@]}" evaluate --proof "$WORK/proof.json" --policy "$WORK/policy.json" --clock 1700000500 \
  --status "$WORK/sup.json" --revocations-known-at 1700000500 --trusted "$ISSUER" 2>&1)
CODE=$?
set -e
echo "$OUT" | grep -E "^decision|not_superseded" | head -n 3
[ "$CODE" -eq 1 ] && echo "$OUT" | grep -q "^decision fail" \
  || { echo "pilot error: expected decision fail (exit 1), got exit $CODE" >&2; exit 1; }
echo "pilot legal complete: PASS → SUPERSEDED (history valid, no longer current)"
if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; fi
