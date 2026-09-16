#!/usr/bin/env bash
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# One-shot quick proof: hides the ID/issuer plumbing behind a single
# command so newcomers get PASS in seconds, not 15 manual steps.
# Payloads live in files (--payload-file/--digest-file hash bytes, no hex
# math); policy kinds are inferred from the proof (no manual JSON).
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
printf 'payment-p1-bytes' > "$WORK/payment.bin"
printf 'invoice-i9-bytes' > "$WORK/invoice.bin"
"${CLI[@]}" create-event --type payment.created --subject payment:p1 \
  --effective-at 1700000000 --payload-file "$WORK/payment.bin" --out "$WORK/ev1.json" >/dev/null
"${CLI[@]}" create-event --type invoice.issued --subject invoice:i9 \
  --effective-at 1700000000 --payload-file "$WORK/invoice.bin" --out "$WORK/inv1.json" >/dev/null
"${CLI[@]}" attest --seed test --subject payment:p1 --claim-type payment.settled \
  --claim amount=4200 --issued-at 1700000150 --out "$WORK/att.json" >/dev/null
ATT=$("${CLI[@]}" id --artifact "$WORK/att.json")
"${CLI[@]}" add-evidence --kind transaction_record --digest-file "$WORK/payment.bin" \
  --attestation-ref "$ATT" --out "$WORK/evd.json" >/dev/null
EVT=$("${CLI[@]}" id --artifact "$WORK/ev1.json")
INV=$("${CLI[@]}" id --artifact "$WORK/inv1.json")
EVD=$("${CLI[@]}" id --artifact "$WORK/evd.json")
"${CLI[@]}" relate --from "$EVT" --type SETTLES --to "$INV" \
  --evidence-ref "$EVD" --attestation-ref "$ATT" --out "$WORK/rel.json" >/dev/null
"${CLI[@]}" build --kind payment.settles-invoice --subject "$EVT" \
  --predicate settles --object "$INV" --at-time 1700000150 \
  --created-at 1700000200 --events "$WORK/ev1.json,$WORK/inv1.json" \
  --attestations "$WORK/att.json" --evidence "$WORK/evd.json" \
  --relationships "$WORK/rel.json" --out "$WORK/proof.json" >/dev/null
# Genesis step: no revocations exist yet, so absence is asserted explicitly
# (--no-require-status). Without it the fail-closed default rejects the
# empty feed (see the strict check below).
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 --revocations-known-at 1700000300 --no-require-status
# Policy from the attestation + proof (kinds inferred, no manual JSON) +
# human-readable explanation.
"${CLI[@]}" init-policy --attestation "$WORK/att.json" --proof "$WORK/proof.json" \
  --out "$WORK/policy.json" >/dev/null
ISSUER=$("${CLI[@]}" id --artifact "$WORK/att.json" --field issuer)
"${CLI[@]}" evaluate --proof "$WORK/proof.json" --policy "$WORK/policy.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --no-require-status --trusted "$ISSUER" >/dev/null
"${CLI[@]}" explain --proof "$WORK/proof.json" --policy "$WORK/policy.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --no-require-status --trusted "$ISSUER" | tail -n 8
# Fail-closed teaching moment: bare verify (no --no-require-status) rejects
# the empty status feed (no --status files consulted) — expected exit 1,
# asserted so a silent default flip breaks this script instead of slipping
# into production.
set +e
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 \
  --revocations-known-at 1700000300 >/dev/null 2>&1
BARE=$?
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --production >/dev/null 2>&1
PROD=$?
set -e
if [ "$BARE" -ne 1 ]; then
  echo "quick_proof: expected bare verify to fail closed on the empty feed (exit 1), got $BARE" >&2
  exit 1
fi
if [ "$PROD" -ne 1 ]; then
  echo "quick_proof: expected --production to fail closed on the empty feed (exit 1), got $PROD" >&2
  exit 1
fi
echo "strict check (bare + --production) fails closed on the empty feed as designed (exit 1); supply --status feed files in production"
echo "quick proof PASS: $WORK/proof.json (verify + evaluate + explain)"
if [ "$KEEP" -eq 0 ]; then rm -rf "$WORK"; fi
