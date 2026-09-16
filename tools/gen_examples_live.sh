#!/usr/bin/env bash
# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
# Regenerate examples/live/ — the worked payment example shipped with the repo.
#
# Why this exists: `examples/live/*.json` are real artifacts (canonical CBOR
# bytes + ids). They are NOT hand-editable: any wire-format or id-binding
# change makes every stored artifact stale, and a stale example teaches the
# wrong thing (it verifies with ID_MISMATCH). Regenerate rather than patch.
#
# Deterministic: fixed timestamps + fixed demo-grade test seed, so reruns
# reproduce identical bytes (the id printed at the end is stable).
# Usage: bash tools/gen_examples_live.sh [--check]
#   --check  regenerate into a temp dir and diff against the committed files
#            (CI-friendly rot guard; exits 1 on drift, commits nothing).
set -euo pipefail

OUT=examples/live
CHECK=0
if [ "${1:-}" = "--check" ]; then CHECK=1; fi
if [ "${1:-}" != "" ] && [ "${1:-}" != "--check" ]; then
  echo "usage: gen_examples_live.sh [--check]" >&2
  exit 2
fi

WORK="$OUT"
if [ "$CHECK" = "1" ]; then WORK=$(mktemp -d /tmp/pe-examples-live.XXXXXX); fi

CLI=(cargo run --quiet --locked -p proof-cli --)
mkdir -p "$WORK/payloads"
# Deterministic payload files: event payloads and the settlement receipt are
# hashed by the CLI (--payload-file / --digest-file), so no digest plumbing
# and no magic hex constants appear in this script.
printf 'payment-p1-payload\n' > "$WORK/payloads/payment.bin"
printf 'invoice-i9-payload\n' > "$WORK/payloads/invoice.bin"
printf 'settlement-receipt-2026\n' > "$WORK/payloads/receipt.bin"

"${CLI[@]}" create-event --type payment.created --subject payment:p1 \
  --effective-at 1700000000 --payload-file "$WORK/payloads/payment.bin" \
  --out "$WORK/ev1.json" >/dev/null
"${CLI[@]}" create-event --type invoice.issued --subject invoice:i9 \
  --effective-at 1700000000 --payload-file "$WORK/payloads/invoice.bin" \
  --out "$WORK/inv1.json" >/dev/null
"${CLI[@]}" attest --seed test --subject payment:p1 --claim-type payment.settled \
  --claim amount=4200 --issued-at 1700000150 --out "$WORK/att.json" >/dev/null
ATT=$("${CLI[@]}" id --artifact "$WORK/att.json")
"${CLI[@]}" add-evidence --kind transaction_record \
  --digest-file "$WORK/payloads/receipt.bin" --attestation-ref "$ATT" \
  --out "$WORK/evd.json" >/dev/null
EV1=$("${CLI[@]}" id --artifact "$WORK/ev1.json")
INV=$("${CLI[@]}" id --artifact "$WORK/inv1.json")
EVD=$("${CLI[@]}" id --artifact "$WORK/evd.json")
"${CLI[@]}" relate --from "$EV1" --type SETTLES --to "$INV" \
  --evidence-ref "$EVD" --attestation-ref "$ATT" --out "$WORK/rel.json" >/dev/null
"${CLI[@]}" build --kind payment.settles-invoice --subject "$EV1" \
  --predicate settles --object "$INV" --at-time 1700000150 \
  --created-at 1700000200 --events "$WORK/ev1.json,$WORK/inv1.json" \
  --attestations "$WORK/att.json" --evidence "$WORK/evd.json" \
  --relationships "$WORK/rel.json" --out "$WORK/proof.json" >/dev/null

# Self-check: the regenerated set must verify and satisfy the shipped policy.
ISSUER=$("${CLI[@]}" id --artifact "$WORK/att.json" --field issuer)
"${CLI[@]}" verify --proof "$WORK/proof.json" --clock 1700000300 \
  --revocations-known-at 1700000300 --no-require-status --quiet >/dev/null
"${CLI[@]}" evaluate --proof "$WORK/proof.json" --policy "$OUT/policy.json" \
  --clock 1700000300 --revocations-known-at 1700000300 --no-require-status \
  --trusted "$ISSUER" --quiet >/dev/null

if [ "$CHECK" = "1" ]; then
  drift=0
  for f in ev1.json inv1.json att.json evd.json rel.json proof.json payloads/payment.bin payloads/invoice.bin payloads/receipt.bin; do
    if ! cmp -s "$WORK/$f" "$OUT/$f"; then
      echo "examples-live drift: $OUT/$f differs from a fresh generation" >&2
      drift=1
    fi
  done
  rm -rf "$WORK"
  if [ "$drift" = "1" ]; then
    echo "run: bash tools/gen_examples_live.sh   (then re-run make test)" >&2
    exit 1
  fi
  echo "examples/live is current (byte-identical to a fresh generation)"
  exit 0
fi

echo "regenerated examples/live (verify PASS + policy PASS)"
echo "  proof $("${CLI[@]}" id --artifact "$OUT/proof.json")"
echo "  verify: proof-cli verify examples/live/proof.json --clock 1700000300 --revocations-known-at 1700000300 --no-require-status"
echo "  policy: proof-cli evaluate examples/live/proof.json --policy examples/live/policy.json --clock 1700000300 --revocations-known-at 1700000300 --no-require-status --trusted $ISSUER"
