#!/usr/bin/env bash
# Bench: deterministic verification throughput for proof-cli (no new deps).
# Builds the release binary, generates the demo proof, and times N verifies.
#
# Usage:  tools/bench.sh [N=50]
set -euo pipefail
cd "$(dirname "$0")/.."

N="${1:-50}"
echo ">> building release proof-cli ..."
cargo build --release --locked -p proof-cli --bin proof-cli >/dev/null 2>&1
BIN="$(pwd)/target/release/proof-cli"

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT

echo ">> generating deterministic demo proof ..."
"$BIN" demo --out "$D" >/dev/null 2>&1
PROOF="$D/proof.cbor.json"

# Baseline: the demo proof verifies PASS with fresh revocation info.
"$BIN" verify --proof "$PROOF" --clock 1700000300 \
    --revocations-known-at 1700000300 --out "$D/baseline.json" >/dev/null 2>&1

# Hijack: runs N verifies of the same proof, prints ms/verify + throughput.
python3 - "$BIN" "$PROOF" "$N" <<'PY'
import subprocess, sys, time
bin_, proof, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
args = [bin_, "verify", "--proof", proof, "--clock", "1700000300",
        "--revocations-known-at", "1700000300", "--quiet"]
subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
t0 = time.perf_counter()
for _ in range(n):
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
dt = time.perf_counter() - t0
print(f"verify x{n}: {dt:.2f}s total | {dt/n*1000:.2f} ms/verify | {n/dt:.1f} verifies/sec")
PY