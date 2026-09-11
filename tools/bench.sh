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
# BIN override for non-default CARGO_TARGET_DIR setups (e.g. .cargo/config
# target-dir); default matches a standard workspace layout (CI).
BIN="${BIN:-$(pwd)/target/release/proof-cli}"

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

# Batch dimension: one batch-verify invocation over N distinct proofs vs N
# single-verify invocations. Same semantics per member (batching amortizes
# process + context setup only — never verification work itself).
echo ">> generating $N distinct proofs for batch ..."
BATCH_LIST="$D/batch-list.txt"
python3 - "$BIN" "$D" "$N" > "$BATCH_LIST" <<'PY'
import json, subprocess, sys
bin_, d, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
paths = []
for i in range(n):
    tag = f"bench-{i:04d}"
    subprocess.run([bin_, "create-event", "--type", "test.event.occurred",
                    "--subject", f"test:{tag}",
                    "--effective-at", "1700000000",
                    "--payload-hex", "ab" * 32,
                    "--out", f"{d}/e{i}.json", "--quiet"],
                   stdout=subprocess.DEVNULL, check=True)
    subprocess.run([bin_, "attest", "--seed", "test",
                    "--subject", f"test:{tag}",
                    "--claim-type", "test.occurred",
                    "--issued-at", "1700000100",
                    "--out", f"{d}/a{i}.json", "--quiet"],
                   stdout=subprocess.DEVNULL, check=True)
    subprocess.run([bin_, "build", "--kind", "test.proposition",
                    "--subject", f"test:{tag}", "--predicate", "occurred",
                    "--at-time", "1700000100", "--created-at", "1700000200",
                    "--events", f"{d}/e{i}.json",
                    "--attestations", f"{d}/a{i}.json",
                    "--evidence", "", "--relationships", "",
                    "--out", f"{d}/p{i}.json", "--quiet"],
                   stdout=subprocess.DEVNULL, check=True)
    paths.append(f"{d}/p{i}.json")
print(",".join(paths))
PY
LIST=$(cat "$BATCH_LIST")
python3 - "$BIN" "$LIST" "$N" <<'PY'
import subprocess, sys, time
bin_, proof_list, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
single = [bin_, "batch-verify", "--proofs", proof_list, "--clock", "1700000200",
          "--revocations-known-at", "1700000200", "--quiet"]
subprocess.run(single, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
t0 = time.perf_counter()
subprocess.run(single, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
dt = time.perf_counter() - t0
print(f"batch-verify x{n} distinct: {dt:.2f}s total | {dt/n*1000:.2f} ms/proof | {n/dt:.1f} proofs/sec (one invocation)")
PY