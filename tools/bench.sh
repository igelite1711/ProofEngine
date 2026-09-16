#!/usr/bin/env bash
# Bench: deterministic throughput for proof-cli (no new deps).
# Builds the release binary, then times: single verify, build/verify/inspect
# on large proofs, wide graphs, deep supersession chains, signing, and one
# batch-verify invocation. All numbers are subprocess end-to-end (honest
# about what they include); per-proof semantics are identical everywhere.
#
# Usage:  tools/bench.sh [N=50]  (plus LARGE_E/WIDE_R/DEEP_D/SIGN_N env knobs)
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

# Scale dimensions: large (many members), wide (many edges), deep (long
# supersession chain), signing throughput, parse-only (inspect) throughput.
# Each prints mean ms/op + peak child RSS (Linux ru_maxrss, KB). Counts are
# overridable: LARGE_E, WIDE_R, DEEP_D, SIGN_N (defaults suit a laptop).
LARGE_E="${LARGE_E:-16}"
WIDE_R="${WIDE_R:-48}"
DEEP_D="${DEEP_D:-8}"
SIGN_N="${SIGN_N:-20}"
export LARGE_E WIDE_R DEEP_D SIGN_N
python3 - "$BIN" "$D" <<'PY'
import json, os, resource, subprocess, sys, time
bin_, d = sys.argv[1], sys.argv[2]
E, R, D, S = (int(os.environ[k]) for k in ("LARGE_E", "WIDE_R", "DEEP_D", "SIGN_N"))
DL = "ab" * 32

def run(*a):
    subprocess.run(list(a), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

def rss():
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

def timeit(label, n, args):
    run(*args)  # warmup
    t0 = time.perf_counter()
    for _ in range(n):
        run(*args)
    dt = time.perf_counter() - t0
    print(f"{label}: {dt/n*1000:.2f} ms/op | peak RSS {rss()} KB")

def mk_event(i, tag):
    p = f"{d}/{tag}-e{i}.json"
    run(bin_, "create-event", "--type", "test.event.occurred",
        "--subject", f"test:{tag}-{i}", "--effective-at", "1700000000",
        "--payload-hex", DL, "--out", p, "--quiet")
    return p

def mk_attest(i, tag, exp=""):
    p = f"{d}/{tag}-a{i}.json"
    cmd = [bin_, "attest", "--seed", "test", "--subject", f"test:{tag}-{i}",
           "--claim-type", "test.occurred", "--issued-at", "1700000100"]
    if exp:
        cmd += ["--expires-at", exp]
    run(*(cmd + ["--out", p, "--quiet"]))
    return p

# --- large: E events + E attestations in one proof ---
evs, atts = [], []
for i in range(E):
    evs.append(mk_event(i, "large"))
    atts.append(mk_attest(i, "large"))
run(bin_, "build", "--kind", "test.proposition", "--subject", "test:large",
    "--predicate", "occurred", "--at-time", "1700000100",
    "--created-at", "1700000200", "--events", ",".join(evs),
    "--attestations", ",".join(atts), "--evidence", "", "--relationships", "",
    "--out", f"{d}/large.json", "--quiet")
timeit(f"build large ({E}+{E} members)", 3,
       [bin_, "build", "--kind", "test.proposition", "--subject", "test:large",
        "--predicate", "occurred", "--at-time", "1700000100",
        "--created-at", "1700000200", "--events", ",".join(evs),
        "--attestations", ",".join(atts), "--evidence", "", "--relationships", "",
        "--out", f"{d}/large.json", "--quiet"])
timeit(f"verify large ({E}+{E} members)", 5,
       [bin_, "verify", "--proof", f"{d}/large.json", "--clock", "1700000200",
        "--revocations-known-at", "1700000200", "--quiet"])
timeit("inspect large (parse-only)", 5,
       [bin_, "inspect", "--proof", f"{d}/large.json", "--quiet"])

# --- wide: R REFERENCES edges across 8 events ---
wevs = [mk_event(i, "wide") for i in range(8)]
ev_ids = [json.load(open(p))["id"] for p in wevs]
rels = []
for i in range(R):
    p = f"{d}/wide-r{i}.json"
    run(bin_, "relate", "--from", ev_ids[i % 8], "--type", "REFERENCES",
        "--to", ev_ids[(i + 1) % 8], "--out", p, "--quiet")
    rels.append(p)
run(bin_, "build", "--kind", "test.proposition", "--subject", "test:wide",
    "--predicate", "occurred", "--at-time", "1700000100",
    "--created-at", "1700000200", "--events", ",".join(wevs),
    "--attestations", "", "--evidence", "", "--relationships", ",".join(rels),
    "--out", f"{d}/wide.json", "--quiet")
timeit(f"verify wide ({R} edges)", 5,
       [bin_, "verify", "--proof", f"{d}/wide.json", "--clock", "1700000200",
        "--quiet"])

# --- deep: D-long supersession chain (status supplied, as in production) ---
datts = [mk_attest(i, "deep") for i in range(D)]
att_ids = [json.load(open(p))["id"] for p in datts]
stats = []
for i in range(1, D):
    p = f"{d}/deep-s{i}.json"
    run(bin_, "supersede", "--seed", "test", "--old", att_ids[i - 1],
        "--new", att_ids[i], "--at", "1700000150", "--out", p, "--quiet")
    stats.append(p)
devs = [mk_event(i, "deep") for i in range(2)]
run(bin_, "build", "--kind", "test.proposition", "--subject", "test:deep",
    "--predicate", "occurred", "--at-time", "1700000100",
    "--created-at", "1700000200",
    "--events", ",".join(devs), "--attestations", ",".join(datts),
    "--evidence", "", "--relationships", "",
    "--out", f"{d}/deep.json", "--quiet")
stargs = []
for s in stats:
    stargs += ["--status", s]
timeit(f"verify deep (chain of {D})", 5,
       [bin_, "verify", "--proof", f"{d}/deep.json", "--clock", "1700000200",
        "--revocations-known-at", "1700000200", *stargs, "--quiet"])

# --- signing throughput ---
t0 = time.perf_counter()
for i in range(S):
    run(bin_, "attest", "--seed", "test", "--subject", f"test:sign-{i}",
        "--claim-type", "test.occurred", "--issued-at", "1700000100",
        "--out", f"{d}/sign.json", "--quiet")
dt = time.perf_counter() - t0
print(f"attest x{S}: {dt/S*1000:.2f} ms/sign | peak RSS {rss()} KB")
PY
# Batch dimension: one batch-verify invocation over N distinct proofs.
# Same semantics per member (batching amortizes process + context setup
# only — never verification work itself).
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