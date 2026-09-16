# proof-bench — in-process benchmark harness (P5, no new deps)

Isolates creation, signing, canonicalization, hashing, verification
(small/large/deep), graph validation, policy evaluation, and round-trip.

```bash
cargo run --release -p proof-bench -- --iters 20 --json
cargo run --release -p proof-bench -- --help
cargo run --release -p proof-bench -- --write-baseline /tmp/base.json
cargo run --release -p proof-bench -- --check-baseline /tmp/base.json --tolerance 25
make bench-smoke   # quick 2-iteration smoke over all scenarios (debug)
make bench-check   # regression gate vs committed baseline.json (release, 100% + noise floor)
```

`baseline.json` is committed from a reference machine and enforced in CI
(`perf` job). Tolerance is deliberately a 2x-class tripwire: 100% relative
plus a 0.05 ms absolute noise floor, because timer jitter on sub-millisecond
scenarios (policy-eval ~0.002 ms/op) exceeds any sane percentage. Refresh it
with `--write-baseline` on the same command when a genuine speedup lands —
never to silence a regression.

No semantics change here: every scenario builds real proofs and verifies
them through the full pipeline. RSS comes from `/proc` on Linux.
