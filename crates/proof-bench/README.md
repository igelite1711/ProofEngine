# proof-bench — in-process benchmark harness (P5, no new deps)

Isolates creation, signing, canonicalization, hashing, verification
(small/large/deep), graph validation, policy evaluation, and round-trip.

```bash
cargo run --release -p proof-bench -- --iters 20 --json
cargo run --release -p proof-bench -- --help
cargo run --release -p proof-bench -- --write-baseline /tmp/base.json
cargo run --release -p proof-bench -- --check-baseline /tmp/base.json --tolerance 25
make bench-smoke   # quick 2-iteration smoke over all scenarios
```

No semantics change here: every scenario builds real proofs and verifies
them through the full pipeline. RSS comes from `/proc` on Linux.
