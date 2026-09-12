# Fuzzing

cargo-fuzz targets for the trust-critical parsers and the verifier. These are
the inputs an attacker controls directly (threat model A4: malicious input
supplier), so they get adversarial testing beyond the hand-written negative
matrix.

## Targets and invariants

| Target | Entry point | Invariant |
|---|---|---|
| `cbor_decoder` | `proof_format::cbor::{decode_strict, encode_canonical}` | accepted bytes re-encode to themselves (canonical round-trip), and re-decode identically |
| `proof_verify` | `proof_verify::verify_proof` | never panics; `Invalid` always carries codes (no silent failure); verdict + codes deterministic (a legitimate proof may be crypto-`Valid` — tamper-resistance is pinned by the stable mutation-soak instead) |
| `policy_parser` | `proof_policy::parse_policy` | never panics; closed requirement set; deterministic re-parse |
| `graph_ingest` | `proof_graph::validate_graph` | never panics; bounded counts; supersedes cycles always rejected |

## Running

Requires nightly Rust and cargo-fuzz (nightly CI smoke: `.github/workflows/fuzz.yml`, 600s per target; first log appears after the first scheduled run — see VERIFICATION.md):

```console
rustup install nightly
cargo install cargo-fuzz
CXX=/usr/bin/g++ cargo +nightly fuzz build
CXX=/usr/bin/g++ cargo +nightly fuzz run policy_parser fuzz/seeds/policy_parser -- -max_total_time=600
```

Troubleshooting (observed failure modes, all environmental — never findings):

- `cargo fuzz build` on **stable** fails (`-Zsanitizer=address` needs
  nightly: `failed to run rustc ... -Zsanitizer=address`). Always use
  `cargo +nightly fuzz`.
- Link errors mentioning Android/`clang++` on Termux: export
  `CXX=/usr/bin/g++` first (the Termux `clang++` targets Android).
- `AddressSanitizer: CHECK failed ... unable to mmap` on `fuzz run`: the
  ASan runtime cannot allocate under PRoot — running is blocked in this
  container by design (see below). The 600s smokes run in
  `.github/workflows/fuzz.yml` (ubuntu-latest) instead.

`fuzz/seeds/<target>/` holds deterministic seeds derived from the golden
fixtures (a valid event, a valid 1.5 KiB proof, a one-byte tamper of it,
truncations, valid and hostile policies, a supersedes cycle). Start every run
with the corpus seeded from these so regressions are caught from minute one:

```console
cargo +nightly fuzz run cbor_decoder fuzz/seeds/cbor_decoder -- -max_total_time=600
```

Any finding: capture the crashing input, minimize with `-runs=1` on the
artifacts dir, and attach it to a bug with the target name and the invariant
that broke. Findings on signature/policy/graph paths are trust-critical — see
`SECURITY.md` for coordinated disclosure.

## Local build status (2026-09-07)

All four targets **build** under nightly (`cargo +nightly fuzz build`
verified; this container needs `CXX=/usr/bin/g++` because the Termux
`clang++` targets Android). **Running** them here is blocked: the
AddressSanitizer runtime cannot `mmap` its shadow memory under PRoot
(`AddressSanitizer: CHECK failed ... unable to mmap`). The 600s-per-target
runs happen in `.github/workflows/fuzz.yml` (ubuntu-latest): **green
latest green CI run, 4/4 success, no findings.** The stable
counterparts — mutation-soak (`crates/proof-verify/tests/soak.rs`),
proptests (`crates/proof-format/src/cbor.rs`), golden negatives — stay
enforced on every push alongside the nightly fuzz.

## Stable-machine alternative (no nightly required)

The same invariants run on stable as regular tests, so machines and CI without
nightly still exercise them continuously:

- `cbor_decoder` / random-bytes invariants: property tests in
  `crates/proof-format/src/cbor.rs` (proptest round-trip + raw-bytes reject-or-round-trip).
- `proof_verify` mutation soak: `crates/proof-verify/tests/soak.rs` mutates a
  valid proof (bit flips, byte deletions, truncations) and asserts fail-closed
  on every mutant.
- `policy_parser` seed corpus: `crates/proof-policy/tests/fuzz_seeds.rs`
  replays every file in `fuzz/seeds/policy_parser/` through the fuzz target's
  invariants (never panics, closed 16-requirement set, deterministic
  re-parse) plus hostile-seed rejection — so the smoke target's contract is
  enforced on stable too.
- `cbor_decoder` seed corpus: `crates/proof-format/tests/fuzz_seeds.rs`
  replays every file in `fuzz/seeds/cbor_decoder/` through the exact
  target invariant (reject or byte-identical re-encode) plus hostile inputs.
- `graph_ingest` seed corpus: `crates/proof-graph/tests/fuzz_seeds.rs`
  replays every file in `fuzz/seeds/graph_ingest/` through the target
  harness (counts within limits, cycles rejected) plus hostile graphs.
- `proof_verify` seed corpus: `crates/proof-verify/tests/fuzz_seeds.rs`
  replays every file in `fuzz/seeds/proof_verify/` through the target
  invariants (coherence + determinism); tamper-resistance stays pinned by
  the 2000-mutant soak alongside it.
