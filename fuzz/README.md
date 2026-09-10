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
cargo +nightly fuzz run cbor_decoder -- -max_total_time=600
cargo +nightly fuzz run proof_verify -- -max_total_time=600
cargo +nightly fuzz run policy_parser -- -max_total_time=600
cargo +nightly fuzz run graph_ingest -- -max_total_time=600
```

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
