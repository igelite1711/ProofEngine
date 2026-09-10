# Proof Engine — Release Checklist (V1)

No release cut yet. When V1 is ready, this file gates the cut.

## Gate

- [ ] `cargo test --locked` green on a clean checkout.
- [ ] `cargo fmt --check` and `cargo clippy --locked --workspace --all-targets` (zero warnings) green.
- [ ] `make demo` reproduces `demo/out/` byte-for-byte.
- [ ] `make trace`, `make neutrality`, `make web-check`, `make cddl-validate` green.
- [ ] `make domain-tests` green.
- [ ] Record the release commit, `Cargo.lock` hash, and test counts in the
  release notes; tag the commit.
