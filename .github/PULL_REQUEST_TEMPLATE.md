name: Pull request
description: Propose a change to code, format, or docs.
body:
  - type: checkboxes
    id: gate
    attributes:
      label: Gate
      description: All of these must pass locally before you open the PR (CI enforces the same).
      options:
        - label: `cargo build --locked` succeeds
        - label: `cargo test --locked` passes (all suites)
        - label: `cargo fmt --check` is clean
        - label: `cargo clippy --locked --workspace --all-targets -- -D warnings` is clean
        - label: `make demo` still reproduces byte-identical artifacts
  - type: textarea
    id: what
    attributes:
      label: What does this PR do?
      description: Summarize the change and why it belongs in ProofEngine (see CONTRIBUTING.md ground rules).
    validations:
      required: true
  - type: textarea
    id: tests
    attributes:
      label: Tests
      description: Which tests cover the change? New tests added? Golden fixtures regenerated (never hand-edited)?
    validations:
      required: true
  - type: checkboxes
    id: docs
    attributes:
      label: Documentation
      options:
        - label: Docs describe implemented behavior only (no future features as done)
        - label: CHANGELOG.md updated under an Unreleased heading (if behavior/format/guarantees changed)
        - label: Error-code table (README/FORMAT) updated if new codes were introduced
