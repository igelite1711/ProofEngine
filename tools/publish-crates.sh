#!/usr/bin/env bash
# Publish ProofEngine crates to crates.io in dependency order.
# Usage:
#   1. cargo login   # paste your crates.io token once (stored in ~/.cargo/credentials.toml)
#      # OR export CARGO_REGISTRY_TOKEN=cio_... (CI / one-shot, never commit it)
#   2. ./tools/publish-crates.sh [--dry-run]
#      ./tools/publish-crates.sh        # real publish
#
# Notes:
# - Publishes are permanent and versions can never be overwritten.
# - Publish in dependency order; wait ~60s between crates so the index updates.
#   `cargo publish --dry-run` FAILS for dependent crates until their deps are
#   actually on crates.io ("no matching package named proof-core found") —
#   that is normal. Only proof-core can dry-run before anything is published.
# - Uses --locked for reproducible builds (PE-OPS-001).
# - Commit Cargo.toml metadata changes before real publish (cargo refuses dirty tree).
set -euo pipefail

DRY_RUN=""
ALLOW_DIRTY=""
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="--dry-run"
  ALLOW_DIRTY="--allow-dirty"  # dry-run only; real publish requires clean tree
  echo ">>> DRY RUN mode (no upload)"
fi

if [[ -z "$DRY_RUN" ]]; then
  if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]] && [[ ! -f "$HOME/.cargo/credentials.toml" ]]; then
    echo "ERROR: no credentials found."
    echo "Run 'cargo login' first, or export CARGO_REGISTRY_TOKEN."
    exit 1
  fi
  if ! git diff --quiet; then
    echo "ERROR: working tree is dirty. Commit first (cargo publish refuses dirty tree)."
    git status --short
    exit 1
  fi
fi

CRATES=(
  proof-core
  proof-format
  proof-crypto
  proof-graph
  proof-verify
  proof-policy
  proof-cli
)

for crate in "${CRATES[@]}"; do
  echo "================ $crate ================"
  # shellcheck disable=SC2086
  cargo publish -p "$crate" --locked $DRY_RUN $ALLOW_DIRTY
  # Give crates.io index time to catch up before the next crate that depends on this one
  if [[ -z "$DRY_RUN" ]]; then
    echo "Published $crate, sleeping 60s for index propagation..."
    sleep 60
  fi
done

echo "All crates published."
echo "Verify: https://crates.io/crates/proof-core etc."
echo "Install CLI: cargo install proof-cli --locked"
