# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Proof Engine — developer entry points (V1.0)

.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check clippy demo quick-proof pilot-legal fuzzcheck trace neutrality no-panic domain-tests cddl-validate freeze-guard sbom release-meta clean install interop-py interop-ts interop conformance bench-smoke bench-check scitt-check coverage

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the workspace
	cargo build --locked

test: ## Run all workspace tests
	cargo test --locked

fmt: ## Format code
	cargo fmt

fmt-check: ## Check formatting (CI)
	cargo fmt --check

clippy: ## Run linter (CI)
	cargo clippy --locked --workspace --all-targets -- -D warnings

demo: build ## Run the deterministic demo (PASS → tamper → FAIL → revoke → FAIL)
	cargo run --locked -p proof-cli -- demo

quick-proof: build ## One-shot proof in seconds (hides ID/digest plumbing)
	bash tools/quick_proof.sh

pilot-legal: build ## Pilot integration: legal execution + supersession lifecycle
	bash tools/pilot_legal.sh

web-demo: build ## Generate the browser demo (real CLI output embedded in demo/web/index.html)
	rm -rf /tmp/opencode-webgen
	python3 tools/gen_web_demo.py --work /tmp/opencode-webgen --template demo/web/template.html --out demo/web/index.html

web-check: ## Verify the browser demo data matches fresh core output (honesty gate)
	python3 tools/check_web_demo.py

web-serve: ## Serve the browser demo locally (no app server; static files only)
	python3 -m http.server --directory demo/web 8901

interop-py: build demo ## Second independent verifier (Python, stdlib-only): 37-check differential over golden corpus
	python3 interop/differential.py --repo . --proof-cli $(PROOF_CLI) --work /tmp/proof-interop

interop-ts: ## Third independent verifier (TypeScript): typecheck + differential over golden corpus
	cd interop/ts && (test -d node_modules || npm install --no-audit --no-fund) && PROOF_CLI=$(abspath $(PROOF_CLI)) npm run --silent differential

interop: interop-py interop-ts ## All independent verifiers (Python + TypeScript)

conformance: build ## Full-verdict conformance: replay every golden proof/policy vector through an engine front end and compare recorded verdicts (any implementation can mirror tools/conformance.py)
	python3 tools/conformance.py --repo . --proof-cli $(PROOF_CLI) --work /tmp/proof-conformance

bench-smoke: ## Quick benchmark smoke (2 iters, all scenarios, JSON)
	cargo run --locked -p proof-bench -- --iters 2 --json

bench-check: ## Perf regression gate (release, 20 iters vs committed baseline, 100% + noise floor)
	cargo run --release --locked -p proof-bench -- --iters 20 --check-baseline crates/proof-bench/baseline.json --tolerance 100

coverage: ## Line coverage summary (needs cargo-llvm-cov; ~80% lines at last cut)
	cargo llvm-cov --locked --workspace --summary-only

scitt-check: ## SCITT adapter: Rust tests + independent Python differential
	cargo test --locked -p proof-adapter-scitt
	python3 crates/proof-adapter-scitt/differential.py

# proof-cli path honors CARGO_TARGET_DIR, the local .cargo/config cache, and vanilla target/.
PROOF_CLI ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR)/debug/proof-cli,$(if $(wildcard /root/.cache/proof-target/debug/proof-cli),/root/.cache/proof-target/debug/proof-cli,target/debug/proof-cli))

install: build ## Install proof-cli to ~/.cargo/bin
	cargo install --locked --path crates/proof-cli

trace: ## Check requirement traceability (CI)
	python3 tools/check_traceability.py

neutrality: ## Check domain neutrality (CI)
	python3 tools/check_neutrality.py
	cargo test --locked -p proof-core extensibility_demonstration

no-panic: ## Check no unwrap/expect/panic in production paths (CI)
	python3 tools/check_no_panic.py

cddl-validate: ## Validate golden vectors against CDDL schema
	python3 tools/validate_cddl.py

freeze-guard: ## Check the semantic foundation is untouched since the pin (PE-FREEZE-001)
	python3 tools/check_freeze.py
	python3 tools/check_freeze_selftest.py

sbom: ## Generate the CycloneDX SBOM from Cargo.lock (PE-OPS-006)
	python3 tools/gen_sbom.py --out sbom.cdx.json

release-meta: ## Assemble dist/ with SBOM + provenance + hashes (RELEASE.md)
	mkdir -p $(OUT)
	python3 tools/gen_sbom.py --out $(OUT)/sbom.cdx.json
	cargo build --locked --release -p proof-cli --bin proof-cli
	cp $(TARGET_DIR)/proof-cli $(OUT)/
	python3 tools/gen_provenance.py --artifacts $(OUT)/proof-cli $(OUT)/sbom.cdx.json --sbom $(OUT)/sbom.cdx.json --out $(OUT)/provenance.json
	(cd $(OUT) && sha256sum * > sha256sums.txt)
	@echo "release metadata in $(OUT)/ (sign per RELEASE.md)"

# Resolve the real cargo target dir via metadata (honors CARGO_TARGET_DIR
# env and local .cargo/config.toml target-dir overrides); fall back to
# ./target/release when cargo/metadata is unavailable.
CARGO_TARGET = $(shell cargo metadata --format-version=1 --no-deps 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('target_directory',''))" 2>/dev/null)
TARGET_DIR ?= $(if $(CARGO_TARGET),$(CARGO_TARGET)/release,$(CURDIR)/target/release)

domain-tests: ## Run domain proof-suite tests
	cd domains/proof-domains && cargo test --locked

fuzzcheck: ## Verify fuzz targets + seeds are present
	@test -f fuzz/fuzz_targets/cbor_decoder.rs && test -f fuzz/fuzz_targets/proof_verify.rs && test -f fuzz/fuzz_targets/policy_parser.rs && test -f fuzz/fuzz_targets/graph_ingest.rs && test -f .github/workflows/fuzz.yml && test -n "$$(ls fuzz/seeds/cbor_decoder/)" && test -n "$$(ls fuzz/seeds/proof_verify/)" && test -n "$$(ls fuzz/seeds/policy_parser/)" && test -n "$$(ls fuzz/seeds/graph_ingest/)" && echo "fuzz targets + seeds + workflow present (see VERIFICATION.md for the latest green run)"

clean: ## Remove build artifacts
	cargo clean
	rm -rf demo/out
