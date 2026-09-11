# Copyright 2026 Proof Engine Contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Proof Engine — developer entry points (V1.0)

.DEFAULT_GOAL := help

.PHONY: help build test fmt fmt-check clippy demo fuzzcheck trace neutrality no-panic domain-tests cddl-validate freeze-guard clean install

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

web-demo: build ## Generate the browser demo (real CLI output embedded in demo/web/index.html)
	rm -rf /tmp/opencode-webgen
	python3 tools/gen_web_demo.py --work /tmp/opencode-webgen --template demo/web/template.html --out demo/web/index.html

web-check: ## Verify the browser demo data matches fresh core output (honesty gate)
	python3 tools/check_web_demo.py

web-serve: ## Serve the browser demo locally (no app server; static files only)
	python3 -m http.server --directory demo/web 8901

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

domain-tests: ## Run domain proof-suite tests
	cd domains/proof-domains && cargo test --locked

fuzzcheck: ## Verify fuzz targets are present
	@test -f fuzz/fuzz_targets/cbor_decoder.rs && test -f fuzz/fuzz_targets/proof_verify.rs && test -f fuzz/fuzz_targets/policy_parser.rs && test -f fuzz/fuzz_targets/graph_ingest.rs && test -f .github/workflows/fuzz.yml && echo "fuzz targets + workflow present (see VERIFICATION.md for the latest green run)"

clean: ## Remove build artifacts
	cargo clean
	rm -rf demo/out
