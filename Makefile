# -------------------------------------------------------------------------------------------------
# Makefile
# -------------------------------------------------------------------------------------------------

.DEFAULT_GOAL := help

# -- help -----------------------------------------------------------------------------------------
.PHONY: help
help:
	@printf "\nTargets:\n\n"
	@awk 'BEGIN {FS = ":.*##"; OFS = ""} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\nCrate Testing:\n"
	@printf "  make test-air                    # Test air crate\n"
	@printf "  make test-assembly               # Test assembly crate\n"
	@printf "  make test-assembly-syntax        # Test assembly-syntax crate\n"
	@printf "  make test-core                   # Test core crate\n"
	@printf "  make test-vm                     # Test miden-vm crate\n"
	@printf "  make test-processor              # Test processor crate\n"
	@printf "  make test-prover                 # Test prover crate\n"
	@printf "  make test-core-lib               # Test core-lib crate\n"
	@printf "  make test-verifier               # Test verifier crate\n"
	@printf "  make check-constraints          # Check core-lib constraint artifacts\n"
	@printf "  make regenerate-constraints      # Regenerate core-lib constraint artifacts\n"
	@printf "\nExamples:\n"
	@printf "  make test-air test=\"some_test\" # Test specific function\n"
	@printf "  make test-fast                   # Fast tests (no proptests/CLI)\n"
	@printf "  make test-skip-proptests         # All tests except proptests\n"
	@printf "  make check-features              # Check all feature combinations with cargo-hack\n\n"


# -- environment toggles --------------------------------------------------------------------------
BACKTRACE                := RUST_BACKTRACE=1
BUILDDOCS                := MIDEN_BUILD_LIB_DOCS=1
DOCS_NIGHTLY_TOOLCHAIN   ?= nightly

# -- feature configuration ------------------------------------------------------------------------
ALL_FEATURES             := --all-features

# Workspace-wide test features
WORKSPACE_TEST_FEATURES  := concurrent,testing,executable
FAST_TEST_FEATURES       := concurrent,testing

# Feature sets for executable builds
FEATURES_CONCURRENT_EXEC := --features concurrent,executable
FEATURES_METAL_EXEC      := --features concurrent,executable,tracing-forest
FEATURES_LOG_TREE        := --features concurrent,executable,tracing-forest

# Per-crate default features
FEATURES_air             := testing
FEATURES_assembly        := testing
FEATURES_assembly-syntax := testing,serde
FEATURES_core            :=
FEATURES_vm              := concurrent,executable,internal
FEATURES_processor       := concurrent,testing,bus-debugger
FEATURES_project         := resolver
FEATURES_package-registry:= resolver
FEATURES_prover          := concurrent
FEATURES_core-lib        :=
FEATURES_verifier        :=

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Runs Clippy with configs (alias for xclippy)
	cargo +nightly xclippy


.PHONY: xclippy
xclippy: ## Runs Clippy with custom lint config from .cargo/config.toml
	cargo +nightly xclippy


.PHONY: fix
fix: ## Runs Fix with configs (alias for xclippy-fix)
	cargo +nightly xclippy-fix

.PHONY: xclippy-fix
xclippy-fix: ## Runs Clippy with --fix using the same lints as xclippy
	cargo +nightly xclippy-fix


.PHONY: format
format: ## Runs Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Runs Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check

.PHONY: shear
shear: ## Runs cargo-shear to find unused or misplaced dependencies
	cargo shear

.PHONY: lint
lint: xclippy xclippy-fix format ## Runs all linting tasks: check with xclippy, fix issues, then format

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generates & checks documentation for workspace crates only
	rm -rf "$${CARGO_TARGET_DIR:-target}/doc"
	$(BUILDDOCS) RUSTDOCFLAGS="--enable-index-page -Zunstable-options -D warnings" cargo +$(DOCS_NIGHTLY_TOOLCHAIN) doc ${ALL_FEATURES} --keep-going --release --no-deps

.PHONY: serve-docs
serve-docs: ## Serves the docs
	mkdir -p docs/external && cd docs/external && npm run start:dev

# -- core knobs (overridable from CLI or by caller targets) --------------------
# Advanced usage (most users should use pattern rules like 'make test-air'):
#   make core-test CRATE=miden-air FEATURES=testing
#   make core-test CARGO_PROFILE=test-dev FEATURES=testing
#   make core-test CRATE=miden-processor FEATURES=testing EXPR="-E 'not test(#*proptest)'"

NEXTEST_PROFILE ?= default
CARGO_PROFILE   ?= test-dev
CRATE           ?=
FEATURES        ?=
# Filter expression/selector passed through to nextest, e.g.:
#   -E 'not test(#*proptest)'   or   'my::module::test_name'
EXPR            ?=
# Extra args to nextest (e.g., --no-run)
EXTRA           ?=

define _CARGO_NEXTEST
	$(BACKTRACE) cargo nextest run \
		--profile $(NEXTEST_PROFILE) \
		--cargo-profile $(CARGO_PROFILE) \
		$(if $(FEATURES),--features $(FEATURES),) \
		$(if $(CRATE),-p $(CRATE),) \
		$(EXTRA) $(EXPR)
endef

.PHONY: core-test core-test-build
## Core: run tests with overridable CRATE/FEATURES/PROFILES/EXPR/EXTRA
core-test:
	$(BUILDDOCS) $(_CARGO_NEXTEST)

## Core: build test binaries only (no run)
core-test-build:
	$(MAKE) core-test EXTRA="--no-run"

# -- pattern rule: `make test-<crate> [test=...]` ------------------------------
# Primary method for testing individual crates (automatically uses correct features):
#   make test-air                              # Test air crate with default features
#   make test-processor                        # Test processor crate with default features
#   make test-air test="'my::mod::some_test'"  # Test specific function in air crate
.PHONY: test-%
test-%: ## Tests a specific crate; accepts 'test=' to pass a selector or nextest expr
	$(MAKE) core-test \
		CRATE=miden-$* \
		FEATURES=$(FEATURES_$*) \
		EXPR=$(if $(test),$(test),)

# -- workspace-wide tests -------------------------------------------------------------------------

.PHONY: test-build
test-build: ## Build the test binaries for the workspace (no run)
	$(MAKE) core-test-build NEXTEST_PROFILE=ci FEATURES="$(WORKSPACE_TEST_FEATURES)"

.PHONY: test
test: ## Run all tests for the workspace
	$(MAKE) core-test NEXTEST_PROFILE=ci FEATURES="$(WORKSPACE_TEST_FEATURES)"

.PHONY: test-docs
test-docs: ## Run documentation tests (cargo test - nextest doesn't support doctests)
	$(BUILDDOCS) cargo test --doc $(ALL_FEATURES)

# -- filtered test runs ---------------------------------------------------------------------------

.PHONY: test-fast
test-fast: ## Runs fast tests (excludes all CLI tests and proptests)
	$(MAKE) core-test \
		FEATURES="$(FAST_TEST_FEATURES)" \
		EXPR="-E 'not test(#*proptest) and not test(cli_)'"

.PHONY: test-skip-proptests
test-skip-proptests: ## Runs all tests, except property-based tests
	$(MAKE) core-test \
		FEATURES="$(WORKSPACE_TEST_FEATURES)" \
		EXPR="-E 'not test(#*proptest)'"

.PHONY: test-loom
test-loom: ## Runs all loom-based tests
	RUSTFLAGS="--cfg loom" $(MAKE) core-test \
		CRATE=miden-utils-sync \
		FEATURES= \
		EXPR="-E 'test(#*loom)'"

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Checks all targets and features for errors without code generation
	$(BUILDDOCS) cargo check --all-targets ${ALL_FEATURES}

.PHONY: check-features
check-features: ## Checks all feature combinations compile without warnings using cargo-hack
	@scripts/check-features.sh

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Builds with default parameters
	$(BUILDDOCS) cargo build --release --features concurrent

.PHONY: build-no-std
build-no-std: ## Builds without the standard library
	$(BUILDDOCS) cargo build --no-default-features --target wasm32-unknown-unknown --workspace

# --- executable ----------------------------------------------------------------------------------

.PHONY: exec
exec: ## Builds an executable with optimized profile and features
	cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-single
exec-single: ## Builds a single-threaded executable
	cargo build --profile optimized --features executable

.PHONY: exec-avx2
exec-avx2: ## Builds an executable with AVX2 acceleration enabled
	RUSTFLAGS="-C target-feature=+avx2" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-sve
exec-sve: ## Builds an executable with SVE acceleration enabled
	RUSTFLAGS="-C target-feature=+sve" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: regenerate-constraints
regenerate-constraints: ## Regenerate core-lib constraint artifacts
	cargo run --package miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write

.PHONY: check-constraints
check-constraints: ## Check core-lib constraint artifacts for drift
	cargo run --package miden-core-lib --features constraints-tools --bin regenerate-constraints -- --check

.PHONY: exec-info
exec-info: ## Builds an executable with log tree enabled
	cargo build --profile optimized $(FEATURES_LOG_TREE)

# --- examples ------------------------------------------------------------------------------------

.PHONY: run-examples
run-examples: exec ## Runs all masm examples to verify they execute correctly
	@echo "Running masm examples..."
	@failed=0; \
	for masm in miden-vm/masm-examples/*/*.masm miden-vm/masm-examples/*/*/*.masm; do \
		[ -f "$$masm" ] || continue; \
		echo "  $$masm"; \
		if ! ./target/optimized/miden-vm run "$$masm" > /dev/null 2>&1; then \
			echo "    FAILED: $$masm"; \
			failed=1; \
		fi; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "Some examples failed!"; \
		exit 1; \
	fi; \
	echo "All examples passed."

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: check-bench
check-bench: ## Builds all benchmarks
	cargo check --benches --features internal

.PHONY: bench
bench: ## Runs benchmarks
	cargo bench --profile optimized --features internal

# ============================================================
# Fuzzing targets
# ============================================================

.PHONY: fuzz-mast-forest
fuzz-mast-forest: fuzz-seeds ## Run fuzzing for MastForest deserialization
	-@cargo +nightly fuzz run mast_forest_deserialize --release --fuzz-dir miden-core-fuzz

.PHONY: fuzz-mast-validate
fuzz-mast-validate: fuzz-seeds ## Run fuzzing for UntrustedMastForest validation
	-@cargo +nightly fuzz run mast_forest_validate --release --fuzz-dir miden-core-fuzz

.PHONY: fuzz-all
fuzz-all: fuzz-seeds ## Run all fuzz targets (in sequence)
	-@cargo +nightly fuzz run mast_forest_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run mast_forest_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run mast_forest_validate --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run program_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run program_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run kernel_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run kernel_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run stack_io_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run advice_map_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run advice_inputs_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run operation_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run operation_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run execution_proof_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run execution_proof_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run precompile_request_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run precompile_request_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run library_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run library_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run package_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300
	-@cargo +nightly fuzz run package_serde_deserialize --release --fuzz-dir miden-core-fuzz -- -max_total_time=300

.PHONY: fuzz-list
fuzz-list: ## List available fuzz targets
	cargo +nightly fuzz list --fuzz-dir miden-core-fuzz

.PHONY: fuzz-coverage
fuzz-coverage: ## Generate coverage report for fuzz targets
	cargo +nightly fuzz coverage mast_forest_deserialize --fuzz-dir miden-core-fuzz
	cargo +nightly fuzz coverage mast_forest_validate --fuzz-dir miden-core-fuzz

.PHONY: fuzz-seeds
fuzz-seeds: ## Generate seed corpus files for fuzzing
	cargo test -p miden-core generate_fuzz_seeds -- --ignored --nocapture
	cargo test -p miden-mast-package generate_fuzz_seeds -- --ignored --nocapture
