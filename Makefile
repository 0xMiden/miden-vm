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
	@printf "  make test-miden-vm               # Test miden-vm crate\n"
	@printf "  make test-processor              # Test processor crate\n"
	@printf "  make test-prover                 # Test prover crate\n"
	@printf "  make test-stdlib                 # Test stdlib crate\n"
	@printf "  make test-verifier               # Test verifier crate\n"
	@printf "\nExamples:\n"
	@printf "  make test-air test=\"some_test\"   # Test specific function\n"
	@printf "  make test-fast                   # Fast tests (no proptests/CLI)\n"
	@printf "  make test-skip-proptests         # All tests except proptests\n\n"


# -- environment toggles --------------------------------------------------------------------------
BACKTRACE                := RUST_BACKTRACE=1
WARNINGS                 := RUSTDOCFLAGS="-D warnings"

# -- feature configuration ------------------------------------------------------------------------
ALL_FEATURES_BUT_ASYNC   := --features concurrent,executable,metal,testing,with-debug-info,internal

# Workspace-wide test features
WORKSPACE_TEST_FEATURES  := concurrent,testing,metal,executable
FAST_TEST_FEATURES       := concurrent,testing,metal,no_err_ctx

# Feature sets for executable builds
FEATURES_CONCURRENT_EXEC := --features concurrent,executable
FEATURES_METAL_EXEC      := --features concurrent,executable,metal,tracing-forest
FEATURES_LOG_TREE        := --features concurrent,executable,tracing-forest

# Per-crate default features
FEATURES_air             := testing
FEATURES_assembly        := testing
FEATURES_assembly-syntax := testing
FEATURES_core            :=
FEATURES_miden-vm        := concurrent,executable,metal,internal
FEATURES_processor       := concurrent,testing,bus-debugger
FEATURES_prover          := concurrent,metal
FEATURES_stdlib          := with-debug-info
FEATURES_verifier        :=

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Runs Clippy with configs
	cargo +nightly clippy --workspace --all-targets ${ALL_FEATURES_BUT_ASYNC} -- -D warnings


.PHONY: fix
fix: ## Runs Fix with configs
	cargo +nightly fix --allow-staged --allow-dirty --all-targets ${ALL_FEATURES_BUT_ASYNC}


.PHONY: format
format: ## Runs Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Runs Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check


.PHONY: lint
lint: format fix clippy ## Runs all linting tasks at once (Clippy, fixing, formatting)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generates & checks documentation
	$(WARNINGS) cargo doc ${ALL_FEATURES_BUT_ASYNC} --keep-going --release

.PHONY: book
book: ## Builds the book & serves documentation site
	mdbook serve --open docs

# -- core knobs (overridable from CLI or by caller targets) --------------------
# Advanced usage (most users should use pattern rules like 'make test-air'):
#   make core-test CRATE=miden-air FEATURES=testing
#   make core-test CARGO_PROFILE=test-dev FEATURES="testing,no_err_ctx"
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
	$(_CARGO_NEXTEST)

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
	cargo test --doc $(ALL_FEATURES_BUT_ASYNC)

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
	cargo check --all-targets ${ALL_FEATURES_BUT_ASYNC}

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Builds with default parameters
	cargo build --release --features concurrent

.PHONY: build-no-std
build-no-std: ## Builds without the standard library
	cargo build --no-default-features --target wasm32-unknown-unknown --workspace

# --- executable ----------------------------------------------------------------------------------

.PHONY: exec
exec: ## Builds an executable with optimized profile and features
	cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-single
exec-single: ## Builds a single-threaded executable
	cargo build --profile optimized --features executable

.PHONY: exec-metal
exec-metal: ## Builds an executable with Metal acceleration enabled
	cargo build --profile optimized $(FEATURES_METAL_EXEC)

.PHONY: exec-avx2
exec-avx2: ## Builds an executable with AVX2 acceleration enabled
	RUSTFLAGS="-C target-feature=+avx2" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-sve
exec-sve: ## Builds an executable with SVE acceleration enabled
	RUSTFLAGS="-C target-feature=+sve" cargo build --profile optimized $(FEATURES_CONCURRENT_EXEC)

.PHONY: exec-info
exec-info: ## Builds an executable with log tree enabled
	cargo build --profile optimized $(FEATURES_LOG_TREE)

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: check-bench
check-bench: ## Builds all benchmarks (incl. those needing no_err_ctx)
	cargo check --benches --features internal,no_err_ctx

.PHONY: bench
bench: ## Runs benchmarks
	cargo bench --profile optimized --features internal,no_err_ctx
