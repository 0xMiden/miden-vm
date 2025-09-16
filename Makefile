# ------------------------------------------------------------------------------
# Makefile
# ------------------------------------------------------------------------------

.DEFAULT_GOAL := help

# -- help ----------------------------------------------------------------------
.PHONY: help
help:
	@printf "\nTargets:\n\n"
	@awk 'BEGIN {FS = ":.*##"; OFS = ""} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\nExamples:\n"
	@printf "  make core-test CRATE=miden-air FEATURES=testing\n"
	@printf "  make test-fast\n"
	@printf "  make test-skip-proptests\n"
	@printf "  make test-air test=\"-E '\''package(miden-air) & test(#*foo)'\''\"\n\n"


# -- environment toggles -------------------------------------------------------
BACKTRACE          = RUST_BACKTRACE=1
WARNINGS           = RUSTDOCFLAGS="-D warnings"
DEBUG_ASSERTIONS   = RUSTFLAGS="-C debug-assertions"

# -- doc help ------------------------------------------------------------------
ALL_FEATURES_BUT_ASYNC=--features concurrent,executable,metal,testing,with-debug-info,internal

# Feature sets for executable builds
FEATURES_CONCURRENT_EXEC := --features concurrent,executable
FEATURES_METAL_EXEC := --features concurrent,executable,metal,tracing-forest
FEATURES_LOG_TREE := --features concurrent,executable,tracing-forest

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
# Examples:
#   make core-test CRATE=miden-air FEATURES=testing
#   make core-test CARGO_PROFILE=test-fast FEATURES="testing,no_err_ctx"
#   make core-test CRATE=miden-processor FEATURES=testing EXPR="-E 'not test(#*proptest)'"

# Use test-dev profile consistently (like origin/main)
NEXTEST_PROFILE ?= ci
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
# Usage:
#   make test-air
#   make test-air test="'my::mod::some_test'"
.PHONY: test-%
test-%: ## Tests a specific crate; accepts 'test=' to pass a selector or nextest expr
	$(DEBUG_ASSERTIONS) $(MAKE) core-test \
		CRATE=miden-$* \
		FEATURES=$(FEATURES_$*) \
		EXPR=$(if $(test),$(test),)

# -- top-level convenience targets ---------------------------------------------

.PHONY: test-build
test-build: ## Build the test binaries for the workspace (no run)
	$(MAKE) core-test-build FEATURES="concurrent,testing,executable"

.PHONY: test
test: ## Run all tests for the workspace
	$(MAKE) core-test FEATURES="concurrent,testing,executable"

.PHONY: test-docs
test-docs: ## Run documentation tests (cargo test - nextest doesn't support doctests)
	cargo test --doc $(ALL_FEATURES_BUT_ASYNC)

.PHONY: test-fast
test-fast: ## Runs fast tests (excludes all CLI tests and proptests)
	$(DEBUG_ASSERTIONS) $(MAKE) core-test \
		FEATURES="testing,no_err_ctx" \
		EXPR="-E 'not test(#*proptest) and not test(cli_)'"

.PHONY: test-skip-proptests
test-skip-proptests: ## Runs all tests, except property-based tests
	$(DEBUG_ASSERTIONS) $(MAKE) core-test \
		FEATURES=testing \
		EXPR="-E 'not test(#*proptest)'"

.PHONY: test-loom
test-loom: ## Runs all loom-based tests
	RUSTFLAGS="--cfg loom" $(MAKE) core-test \
		FEATURES=testing \
		EXPR="-E 'test(#*loom)'"

# -- per-crate default features ------------------------------------------------
FEATURES_air             := testing
FEATURES_assembly        := testing
FEATURES_assembly-syntax := testing
FEATURES_core            :=
FEATURES_miden-vm        := concurrent,executable,metal,internal
FEATURES_processor       := concurrent,testing
FEATURES_prover          := concurrent,metal
FEATURES_stdlib          := with-debug-info
FEATURES_verifier        :=

# -- compatibility aliases (optional; pattern rule already covers them) --------
.PHONY: test-air test-assembly test-assembly-syntax test-core test-miden-vm test-processor test-prover test-stdlib test-verifier
test-air: ## Tests miden-air package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-air              FEATURES="$(FEATURES_air)"               EXPR=$(if $(test),$(test),)
test-assembly: ## Tests miden-assembly package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-assembly         FEATURES="$(FEATURES_assembly)"          EXPR=$(if $(test),$(test),)
test-assembly-syntax: ## Tests miden-assembly-syntax package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-assembly-syntax  FEATURES="$(FEATURES_assembly-syntax)"   EXPR=$(if $(test),$(test),)
test-core: ## Tests miden-core package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-core             FEATURES="$(FEATURES_core)"              EXPR=$(if $(test),$(test),)
test-miden-vm: ## Tests miden-vm package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-vm               FEATURES="$(FEATURES_miden-vm)"           EXPR=$(if $(test),$(test),)
test-processor: ## Tests miden-processor package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-processor        FEATURES="$(FEATURES_processor)"         EXPR=$(if $(test),$(test),)
test-prover: ## Tests miden-prover package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-prover           FEATURES="$(FEATURES_prover)"            EXPR=$(if $(test),$(test),)
test-stdlib: ## Tests miden-stdlib package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-stdlib           FEATURES="$(FEATURES_stdlib)"            EXPR=$(if $(test),$(test),)
test-verifier: ## Tests miden-verifier package
	$(DEBUG_ASSERTIONS) $(MAKE) core-test CRATE=miden-verifier         FEATURES="$(FEATURES_verifier)"          EXPR=$(if $(test),$(test),)


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

# --- executable ------------------------------------------------------------------------------------

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
