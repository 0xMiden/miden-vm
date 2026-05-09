.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

ALL_FEATURES_EXCEPT_ROCKSDB="concurrent executable internal serde std"
MIDEN_STARK_TEST_PACKAGES=-p miden-lifted-air -p miden-lifted-stark -p miden-stateful-hasher -p miden-stark-transcript
MIDEN_CRYPTO_FUZZ_TARGETS=word merkle merkle_store smt_serde partial_smt mmr crypto aead signatures
MIDEN_SERDE_UTILS_FUZZ_TARGETS=primitives collections string vint64 goldilocks budgeted
WARNINGS=RUSTDOCFLAGS="-D warnings"

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Run Clippy with configs (alias for xclippy)
	cargo xclippy

.PHONY: xclippy
xclippy: ## Run Clippy with the curated workspace lint set
	cargo xclippy

.PHONY: fix
fix: ## Run Fix with configs (alias for xclippy-fix)
	cargo xclippy-fix

.PHONY: xclippy-fix
xclippy-fix: ## Run Clippy with --fix using the same lint set as xclippy
	cargo xclippy-fix


.PHONY: format
format: ## Run Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Run Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check

.PHONY: shear
shear: ## Runs cargo-shear to find unused or misplaced dependencies
	cargo shear --deny-warnings

.PHONY: toml
toml: ## Runs Format for all TOML files
	taplo fmt

.PHONY: toml-check
toml-check: ## Runs Format for all TOML files but only in check mode
	taplo fmt --check --verbose

.PHONY: typos-check
typos-check: ## Runs spellchecker
	typos

.PHONY: workspace-check
workspace-check: ## Runs a check that all packages have `lints.workspace = true`
	cargo workspace-lints

.PHONY: cargo-deny
cargo-deny: ## Run cargo-deny to check dependencies for security vulnerabilities and license compliance
	cargo deny check

.PHONY: zeroize-audit
zeroize-audit: ## Run Zeroize audit using rustdoc JSON
	cargo +nightly rustdoc -p miden-crypto --all-features -- -Zunstable-options --output-format json --document-private-items
	@target_dir="$${CARGO_TARGET_DIR:-target}"; \
	if [ "$$target_dir" = "/" ]; then target_dir=target; fi; \
	cargo run --quiet --manifest-path tools/zeroize-audit/Cargo.toml -- "$$target_dir/doc/miden_crypto.json"

.PHONY: lint
lint: clippy fix format toml typos-check shear cargo-deny ## Run all linting tasks at once (Clippy, fixing, formatting, cargo-shear, cargo-deny)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generate and check documentation for workspace crates only
	rm -rf "${CARGO_TARGET_DIR:-target}/doc"
	RUSTDOCFLAGS="--enable-index-page -Zunstable-options -D warnings" cargo +nightly doc --all-features --keep-going --release --no-deps

# --- testing -------------------------------------------------------------------------------------

.PHONY: test-default
test-default: ## Run tests with default features
	cargo nextest run --profile default --cargo-profile test-release --features ${ALL_FEATURES_EXCEPT_ROCKSDB}

.PHONY: test-no-std
test-no-std: ## Run tests with `no-default-features` (std)
	cargo nextest run --profile default --cargo-profile test-release --no-default-features

.PHONY: test-smt-concurrent
test-smt-concurrent: ## Run only concurrent SMT tests
	cargo nextest run --profile smt-concurrent --cargo-profile test-release

.PHONY: test-docs
test-docs:
	cargo test --doc --all-features --profile test-release

.PHONY: test-p3-parallel
test-p3-parallel: ## Run Miden STARK crate tests with the parallel feature enabled
	cargo test $(MIDEN_STARK_TEST_PACKAGES) -F miden-lifted-stark/parallel

.PHONY: test-large-smt
test-large-smt: ## Run large SMT unit tests and RocksDB integration tests
	cargo nextest run --success-output immediate --profile large-smt --cargo-profile test-release --features rocksdb

.PHONY: test
test: test-default test-no-std test-docs test-large-smt ## Run all tests except concurrent SMT tests

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	cargo check --all-targets --all-features

.PHONY: check-features
check-features: ## Check curated feature combinations across the integrated workspace
	./scripts/check-features.sh

.PHONY: check-fuzz
check-fuzz: ## Check and link fuzz targets
	cd miden-crypto-fuzz && cargo check --locked
	cd miden-serde-utils/fuzz && cargo check --locked
	for target in $(MIDEN_CRYPTO_FUZZ_TARGETS); do \
		cargo +nightly fuzz build --fuzz-dir miden-crypto-fuzz $$target; \
	done
	for target in $(MIDEN_SERDE_UTILS_FUZZ_TARGETS); do \
		(cd miden-serde-utils && cargo +nightly fuzz build $$target); \
	done

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Build with default features enabled
	cargo build --release

.PHONY: build-no-std
build-no-std: ## Build without the standard library
	cargo build --release --no-default-features --target wasm32-unknown-unknown

.PHONY: build-target-miden
build-target-miden: ## Build `miden-field` for wasm32-wasip2 with `--cfg miden`
	RUSTFLAGS="$${RUSTFLAGS:+$$RUSTFLAGS }--cfg miden" cargo build --release -p miden-field --target wasm32-wasip2

.PHONY: build-avx2
build-avx2: ## Build with avx2 support
	RUSTFLAGS="-C target-feature=+avx2" cargo build --release

.PHONY: build-avx512
build-avx512: ## Build with avx512 support
	RUSTFLAGS="-C target-feature=+avx512f,+avx512dq" cargo build --release

.PHONY: build-sve
build-sve: ## Build with sve support
	RUSTFLAGS="-C target-feature=+sve" cargo build --release

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench
bench: ## Run crypto benchmarks
	cargo bench --features concurrent

.PHONY: bench-smt-concurrent
bench-smt-concurrent: ## Run SMT benchmarks with concurrent feature
	cargo run --bin miden-crypto --release --features concurrent,executable -- --size 1000000

.PHONY: bench-large-smt-memory
bench-large-smt-memory: ## Run large SMT benchmarks with memory storage
	cargo run --bin miden-crypto --release --features concurrent,executable -- --size 1000000

.PHONY: bench-large-smt-rocksdb
bench-large-smt-rocksdb: ## Run large SMT benchmarks with rocksdb storage
	cargo run --bin miden-crypto --release --features concurrent,rocksdb,executable -- --storage rocksdb --size 1000000

.PHONY: bench-large-smt-rocksdb-open
bench-large-smt-rocksdb-open: ## Run large SMT benchmarks with rocksdb storage and open existing database
	cargo run --bin miden-crypto --release --features concurrent,rocksdb,executable -- --storage rocksdb --open

# --- fuzzing --------------------------------------------------------------------------------

.PHONY: fuzz-smt
fuzz-smt: ## Run fuzzing for SMT (sequential vs parallel consistency)
	cargo +nightly fuzz run smt --release --fuzz-dir miden-crypto-fuzz -- -max_len=10485760

.PHONY: fuzz-word
fuzz-word: ## Run fuzzing for Word serialization
	cargo +nightly fuzz run word --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-merkle
fuzz-merkle: ## Run fuzzing for Merkle tree serialization
	cargo +nightly fuzz run merkle --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-merkle-store
fuzz-merkle-store: ## Run fuzzing for MerkleStore deserialization
	cargo +nightly fuzz run merkle_store --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-smt-serde
fuzz-smt-serde: ## Run fuzzing for SMT serialization
	cargo +nightly fuzz run smt_serde --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-partial-smt
fuzz-partial-smt: ## Run fuzzing for PartialSmt deserialization
	cargo +nightly fuzz run partial_smt --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-mmr
fuzz-mmr: ## Run fuzzing for MMR structures serialization
	cargo +nightly fuzz run mmr --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-crypto
fuzz-crypto: ## Run fuzzing for cryptographic types serialization
	cargo +nightly fuzz run crypto --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-aead
fuzz-aead: ## Run fuzzing for AEAD decryption paths
	cargo +nightly fuzz run aead --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-signatures
fuzz-signatures: ## Run fuzzing for DSA signature deserialization
	cargo +nightly fuzz run signatures --release --fuzz-dir miden-crypto-fuzz

# --- installing ----------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v typos >/dev/null 2>&1 && echo "[OK] typos is installed" || echo "[MISSING] typos is not installed (run: make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] nextest is installed" || echo "[MISSING] nextest is not installed (run: make install-tools)"
	@command -v taplo >/dev/null 2>&1 && echo "[OK] taplo is installed" || echo "[MISSING] taplo is not installed (run: make install-tools)"
	@command -v cargo-shear >/dev/null 2>&1 && echo "[OK] cargo-shear is installed" || echo "[MISSING] cargo-shear is not installed (run: make install-tools)"
	@command -v cargo deny >/dev/null 2>&1 && echo "[OK] cargo-deny is installed" || echo "[MISSING] cargo-deny is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs development tools required by the Makefile (typos, nextest, taplo, cargo-shear, cargo-deny)
	@echo "Installing development tools..."
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-shear --locked
	cargo install cargo-deny --locked
	@echo "Development tools installation complete!"
