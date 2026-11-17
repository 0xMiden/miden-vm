#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Treat Cargo and rustc lint warnings as errors.
export CARGO_BUILD_WARNINGS=deny
export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIB_DOCS=1

# Run cargo-hack with comprehensive feature checking
cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default,python \
    --all-targets

echo "All feature combinations compiled successfully!"
