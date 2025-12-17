#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIB_DOCS=1

# Run cargo-hack with comprehensive feature checking
# Note: legacy-stark-tests is excluded because it contains Winterfell-era tests that need updating
cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default,legacy-stark-tests \
    --all-targets

echo "All feature combinations compiled successfully!"
