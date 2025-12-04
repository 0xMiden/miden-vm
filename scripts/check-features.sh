#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors
export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIBCORE_DOCS=1

# Run cargo-hack with comprehensive feature checking
cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default \
    --all-targets

echo "All feature combinations compiled successfully!"
