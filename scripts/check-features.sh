#!/bin/bash

set -euo pipefail

# Script to check all feature combinations compile without warnings.
# This script ensures that warnings are treated as errors for CI.

echo "Checking all feature combinations with cargo-hack..."

# Set environment variables to treat warnings as errors.
export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIB_DOCS=1

cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default \
    --all-targets

echo ""
echo "Checking targeted multi-feature combinations..."

# `cargo hack --each-feature` does not cover combinations like
# `miden-lifted-stark/testing,concurrent`.
cargo check -p miden-lifted-stark --all-targets --features testing,concurrent

echo "All feature combinations compiled successfully!"
