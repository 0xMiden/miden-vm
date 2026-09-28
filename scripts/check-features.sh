#!/bin/bash

set -euo pipefail

# Script to check individual features compile without warnings
# This script ensures that warnings are treated as errors for CI

echo "Checking workspace features with cargo-hack..."

# Treat Cargo and rustc lint warnings as errors.
export CARGO_BUILD_WARNINGS=deny
export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIB_DOCS=1

# Check individual features and all targets.
cargo hack check \
    --workspace \
    --each-feature \
    --exclude-features default,python \
    --all-targets

# Dev-dependencies can enable std and hide broken library feature configurations.
# Exclude packages that have no library target from this pass.
cargo hack check \
    --workspace \
    --exclude miden-bench \
    --exclude miden-release-policy \
    --exclude miden-format \
    --each-feature \
    --exclude-features default \
    --lib \
    --no-dev-deps

echo "Workspace feature checks passed!"
