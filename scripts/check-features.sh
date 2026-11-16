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
# cargo-hack temporarily removes dev-dependencies, leaving valid workspace declarations unused.
# Enforce Cargo warnings in the complete pass above and rustc warnings in both passes.
CARGO_BUILD_WARNINGS=warn cargo hack check \
    --workspace \
    --exclude miden-bench \
    --exclude miden-debug-lit-support \
    --exclude miden-release-policy \
    --exclude miden-format \
    --each-feature \
    --exclude-features default,python \
    --lib \
    --no-dev-deps

echo "Workspace feature checks passed!"
