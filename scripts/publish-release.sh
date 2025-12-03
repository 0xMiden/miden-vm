#!/bin/sh

# Expects
# 1. to be run from the root of the repository
# 2. for ~/.cargo/credentials.toml to contain your crates.io token (see
#   https://doc.rust-lang.org/cargo/reference/publishing.html)
#
# It is recommended to run this script while still on the `next` branch right before merging it into
# `main`, so that if any error occurs, we can fix it and re-run the script directly without having
# to merge the fix into `next`, and then merge `next` into `main` again.

cargo publish -p miden-utils-sync
cargo publish -p miden-utils-diagnostics
cargo publish -p miden-utils-indexing
cargo publish -p miden-debug-types
cargo publish -p miden-utils-core-derive
cargo publish -p miden-core
cargo publish -p miden-air
cargo publish -p miden-assembly-syntax
cargo publish -p miden-mast-package
cargo publish -p miden-assembly
cargo publish -p miden-processor
cargo publish -p miden-prover
cargo publish -p miden-verifier
cargo publish -p miden-libcore
cargo publish -p miden-vm
