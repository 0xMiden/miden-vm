#!/bin/bash
set -euo pipefail

# Source Cargo configuration can run wrappers or credential providers.
# Package verification has already completed in a job without OIDC access.
if [[ -e .cargo || -L .cargo ]]; then
    mv .cargo "$RUNNER_TEMP/release-source-cargo-config"
fi
version="$(sed -n 's/^channel *= *"\([0-9.]*\)".*/\1/p' rust-toolchain.toml)"
[[ "$version" =~ ^1\.[0-9]+\.[0-9]+$ ]] || {
    echo '::error::Release publication requires a numbered Rust toolchain.' >&2
    exit 1
}
rustup toolchain install "$version" --profile minimal --no-self-update
{
    echo "RUSTUP_TOOLCHAIN=$version"
    echo "CARGO_HOME=$RUNNER_TEMP/release-cargo-home"
    echo 'RUSTC=rustc'
    echo 'RUSTC_WRAPPER='
    echo 'RUSTC_WORKSPACE_WRAPPER='
} >> "$GITHUB_ENV"
