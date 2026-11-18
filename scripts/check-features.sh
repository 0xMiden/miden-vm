#!/bin/bash

set -euo pipefail

export RUSTFLAGS="-D warnings"
export MIDEN_BUILD_LIB_DOCS=1

check_all_targets() {
    CARGO_BUILD_WARNINGS=deny cargo hack check \
        --workspace \
        --each-feature \
        --exclude-features default,python \
        --all-targets
}

check_libraries() {
    # Dev-dependencies can enable std and hide broken library feature configurations.
    # Removing them can leave valid workspace dependencies unused.
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
}

case "${1:-all}" in
    all)
        check_all_targets
        check_libraries
        ;;
    all-targets) check_all_targets ;;
    libraries) check_libraries ;;
    *)
        echo "Usage: $0 [all|all-targets|libraries]" >&2
        exit 2
        ;;
esac

echo "Workspace feature checks passed!"
