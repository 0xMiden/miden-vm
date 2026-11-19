#!/bin/bash
# Guardrails for issue #3111:
# 1. Regenerated core-lib docs under crates/lib/core/docs/ must match what is committed.
# 2. clk measurement fixtures for assembly / core-lib cycle counts must still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Regenerating core library docs..."
MIDEN_BUILD_LIB_DOCS=1 cargo check -p miden-core-lib

if [ -n "$(git status --porcelain crates/lib/core/docs)" ]; then
    echo "ERROR: Found uncommitted changes in crates/lib/core/docs/" >&2
    echo "Assembly comments changed but generated documentation was not committed." >&2
    echo "" >&2
    echo "To fix:" >&2
    echo "  1. MIDEN_BUILD_LIB_DOCS=1 cargo build -p miden-core-lib" >&2
    echo "  2. Commit the changes under crates/lib/core/docs/" >&2
    echo "" >&2
    git status crates/lib/core/docs >&2
    echo "" >&2
    git diff crates/lib/core/docs >&2
    exit 1
fi
echo "Generated core-lib docs match the committed tree."

echo "Checking assembly cycle fixtures..."
# Processor VM tests need a larger stack than the default test thread stack (see Makefile TEST_RUST_MIN_STACK).
RUST_MIN_STACK="${TEST_RUST_MIN_STACK:-16777216}" \
    cargo test -p miden-processor --lib tests::user_doc_assembly_cycle_fixtures_match_documentation -- --exact

echo "Checking core-lib num_leaves_to_num_peaks cycle fixture..."
RUST_MIN_STACK="${TEST_RUST_MIN_STACK:-16777216}" \
    cargo test -p miden-core-lib --test core-lib \
    collections::mmr::test_num_leaves_to_num_peaks_cycle_count -- --exact
