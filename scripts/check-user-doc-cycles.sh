#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Regenerating core library docs..."
MIDEN_BUILD_LIB_DOCS=1 cargo check -p miden-core-lib

echo "Checking user doc cycle counts..."
if command -v python3.12 >/dev/null 2>&1; then
    PYTHON=python3.12
elif command -v python3.11 >/dev/null 2>&1; then
    PYTHON=python3.11
else
    PYTHON=python3
fi
if ! "$PYTHON" -c 'import tomllib' 2>/dev/null; then
    echo "error: Python 3.11+ required (tomllib). Use python3.11 or python3.12." >&2
    exit 1
fi
"$PYTHON" scripts/check_user_doc_cycles.py

echo "Checking assembly cycle fixtures..."
# Processor VM tests need a larger stack than the default test thread stack (see Makefile TEST_RUST_MIN_STACK).
RUST_MIN_STACK="${TEST_RUST_MIN_STACK:-16777216}" \
    cargo test -p miden-processor --lib tests::user_doc_assembly_cycle_fixtures_match_documentation -- --exact
