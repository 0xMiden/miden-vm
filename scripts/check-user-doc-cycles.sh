#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Regenerating core library docs..."
MIDEN_BUILD_LIB_DOCS=1 cargo check -p miden-core-lib

echo "Checking user doc cycle counts..."
python3 scripts/check_user_doc_cycles.py

echo "Checking assembly cycle fixtures..."
cargo test -p miden-processor tests::user_doc_assembly_cycle_fixtures_match_documentation -- --exact
