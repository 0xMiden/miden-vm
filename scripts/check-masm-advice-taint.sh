#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
midenc_masm_lint="${MIDENC_MASM_LINT:-$repo_root/tools/midenc-masm-lint/target/debug/midenc-masm-lint}"

if [[ "$#" -eq 0 || ( "$#" -eq 1 && "${1:-}" == -* ) ]]; then
    set -- "$repo_root/crates/lib/core/asm/miden-project.toml" "$@"
fi
exec "$midenc_masm_lint" "$@"
