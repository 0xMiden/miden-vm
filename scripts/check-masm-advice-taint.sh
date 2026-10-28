#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
midenc_masm_lint="${MIDENC_MASM_LINT:-$repo_root/tools/midenc-masm-lint/target/debug/midenc-masm-lint}"

has_manifest=false
expects_target=false
for argument in "$@"; do
    if [[ "$expects_target" == true ]]; then
        expects_target=false
    elif [[ "$argument" == --target ]]; then
        expects_target=true
    elif [[ "$argument" != -* ]]; then
        has_manifest=true
    fi
done
if [[ "$has_manifest" == false ]]; then
    set -- "$repo_root/crates/lib/core/asm/miden-project.toml" "$@"
fi
exec "$midenc_masm_lint" "$@"
