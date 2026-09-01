#!/bin/bash
set -euo pipefail

base="${1:?usage: check-release-metadata.sh BASE_COMMIT}"

package_version() {
    local metadata="$1"
    local package="$2"

    printf '%s' "$metadata" |
        jq -er --arg package "$package" '.packages[] | select(.name == $package) | .version'
}

release_line() {
    local core="${1%%[-+]*}"
    printf '%s\n' "${core%.*}"
}

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"
worktree_root="$(mktemp -d)"
base_worktree="$worktree_root/base"
cleanup() {
    git worktree remove --force "$base_worktree" >/dev/null 2>&1 || true
    rmdir "$worktree_root" >/dev/null 2>&1 || true
}
trap cleanup EXIT
git worktree add --detach "$base_worktree" "$base" >/dev/null
base_metadata_json="$(
    cargo metadata --locked --no-deps --format-version 1 --manifest-path "$base_worktree/Cargo.toml"
)"

# miden-precompiles inherits workspace.package.version.
current_workspace="$(package_version "$metadata_json" miden-precompiles)"
base_workspace="$(package_version "$base_metadata_json" miden-precompiles)"

if [[ "$current_workspace" != "$base_workspace" ]]; then
    if git show-ref --verify --quiet "refs/tags/v$current_workspace"; then
        echo "ERROR: v$current_workspace has already been released. Choose a newer workspace version." >&2
        exit 1
    fi

    current_midenc="$(package_version "$metadata_json" midenc-hir-type)"
    base_midenc="$(package_version "$base_metadata_json" midenc-hir-type)"

    if [[ "$(release_line "$current_workspace")" != "$(release_line "$base_workspace")" && "$current_midenc" == "$base_midenc" ]]; then
        echo "ERROR: $current_workspace starts a new release line. Bump midenc-hir-type from $base_midenc." >&2
        exit 1
    fi

    if [[ "$current_midenc" != "$base_midenc" ]]; then
        requirement="$(
            printf '%s' "$metadata_json" |
                jq -r '[.packages[].dependencies[] | select(.name == "midenc-hir-type") | .req] | unique[]'
        )"
        if [[ "$current_midenc" == *-* ]]; then
            expected="$current_midenc"
        else
            expected="${current_midenc%.*}"
        fi
        if [[ "$requirement" != "^$expected" ]]; then
            echo "ERROR: midenc-hir-type $current_midenc needs workspace requirement $expected, found ${requirement#^}." >&2
            exit 1
        fi
    fi
fi

for manifest in \
    tools/miden-core-fuzz/Cargo.toml \
    tools/miden-crypto-fuzz/Cargo.toml \
    tools/miden-serde-utils-fuzz/Cargo.toml; do
    cargo metadata --locked --no-deps --format-version 1 --manifest-path "$manifest" >/dev/null
done

scripts/check-package-release-plan.sh --skip-semver
