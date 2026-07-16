#!/bin/bash
set -euo pipefail

EXPECTED_VERSION="0.28.0"
EXEMPT_PACKAGE="midenc-hir-type"

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: Required command '$1' is not installed or not in PATH"
        exit 1
    fi
}

check_command "cargo"
check_command "jq"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/.."

workspace_version="$(
    awk '
        /^\[workspace\.package\]/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' Cargo.toml
)"

if [ "${workspace_version}" != "${EXPECTED_VERSION}" ]; then
    echo "ERROR: workspace package version is ${workspace_version}, expected ${EXPECTED_VERSION}"
    exit 1
fi

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"

version_errors="$(
    printf '%s' "${metadata_json}" |
        jq -r --arg expected "${EXPECTED_VERSION}" --arg exempt "${EXEMPT_PACKAGE}" '
            .packages[]
            | select(.name != $exempt and .version != $expected)
            | "\(.name) \(.version)"
        '
)"

if [ -n "${version_errors}" ]; then
    echo "ERROR: workspace crates must use version ${EXPECTED_VERSION}, except ${EXEMPT_PACKAGE}:"
    printf '%s\n' "${version_errors}" | sed 's/^/  - /'
    exit 1
fi

echo "Workspace crate versions are pinned to ${EXPECTED_VERSION}."
