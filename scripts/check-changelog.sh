#!/bin/bash
set -uo pipefail

CHANGELOG_FILE="CHANGELOG.md"

usage() {
    cat <<EOF
Usage: BASE_REF=<base> NO_CHANGELOG_LABEL=<true|false> $0 [CHANGELOG_FILE]

When no changelog file is passed, the script requires ${CHANGELOG_FILE}.
EOF
}

require_changelog() {
    local changelog_file="$1"

    if git diff --quiet "origin/${BASE_REF}" -- "${changelog_file}"; then
        >&2 echo "Changes should come with an entry in the \"${changelog_file}\" file. This behavior
can be overridden by using the \"no changelog\" label, which is used for changes
that are trivial / explicitly stated not to require a changelog entry."
        exit 1
    fi

    echo "The \"${changelog_file}\" file has been updated."
}

if [ "${NO_CHANGELOG_LABEL:-false}" = "true" ]; then
    # 'no changelog' set, so finish successfully
    echo "\"no changelog\" label has been set"
    exit 0
fi

if [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

: "${BASE_REF:?BASE_REF is not set}"

if [ "$#" -gt 0 ]; then
    for changelog_file in "$@"; do
        require_changelog "${changelog_file}"
    done
    exit 0
fi

require_changelog "${CHANGELOG_FILE}"
