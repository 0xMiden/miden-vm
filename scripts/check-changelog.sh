#!/bin/sh
set -u

CHANGELOG_FILE="${1:-CHANGELOG.md}"

if [ "${NO_CHANGELOG_LABEL:-}" = "true" ]; then
    # 'no changelog' set, so finish successfully
    echo "\"no changelog\" label has been set"
    exit 0
else
    # a changelog check is required
    # fail if the diff is empty
    if git diff --exit-code "origin/${BASE_REF:-main}" -- "${CHANGELOG_FILE}"; then
        >&2 cat <<EOF
Changes should come with an entry in the "CHANGELOG.md" file. This behavior
can be overridden by using the "no changelog" label, which is used for changes
that are trivial / explicitly stated not to require a changelog entry.
EOF
        exit 1
    fi

    echo "The \"CHANGELOG.md\" file has been updated."
fi
