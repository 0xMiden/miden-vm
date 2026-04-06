#!/bin/bash
set -euo pipefail

FRAGMENT_GLOB=':(glob).changes/unreleased/*.md'

if [[ "${NO_CHANGELOG_LABEL:-false}" == "true" ]]; then
    echo "\"no changelog\" label has been set"
    exit 0
fi

if [[ -z "${BASE_REF:-}" ]]; then
    echo "BASE_REF must be set" >&2
    exit 1
fi

fragments=()
while IFS= read -r fragment; do
    [[ -n "$fragment" ]] && fragments+=("$fragment")
done < <(git diff --name-only --diff-filter=AMR "origin/${BASE_REF}...HEAD" -- "$FRAGMENT_GLOB")

if [[ "${#fragments[@]}" -eq 0 ]]; then
    cat >&2 <<'EOF'
Changes should come with a changelog fragment in ".changes/unreleased/".
This behavior can be overridden by using the "no changelog" label for changes
that are trivial or explicitly stated not to require a changelog entry.
EOF
    exit 1
fi

validate_args=()
for fragment in "${fragments[@]}"; do
    validate_args+=(--validate-fragment "$fragment")
done

./scripts/prepare-changelog-release.py "${validate_args[@]}"
