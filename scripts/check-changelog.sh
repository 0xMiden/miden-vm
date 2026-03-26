#!/bin/bash
set -euo pipefail

FRAGMENT_GLOB=':(glob).changes/unreleased/*.md'

validate_fragment() {
    local fragment="$1"
    local first_delim second_delim kind="" pr_url="" crate="" body=""

    if [[ ! -f "$fragment" ]]; then
        echo "Fragment file does not exist: $fragment" >&2
        return 1
    fi

    first_delim="$(awk 'NR == 1 && $0 == "---" { print NR; exit }' "$fragment")"
    second_delim="$(awk 'NR > 1 && $0 == "---" { print NR; exit }' "$fragment")"

    if [[ -z "$first_delim" || -z "$second_delim" ]]; then
        echo "Fragment $fragment must start with YAML front matter delimited by '---'" >&2
        return 1
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        case "$line" in
            kind:\ *)
                kind="${line#kind: }"
                ;;
            pr:\ *)
                pr_url="${line#pr: }"
                ;;
            crate:\ *)
                crate="${line#crate: }"
                ;;
            *)
                echo "Fragment $fragment has an unsupported front matter line: $line" >&2
                return 1
                ;;
        esac
    done < <(sed -n "2,$((second_delim - 1))p" "$fragment")

    body="$(sed -n "$((second_delim + 1)),\$p" "$fragment" | sed '/^[[:space:]]*$/d')"

    case "$kind" in
        breaking|change|enhancement|fix) ;;
        *)
            echo "Fragment $fragment has invalid kind '$kind'. Expected one of: breaking, change, enhancement, fix" >&2
            return 1
            ;;
    esac

    if [[ ! "$pr_url" =~ ^https://github\.com/[^/]+/[^/]+/pull/[0-9]+$ ]]; then
        echo "Fragment $fragment must include a GitHub pull request URL in 'pr:'" >&2
        return 1
    fi

    if [[ -n "$crate" && ! "$crate" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
        echo "Fragment $fragment has invalid crate '$crate'" >&2
        return 1
    fi

    if [[ -z "$body" ]]; then
        echo "Fragment $fragment must contain a non-empty summary body" >&2
        return 1
    fi
}

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

for fragment in "${fragments[@]}"; do
    validate_fragment "$fragment"
done

echo "Validated ${#fragments[@]} changelog fragment(s)."
