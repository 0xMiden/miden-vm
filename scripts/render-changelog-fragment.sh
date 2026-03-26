#!/bin/bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage:
  render-changelog-fragment.sh --kind KIND --pr-url URL --summary TEXT [--crate CRATE] [--output PATH]
EOF
}

kind=""
pr_url=""
crate=""
summary=""
output=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kind)
            kind="$2"
            shift 2
            ;;
        --pr-url)
            pr_url="$2"
            shift 2
            ;;
        --crate)
            crate="$2"
            shift 2
            ;;
        --summary)
            summary="$2"
            shift 2
            ;;
        --output)
            output="$2"
            shift 2
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

case "$kind" in
    breaking|change|enhancement|fix) ;;
    *)
        echo "Invalid fragment kind: $kind" >&2
        exit 1
        ;;
esac

if [[ ! "$pr_url" =~ ^https://github\.com/[^/]+/[^/]+/pull/[0-9]+$ ]]; then
    echo "Invalid GitHub pull request URL: $pr_url" >&2
    exit 1
fi

if [[ -n "$crate" && ! "$crate" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "Invalid crate name: $crate" >&2
    exit 1
fi

if [[ -z "$summary" ]]; then
    echo "Fragment summary must not be empty" >&2
    exit 1
fi

render_fragment() {
    printf '%s\n' '---'
    printf 'kind: %s\n' "$kind"
    printf 'pr: %s\n' "$pr_url"
    if [[ -n "$crate" ]]; then
        printf 'crate: %s\n' "$crate"
    fi
    printf '%s\n' '---'
    printf '\n'
    printf '%s\n' "$summary"
}

if [[ -n "$output" ]]; then
    render_fragment > "$output"
else
    render_fragment
fi
