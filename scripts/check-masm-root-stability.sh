#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
workspace_version="$(
    awk '
        /^\[workspace.package\]/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && /^version[[:space:]]*=/ {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' "$repo_root/Cargo.toml"
)"

parse_version() {
    local version="$1"
    local prefix="$2"
    local major minor patch

    IFS=. read -r major minor patch <<<"$version"
    if [[ ! "$major" =~ ^[0-9]+$ || ! "$minor" =~ ^[0-9]+$ || ! "$patch" =~ ^[0-9]+$ ]]; then
        echo "::error::could not parse semantic version '$version'"
        exit 1
    fi

    eval "${prefix}_major=\$major"
    eval "${prefix}_minor=\$minor"
    eval "${prefix}_patch=\$patch"
}

latest_release_tag_on_head() {
    git -C "$repo_root" tag --merged HEAD --list 'v[0-9]*.[0-9]*.[0-9]*' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V \
        | tail -n1 \
        || true
}

parse_version "$workspace_version" current

git -C "$repo_root" fetch --tags origin

baseline_tag="$(latest_release_tag_on_head)"
if [[ -z "$baseline_tag" ]]; then
    echo "No release tag found on the current branch history; skipping MASM root stability check"
    exit 0
fi

baseline_version="${baseline_tag#v}"
parse_version "$baseline_version" baseline

if (( baseline_major != current_major )); then
    echo "workspace version changed major version from ${baseline_version} to ${workspace_version}; skipping MASM root stability check"
    exit 0
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/masm-root-check.XXXXXX")"
check_script="$repo_root/scripts/.check-masm-export-digests.${baseline_tag}.$$.rs"

cleanup() {
    rm -f "$check_script"
    git -C "$repo_root" worktree remove --force "$workdir/baseline" >/dev/null 2>&1 || true
    rm -rf "$workdir"
}
trap cleanup EXIT

git -C "$repo_root" worktree add --detach --quiet "$workdir/baseline" "$baseline_tag"
sed -E "s/tag = \"v[0-9]+\\.[0-9]+\\.[0-9]+\"/tag = \"${baseline_tag}\"/g" \
    "$repo_root/scripts/check-masm-export-digests.rs" >"$check_script"
chmod +x "$check_script"

if (($# > 0)); then
    projects=("$@")
elif [[ -n "${MIDEN_ROOT_CHECK_PROJECTS:-}" ]]; then
    # shellcheck disable=SC2206
    projects=(${MIDEN_ROOT_CHECK_PROJECTS})
else
    projects=("crates/lib/core/asm/miden-project.toml")
fi

for project in "${projects[@]}"; do
    if [[ "$project" = /* ]]; then
        current_project="$project"
        relative_project="${project#"$repo_root"/}"
    else
        current_project="$repo_root/$project"
        relative_project="$project"
    fi

    baseline_project="$workdir/baseline/$relative_project"

    if [[ ! -e "$current_project" ]]; then
        echo "::error::current MASM project does not exist: $current_project"
        exit 1
    fi

    if [[ ! -e "$baseline_project" ]]; then
        echo "MASM project '$relative_project' did not exist in $baseline_tag; skipping"
        continue
    fi

    echo "Checking MASM root stability for $relative_project against $baseline_tag"
    RUSTC_WRAPPER= rustup run nightly cargo -Zscript \
        "$check_script" \
        "$baseline_project" \
        "$current_project"
done

echo "MASM procedure roots are stable against $baseline_tag"
