#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/.."

# shellcheck source=scripts/lib/release-plan-common.sh
source "$DIR/lib/release-plan-common.sh"

check_command "cargo"
check_command "curl"
check_command "jq"
check_command "awk"

export CRATES_IO_USER_AGENT="miden-vm-package-release-plan"
RELEASE_PLAN_TMPDIR="$(mktemp -d)"
export RELEASE_PLAN_TMPDIR
trap 'rm -rf "$RELEASE_PLAN_TMPDIR"' EXIT

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"
workspace_root="$(printf '%s' "$metadata_json" | jq -r '.workspace_root')"
selected_packages=()

add_packages() {
    local item word

    for item in "$@"; do
        item="${item%%#*}"
        item="${item//,/ }"
        for word in $item; do
            selected_packages+=("$word")
        done
    done
}

add_packages "$@"
selected_package_count="${#selected_packages[@]}"

publishable_package_names="$(
    publishable_packages | cut -f1
)"

if [[ "$selected_package_count" -gt 0 ]]; then
    for selected in "${selected_packages[@]}"; do
        if ! printf '%s\n' "$publishable_package_names" | grep -Fxq "$selected"; then
            echo "ERROR: '$selected' is not a publishable workspace package" >&2
            echo "Publishable packages:" >&2
            printf '%s\n' "$publishable_package_names" | sed 's/^/  - /' >&2
            exit 1
        fi
    done
fi

is_selected_package() {
    local package="$1"
    local selected

    if [[ "$selected_package_count" -eq 0 ]]; then
        return 0
    fi

    for selected in "${selected_packages[@]}"; do
        if [[ "$selected" == "$package" ]]; then
            return 0
        fi
    done

    return 1
}

would_publish=()
already_published=()
version_errors=()
semver_failures=()

echo "Package release plan"
echo

while IFS=$'\t' read -r package local_version manifest_path; do
    baseline_commit=""

    if ! is_selected_package "$package"; then
        continue
    fi

    latest_version="$(latest_published_version "$package")"

    if [[ -z "$latest_version" ]]; then
        would_publish+=("$package v$local_version (latest published: none)")
        continue
    fi

    if crate_version_exists "$package" "$local_version"; then
        if ! package_archive_matches_published "$package" "$local_version" "$workspace_root"; then
            version_errors+=("$package v$local_version already exists on crates.io, but the local package archive differs from the published crate")
            continue
        fi

        already_published+=("$package v$local_version (latest published: $latest_version)")
        continue
    fi

    cmp="$(version_cmp "$local_version" "$latest_version")"
    if [[ "$cmp" -le 0 ]]; then
        version_errors+=("$package v$local_version is not newer than latest published v$latest_version")
        continue
    fi

    echo "Checking semver for $package v$local_version against published v$latest_version"
    baseline_commit="$(baseline_commit_for "$package" "$latest_version" || true)"
    if run_semver_check "$package" "$latest_version" "$workspace_root" "$baseline_commit"; then
        would_publish+=("$package v$local_version (latest published: $latest_version)")
    else
        semver_failures+=("$package v$local_version against published v$latest_version")
    fi
done < <(publishable_packages)

echo

echo "Would be published:"
if [[ ${#would_publish[@]} -gt 0 ]]; then
    printf '  - %s\n' "${would_publish[@]}"
else
    echo "  none"
fi

echo

echo "Already published:"
if [[ ${#already_published[@]} -gt 0 ]]; then
    printf '  - %s\n' "${already_published[@]}"
else
    echo "  none"
fi

echo

echo "Version errors:"
if [[ ${#version_errors[@]} -gt 0 ]]; then
    printf '  - %s\n' "${version_errors[@]}"
else
    echo "  none"
fi

echo

echo "Semver errors:"
if [[ ${#semver_failures[@]} -gt 0 ]]; then
    printf '  - %s\n' "${semver_failures[@]}"
else
    echo "  none"
fi

if [[ ${#version_errors[@]} -gt 0 || ${#semver_failures[@]} -gt 0 ]]; then
    exit 1
fi

echo
echo "Release plan check passed."
