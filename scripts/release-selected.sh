#!/usr/bin/env bash
set -euo pipefail

mode=""
packages_arg=""
packages_file="release-packages.txt"
allow_dirty="false"

usage() {
  cat <<'USAGE'
Usage: scripts/release-selected.sh --mode <dry-run|publish> [--packages <list>] [--packages-file <path>] [--allow-dirty]

Publishes or dry-runs a selected set of publishable workspace crates.

Package lists may be comma, space, or newline separated. Lines in package files
may contain comments after '#'. Packages are processed in the order provided.
--allow-dirty is accepted only with --mode dry-run.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --packages)
      packages_arg="${2:-}"
      shift 2
      ;;
    --packages-file)
      packages_file="${2:-}"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty="true"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$mode" in
  dry-run | publish) ;;
  "")
    echo "error: --mode is required" >&2
    usage >&2
    exit 2
    ;;
  *)
    echo "error: unsupported mode '$mode'; expected dry-run or publish" >&2
    exit 2
    ;;
esac

if [[ "$allow_dirty" == "true" && "$mode" != "dry-run" ]]; then
  echo "error: --allow-dirty is only supported in dry-run mode" >&2
  exit 2
fi

for cmd in cargo jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' is not installed or not in PATH" >&2
    exit 1
  fi
done

packages=()

add_packages() {
  local line word
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line//,/ }"
    for word in $line; do
      packages+=("$word")
    done
  done
}

if [[ -n "$packages_arg" ]]; then
  add_packages <<< "$packages_arg"
else
  if [[ ! -f "$packages_file" ]]; then
    echo "error: packages file '$packages_file' does not exist" >&2
    exit 1
  fi
  add_packages < "$packages_file"
fi

if [[ ${#packages[@]} -eq 0 ]]; then
  echo "error: no packages selected" >&2
  exit 1
fi

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"

package_version() {
  local package="$1"
  printf '%s' "$metadata_json" \
    | jq -er --arg package "$package" '
      . as $m
      | $m.packages[]
      | select(.name == $package and (.id as $id | $m.workspace_members | index($id)))
      | select(.publish != [])
      | .version
    '
}

all_publishable_packages() {
  printf '%s' "$metadata_json" \
    | jq -r '
      . as $m
      | $m.packages[]
      | select((.id as $id | $m.workspace_members | index($id)) and .publish != [])
      | .name
    '
}

is_selected_package() {
  local package="$1"
  local selected

  for selected in "${packages[@]}"; do
    if [[ "$selected" == "$package" ]]; then
      return 0
    fi
  done

  return 1
}

for package in "${packages[@]}"; do
  if ! package_version "$package" >/dev/null; then
    echo "error: '$package' is not a publishable workspace package" >&2
    echo "publishable packages:" >&2
    all_publishable_packages | sed 's/^/  - /' >&2
    exit 1
  fi
done

crate_version_exists() {
  local package="$1"
  local version="$2"

  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi

  curl --fail --silent --show-error --output /dev/null \
    --user-agent "miden-vm-release-selected" \
    "https://crates.io/api/v1/crates/${package}/${version}"
}

publish_package() {
  local package="$1"
  local version="$2"
  local attempt=1
  local max_attempts=1
  local retry_seconds="${RELEASE_PUBLISH_RETRY_SECONDS:-30}"

  if [[ "$mode" == "publish" ]]; then
    max_attempts="${RELEASE_PUBLISH_ATTEMPTS:-5}"
  fi

  while true; do
    if [[ "$mode" == "dry-run" ]]; then
      cargo publish -p "$package" --dry-run
      return
    fi

    if crate_version_exists "$package" "$version"; then
      echo "Skipping $package v$version; it already exists on crates.io."
      return
    fi

    if cargo publish -p "$package"; then
      return
    fi

    if [[ "$attempt" -ge "$max_attempts" ]]; then
      echo "error: failed to publish $package v$version after $attempt attempt(s)" >&2
      return 1
    fi

    attempt=$((attempt + 1))
    echo "Retrying $package v$version in ${retry_seconds}s (attempt $attempt/$max_attempts)..."
    sleep "$retry_seconds"
  done
}

dry_run_selected_packages() {
  local package
  local cmd=(cargo publish --workspace --dry-run)

  if [[ "$allow_dirty" == "true" ]]; then
    cmd+=(--allow-dirty)
  fi

  while IFS= read -r package; do
    if ! is_selected_package "$package"; then
      cmd+=(--exclude "$package")
    fi
  done < <(all_publishable_packages)

  "${cmd[@]}"
}

echo "Release mode: $mode"
echo "Selected packages:"
for package in "${packages[@]}"; do
  version="$(package_version "$package")"
  echo "  - $package v$version"
done

if [[ "$mode" == "dry-run" ]]; then
  dry_run_selected_packages
else
  for package in "${packages[@]}"; do
    version="$(package_version "$package")"
    publish_package "$package" "$version"
  done
fi
