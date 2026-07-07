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

for cmd in cargo curl jq; do
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

all_publishable_packages_sorted() {
  all_publishable_packages | sort
}

selected_packages_sorted() {
  printf '%s\n' "${packages[@]}" | sort
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

check_packages_file_covers_publishable_packages() {
  local missing extra duplicate

  duplicate="$(
    printf '%s\n' "${packages[@]}" | sort | uniq -d
  )"
  if [[ -n "$duplicate" ]]; then
    echo "error: duplicate package(s) in '$packages_file':" >&2
    printf '%s\n' "$duplicate" | sed 's/^/  - /' >&2
    exit 1
  fi

  missing="$(
    comm -23 <(all_publishable_packages_sorted) <(selected_packages_sorted)
  )"
  if [[ -n "$missing" ]]; then
    echo "error: '$packages_file' is missing publishable workspace package(s):" >&2
    printf '%s\n' "$missing" | sed 's/^/  - /' >&2
    exit 1
  fi

  extra="$(
    comm -13 <(all_publishable_packages_sorted) <(selected_packages_sorted)
  )"
  if [[ -n "$extra" ]]; then
    echo "error: '$packages_file' contains package(s) that are not publishable workspace packages:" >&2
    printf '%s\n' "$extra" | sed 's/^/  - /' >&2
    exit 1
  fi
}

for package in "${packages[@]}"; do
  if ! package_version "$package" >/dev/null; then
    echo "error: '$package' is not a publishable workspace package" >&2
    echo "publishable packages:" >&2
    all_publishable_packages | sed 's/^/  - /' >&2
    exit 1
  fi
done

if [[ -z "$packages_arg" ]]; then
  check_packages_file_covers_publishable_packages
fi

crate_version_exists() {
  local package="$1"
  local version="$2"
  local http_code

  http_code="$(
    curl --silent --show-error --output /dev/null \
      --write-out "%{http_code}" \
      --user-agent "miden-vm-release-selected" \
      "https://crates.io/api/v1/crates/${package}/${version}"
  )"

  case "$http_code" in
    200) return 0 ;;
    404) return 1 ;;
    *)
      echo "error: unable to verify $package v$version on crates.io; HTTP $http_code" >&2
      return 2
      ;;
  esac
}

ensure_selected_versions_unpublished() {
  local package version

  for package in "${packages[@]}"; do
    version="$(package_version "$package")"
    if crate_version_exists "$package" "$version"; then
      echo "error: $package v$version already exists on crates.io" >&2
      echo "Remove it from the release package list or bump its version before releasing." >&2
      exit 1
    fi
  done
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

ensure_selected_versions_unpublished

if [[ "$mode" == "dry-run" ]]; then
  dry_run_selected_packages
else
  for package in "${packages[@]}"; do
    version="$(package_version "$package")"
    publish_package "$package" "$version"
  done
fi
