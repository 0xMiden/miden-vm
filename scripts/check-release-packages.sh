#!/usr/bin/env bash
set -euo pipefail

packages_file="${1:-release-packages.txt}"

for cmd in cargo jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' is not installed or not in PATH" >&2
    exit 1
  fi
done

if [[ ! -f "$packages_file" ]]; then
  echo "error: packages file '$packages_file' does not exist" >&2
  exit 1
fi

metadata_json="$(cargo metadata --locked --no-deps --format-version 1)"

all_publishable="$(
  printf '%s' "$metadata_json" \
    | jq -r '
      . as $m
      | $m.packages[]
      | select((.id as $id | $m.workspace_members | index($id)) and .publish != [])
      | .name
    ' \
    | sort
)"

listed="$(
  sed 's/#.*//' "$packages_file" \
    | tr ',[:space:]' '\n' \
    | sed '/^$/d' \
    | sort
)"

duplicates="$(
  sed 's/#.*//' "$packages_file" \
    | tr ',[:space:]' '\n' \
    | sed '/^$/d' \
    | sort \
    | uniq -d
)"

if [[ -n "$duplicates" ]]; then
  echo "error: duplicate package(s) in '$packages_file':" >&2
  printf '%s\n' "$duplicates" | sed 's/^/  - /' >&2
  exit 1
fi

missing="$(comm -23 <(printf '%s\n' "$all_publishable") <(printf '%s\n' "$listed"))"
if [[ -n "$missing" ]]; then
  echo "error: '$packages_file' is missing publishable workspace package(s):" >&2
  printf '%s\n' "$missing" | sed 's/^/  - /' >&2
  exit 1
fi

extra="$(comm -13 <(printf '%s\n' "$all_publishable") <(printf '%s\n' "$listed"))"
if [[ -n "$extra" ]]; then
  echo "error: '$packages_file' contains package(s) that are not publishable workspace packages:" >&2
  printf '%s\n' "$extra" | sed 's/^/  - /' >&2
  exit 1
fi

echo "release package list covers all publishable workspace packages"
