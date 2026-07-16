#!/bin/bash
set -e
set -o pipefail

# Enhanced MSRV checking script for workspace repository
# Checks MSRV for each workspace member and provides helpful error messages

# ---- utilities --------------------------------------------------------------

check_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Required command '$1' is not installed or not in PATH"
    exit 1
  fi
}

# Check required commands
check_command "cargo"
check_command "jq"
check_command "rustup"
check_command "sed"
check_command "grep"
check_command "awk"

# Portable in-place sed (GNU/macOS); usage: sed_i 's/foo/bar/' file
# shellcheck disable=SC2329  # used quoted
sed_i() {
  if sed --version >/dev/null 2>&1; then
    sed -i "$@"
  else
    sed -i '' "$@"
  fi
}

# ---- repo root --------------------------------------------------------------

# Get the directory where this script is located and change to the parent directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/.."

echo "Checking MSRV for workspace members..."

# ---- metadata ---------------------------------------------------------------

metadata_json="$(cargo metadata --no-deps --format-version 1)"
workspace_root="$(printf '%s' "$metadata_json" | jq -r '.workspace_root')"

failed_packages=""

# Iterate actual workspace packages with manifest paths and (maybe) rust_version
# Fields per line (TSV): id  name  manifest_path  rust_version_or_empty
while IFS=$'\t' read -r pkg_id package_name manifest_path rust_version; do
  # Derive package directory (avoid external dirname for portability)
  package_dir="${manifest_path%/*}"
  if [[ -z "$package_dir" || "$package_dir" == "$manifest_path" ]]; then
    package_dir="."
  fi

  echo "Checking $package_name ($pkg_id) in $package_dir"

  if [[ ! -f "$package_dir/Cargo.toml" ]]; then
    echo "WARNING: No Cargo.toml found in $package_dir, skipping..."
    continue
  fi

  # Prefer cargo metadata's effective rust_version if present
  current_msrv="$rust_version"
  if [[ -z "$current_msrv" ]]; then
    # If the crate inherits: rust-version.workspace = true
    if grep -Eq '^\s*rust-version\.workspace\s*=\s*true\b' "$package_dir/Cargo.toml"; then
      # Read from workspace root [workspace.package]
      current_msrv="$(grep -Eo '^\s*rust-version\s*=\s*"[^"]+"' "$workspace_root/Cargo.toml" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
      if [[ -n "$current_msrv" ]]; then
        echo "   Using workspace MSRV: $current_msrv"
      fi
    fi
  fi

  if [[ -z "$current_msrv" ]]; then
    echo "WARNING: No rust-version found (package or workspace) for $package_name"
    continue
  fi

  echo "   Current MSRV: $current_msrv"

  # Try to verify the MSRV
  if ! cargo msrv verify --manifest-path "$package_dir/Cargo.toml" >/dev/null 2>&1; then
    echo "ERROR: MSRV check failed for $package_name"
    failed_packages="$failed_packages $package_name"

    echo "Searching for correct MSRV for $package_name..."

    # Determine the currently-installed stable toolchain version (e.g., "1.81.0")
    latest_stable="$(rustup run stable rustc --version 2>/dev/null | awk '{print $2}')"
    if [[ -z "$latest_stable" ]]; then latest_stable="1.81.0"; fi

    # Search for the actual MSRV starting from the current one
    if actual_msrv=$(cargo msrv find \
          --manifest-path "$package_dir/Cargo.toml" \
          --min "$current_msrv" \
          --max "$latest_stable" \
          --output-format minimal 2>/dev/null); then
      echo "   Found actual MSRV: $actual_msrv"
      echo ""
      echo "ERROR SUMMARY for $package_name:"
      echo "   Package:   $package_name"
      echo "   Directory: $package_dir"
      echo "   Current (incorrect) MSRV: $current_msrv"
      echo "   Correct MSRV:             $actual_msrv"
      echo ""
      echo "TO FIX:"
      echo "   Update rust-version in $package_dir/Cargo.toml from \"$current_msrv\" to \"$actual_msrv\""
      echo ""
      echo "   Or run this command (portable in-place edit):"
      echo "     sed_i 's/^\\s*rust-version\\s*=\\s*\"$current_msrv\"/rust-version = \"$actual_msrv\"/' \"$package_dir/Cargo.toml\""
    else
      echo "   Could not determine correct MSRV automatically"
      echo ""
      echo "ERROR SUMMARY for $package_name:"
      echo "   Package:   $package_name"
      echo "   Directory: $package_dir"
      echo "   Current (incorrect) MSRV: $current_msrv"
      echo "   Could not automatically determine correct MSRV"
      echo ""
      echo "TO FIX:"
      echo "   Run manually: cargo msrv find --manifest-path \"$package_dir/Cargo.toml\""
    fi
    echo "-------------------------------------------------------------------------------"
  else
    echo "OK: MSRV check passed for $package_name"
  fi
  echo ""

done < <(
  printf '%s' "$metadata_json" \
  | jq -r '. as $m
           | $m.workspace_members[]
           | . as $id
           | ($m.packages[] | select(.id == $id)
              | [ .id, .name, .manifest_path, (.rust_version // "") ] | @tsv)'
)

if [[ -n "$failed_packages" ]]; then
  echo "MSRV CHECK FAILED"
  echo ""
  echo "The following packages have incorrect MSRV settings:$failed_packages"
  echo ""
  echo "Please fix the rust-version fields in the affected Cargo.toml files as shown above."
  exit 1
else
  echo "ALL WORKSPACE MEMBERS PASSED MSRV CHECKS!"
  exit 0
fi
