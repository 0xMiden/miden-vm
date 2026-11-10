#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/release-plan-common.sh
source "$repo_root/scripts/lib/release-plan-common.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
export RELEASE_PLAN_TMPDIR="$test_root/cache"
mkdir -p "$test_root/repo/src" "$test_root/hooks" "$RELEASE_PLAN_TMPDIR"
cd "$test_root/repo"
git init -q
git config user.name 'Release baseline test'
git config user.email 'baseline@example.invalid'
git config commit.gpgsign false
git config tag.gpgsign false
git config core.hooksPath "$test_root/hooks"
cat > Cargo.toml <<'TOML'
[workspace]
members = ["."]
[workspace.package]
version = "0.19.0"
[package]
name = "other-package"
version.workspace = true
TOML
touch src/lib.rs
git add Cargo.toml src/lib.rs
git commit -qm 'Create unrelated package with the same release version'
git tag v0.19.0
collision="$(git rev-parse HEAD)"

published_version_info() {
    printf '%s\n' "$test_root/published.json"
}
printf '{"version":{"trustpub_data":null}}\n' > "$test_root/published.json"
if baseline_commit_for miden-debug 0.19.0; then
    echo 'An unrelated version tag was accepted as a debugger baseline' >&2
    exit 1
fi
[[ "$(git rev-parse v0.19.0)" == "$collision" ]]

sed 's/other-package/miden-debug/' Cargo.toml > Cargo.toml.tmp
mv Cargo.toml.tmp Cargo.toml
git add Cargo.toml
git commit -qm 'Create debugger baseline with inherited version'
baseline="$(git rev-parse HEAD)"
printf '{"version":{"trustpub_data":{"sha":"%s"}}}\n' "$baseline" > "$test_root/published.json"
[[ "$(baseline_commit_for miden-debug 0.19.0)" == "$baseline" ]]

# Correct provenance wins over the unrelated tag, but must match the version.
if commit_has_package_version "$baseline" miden-debug 0.19.1; then
    echo 'A baseline with the wrong package version was accepted' >&2
    exit 1
fi
printf '{"version":{"trustpub_data":{"sha":"%s"}}}\n' "$collision" > "$test_root/published.json"
if baseline_commit_for miden-debug 0.19.0; then
    echo 'An unrelated provenance commit was accepted as a baseline' >&2
    exit 1
fi

printf '{"version":{"trustpub_data":null}}\n' > "$test_root/published.json"
[[ "$(baseline_commit_for other-package 0.19.0)" == "$collision" ]]
echo 'Release baseline checks passed'
