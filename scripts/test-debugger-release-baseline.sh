#!/usr/bin/env bash
set -euo pipefail

# Reproduce the v0.19.0 tag collision encountered when importing the debugger.
# The baseline selector is shared by all workspace crates. These fixtures check
# that it verifies package identity and resolves inherited workspace versions.
# The version below is a fixed regression fixture, independent of future releases.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/release-plan-common.sh
source "$repo_root/scripts/lib/release-plan-common.sh"
# Use a disposable Git repository so fixture commits and tags cannot affect this checkout.
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
export RELEASE_PLAN_TMPDIR="$test_root/cache"
mkdir -p "$test_root/repo/src" "$test_root/hooks" "$RELEASE_PLAN_TMPDIR"
cd "$test_root/repo"
git init -q
git config user.name 'Release baseline test'
git config user.email 'baseline@example.invalid'
# Fixture commits use an empty hooks directory and do not need signing credentials.
git config commit.gpgsign false
git config tag.gpgsign false
git config core.hooksPath "$test_root/hooks"
# Start with an unrelated crate whose tag has the debugger's historical version.
# Inherit the version to exercise the workspace metadata lookup used by the VM.
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

# Substitute local crates.io responses, including trusted-publishing provenance.
# Every scenario has a local tag, so the selector also avoids fetching Git refs.
published_version_info() {
    printf '%s\n' "$test_root/published.json"
}
printf '{"version":{"trustpub_data":null}}\n' > "$test_root/published.json"
# Reject a same-version tag for another crate and leave the tag unchanged.
if baseline_commit_for miden-debug 0.19.0; then
    echo 'An unrelated version tag was accepted as a debugger baseline' >&2
    exit 1
fi
[[ "$(git rev-parse v0.19.0)" == "$collision" ]]

# Valid debugger provenance takes precedence over the unrelated tag.
sed 's/other-package/miden-debug/' Cargo.toml > Cargo.toml.tmp
mv Cargo.toml.tmp Cargo.toml
git add Cargo.toml
git commit -qm 'Create debugger baseline with inherited version'
baseline="$(git rev-parse HEAD)"
printf '{"version":{"trustpub_data":{"sha":"%s"}}}\n' "$baseline" > "$test_root/published.json"
[[ "$(baseline_commit_for miden-debug 0.19.0)" == "$baseline" ]]

# A provenance commit must also contain the exact requested crate version.
if commit_has_package_version "$baseline" miden-debug 0.19.1; then
    echo 'A baseline with the wrong package version was accepted' >&2
    exit 1
fi
# Reject provenance that points to the unrelated crate, even though its version matches.
printf '{"version":{"trustpub_data":{"sha":"%s"}}}\n' "$collision" > "$test_root/published.json"
if baseline_commit_for miden-debug 0.19.0; then
    echo 'An unrelated provenance commit was accepted as a baseline' >&2
    exit 1
fi

# With no provenance, a tag is still valid for the crate it actually contains.
printf '{"version":{"trustpub_data":null}}\n' > "$test_root/published.json"
[[ "$(baseline_commit_for other-package 0.19.0)" == "$collision" ]]
echo 'Debugger release baseline checks passed'
