#!/bin/bash
set -euo pipefail
scripts="$(cd "$(dirname "$0")" && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

git init --quiet --bare "$fixture/remote.git"
git init --quiet "$fixture/checkout"
cd "$fixture/checkout"
git config user.name test
git config user.email test@example.invalid
git remote add origin "$fixture/remote.git"
git commit --quiet --allow-empty -m release
git branch -M main
git push --quiet origin main
export RELEASE_BRANCH=main RELEASE_TAG=v0.35.1
RELEASE_SHA="$(git rev-parse HEAD)"
export RELEASE_SHA
"$scripts/verify-release-refs.sh"
if "$scripts/verify-release-tag.sh" 2>/dev/null; then
    echo 'Missing release tag was accepted.' >&2; exit 1
fi
git tag -a "$RELEASE_TAG" -m release
git push --quiet origin "$RELEASE_TAG"
"$scripts/verify-release-refs.sh"
"$scripts/verify-release-tag.sh"
git commit --quiet --allow-empty -m advanced
git push --quiet origin main
if "$scripts/verify-release-refs.sh" 2>/dev/null; then
    echo 'Advanced branch was accepted.' >&2; exit 1
fi
advanced_sha="$(git rev-parse HEAD)"
git checkout --quiet --detach "$RELEASE_SHA"
git --git-dir="$fixture/remote.git" update-ref refs/heads/main "$RELEASE_SHA"
git --git-dir="$fixture/remote.git" update-ref "refs/tags/$RELEASE_TAG" "$advanced_sha"
if "$scripts/verify-release-refs.sh" 2>/dev/null; then
    echo 'Changed remote tag was accepted.' >&2; exit 1
fi
git checkout --quiet --detach "$advanced_sha"
git tag -f "$RELEASE_TAG" "$(git rev-parse HEAD)" >/dev/null
source "$scripts/lib/release-policy.sh"
[[ "$(version_cmp 1.5.0 1.5.0-alpha.3)" == 1 ]]
printf '%s' '{"versions":[{"num":"1.2.0","yanked":false},{"num":"1.2.1-rc.1","yanked":false}]}' > "$fixture/history.json"
[[ "$(release_policy latest 1.2.1 "$fixture/history.json")" == 1.2.1-rc.1 ]]
[[ "$(release_policy baseline 1.2.1 "$fixture/history.json")" == 1.2.0 ]]
printf '%s' '{"versions":[{"num":"1.2.0-rc.1","yanked":false}]}' > "$fixture/history.json"
if release_policy baseline invalid "$fixture/history.json" 2> "$fixture/error"; then
    echo 'Invalid baseline version was accepted.' >&2; exit 1
fi
[[ "$(<"$fixture/error")" == "release policy: "* ]]
printf '[package]\nname="miden-vm"\nversion="0.35.2"\n[lib]\npath="lib.rs"\n' > Cargo.toml
touch lib.rs
git tag v0.35.0 "$RELEASE_SHA"
git push --quiet origin v0.35.0
RELEASE_BRANCH=release-v0.35.2 RELEASE_TAG=v0.35.2
prior_sha="$RELEASE_SHA"
RELEASE_SHA="$(git rev-parse HEAD)"
git push --quiet origin "HEAD:refs/heads/$RELEASE_BRANCH"
verify_release_commit "$RELEASE_BRANCH" "$RELEASE_SHA" "$RELEASE_TAG"
git checkout --quiet --detach "$prior_sha"
RELEASE_SHA="$prior_sha"
git push --quiet --force origin "HEAD:refs/heads/$RELEASE_BRANCH"
if verify_release_commit "$RELEASE_BRANCH" "$RELEASE_SHA" "$RELEASE_TAG"; then
    echo 'Patch missing the previous patch was accepted.' >&2; exit 1
fi
git checkout --quiet --orphan unrelated
git commit --quiet --allow-empty -m unrelated
RELEASE_SHA="$(git rev-parse HEAD)"
git push --quiet --force origin "HEAD:refs/heads/$RELEASE_BRANCH"
if verify_release_commit "$RELEASE_BRANCH" "$RELEASE_SHA" "$RELEASE_TAG"; then
    echo 'Patch missing the base release was accepted.' >&2; exit 1
fi
echo 'Release version, ancestry, head and tag checks passed.'
