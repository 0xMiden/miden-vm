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
"$scripts/verify-release-head.sh"
if "$scripts/verify-release-tag.sh" 2>/dev/null; then
    echo 'Missing release tag was accepted.' >&2; exit 1
fi
git tag -a "$RELEASE_TAG" -m release
git push --quiet origin "$RELEASE_TAG"
"$scripts/verify-release-tag.sh"
git commit --quiet --allow-empty -m advanced
git push --quiet origin main
if "$scripts/verify-release-head.sh" 2>/dev/null; then
    echo 'Advanced branch was accepted.' >&2; exit 1
fi
git tag -f "$RELEASE_TAG"
git push --quiet --force origin "$RELEASE_TAG"
if "$scripts/verify-release-tag.sh" 2>/dev/null; then
    echo 'Changed remote tag was accepted.' >&2; exit 1
fi
echo 'Release head and tag checks passed.'
