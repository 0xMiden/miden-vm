#!/bin/bash
set -euo pipefail

git fetch --no-tags origin "+refs/heads/$RELEASE_BRANCH:refs/remotes/origin/$RELEASE_BRANCH"
head_sha="$(git rev-parse "refs/remotes/origin/$RELEASE_BRANCH^{commit}")"
if [[ "$RELEASE_SHA" != "$head_sha" || "$(git rev-parse HEAD)" != "$RELEASE_SHA" ]]; then
    echo "::error::Release commit $RELEASE_SHA must match the checkout and origin/$RELEASE_BRANCH HEAD ($head_sha). Redispatch from the intended branch." >&2
    exit 1
fi

# An existing tag must already match; an absent tag can be created after checks.
tag_refs="$(git ls-remote --tags origin "refs/tags/$RELEASE_TAG")"
if [[ -n "$tag_refs" ]]; then
    "$(dirname "$0")/verify-release-tag.sh"
fi
