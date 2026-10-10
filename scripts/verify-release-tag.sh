#!/bin/bash
set -euo pipefail

# Fetch into FETCH_HEAD so a stale local tag cannot hide remote changes.
git fetch --no-tags origin "refs/tags/${RELEASE_TAG}"
tag_sha="$(git rev-parse 'FETCH_HEAD^{commit}')"
if [[ "$tag_sha" != "$RELEASE_SHA" ]]; then
    echo "::error::Tag $RELEASE_TAG points at $tag_sha, expected $RELEASE_SHA. Tags are immutable; choose a new version." >&2
    exit 1
fi
