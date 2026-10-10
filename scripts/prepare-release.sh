#!/bin/bash
# Validate the dispatched release and emit its commit, tag and release type for GitHub Actions.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/release-policy.sh
source "$DIR/lib/release-policy.sh"

# An environment name alone does not require approval. Fail before staging if
# the repository has not configured a reviewer for it.
if ! has_reviewers="$(gh api "repos/${GH_REPO}/environments/release" --jq 'any(.protection_rules[]; .type == "required_reviewers" and (.reviewers | length) > 0)')"; then
    echo "::error::Could not read release environment for ${GH_REPO}." >&2
    exit 1
fi
if [[ "$has_reviewers" != true ]]; then
    echo "::error::Configure required reviewers on the release environment before releasing." >&2
    exit 1
fi

release_sha="${GITHUB_SHA}"
prerelease=false
[[ "$RELEASE_TAG" != *-rc.* ]] || prerelease=true

[[ "${GITHUB_REF_TYPE}" == branch ]] || {
    echo "::error::Dispatch from a release branch, not a tag." >&2
    exit 1
}
release_branch="${GITHUB_REF_NAME}"

verify_release_commit "$release_branch" "$release_sha" "$RELEASE_TAG"
{
    echo "tag=${RELEASE_TAG}"
    echo "sha=${release_sha}"
    echo "branch=${release_branch}"
    echo "prerelease=${prerelease}"
} >> "${GITHUB_OUTPUT}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    # shellcheck disable=SC2016
    printf 'Release %s from `%s` at `%s`.\n' "$RELEASE_TAG" "$release_branch" "$release_sha" >> "$GITHUB_STEP_SUMMARY"
fi
