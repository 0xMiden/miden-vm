#!/bin/bash
# Validate the dispatched release and emit its commit, tag and release type for GitHub Actions.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/release-policy.sh
source "$DIR/lib/release-policy.sh"

# Require named reviewers so their current repository role can be checked.
if ! reviewers="$(gh api "repos/${GH_REPO}/environments/release" --jq 'if .can_admins_bypass == false then [.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]] else [] end')"; then
    echo "::error::Could not read release environment for ${GH_REPO}." >&2
    exit 1
fi
if ! jq -e 'length > 0 and all(.[]; .type == "User")' <<< "$reviewers" >/dev/null; then
    echo "::error::Configure named admin reviewers and disable admin bypass on the release environment." >&2
    exit 1
fi
while IFS= read -r reviewer; do
    permission="$(gh api "repos/${GH_REPO}/collaborators/${reviewer}/permission" --jq '.permission')"
    if [[ "$permission" != admin ]]; then
        echo "::error::Release reviewer $reviewer must have repository admin access." >&2
        exit 1
    fi
done < <(jq -r '.[].reviewer.login' <<< "$reviewers")

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
