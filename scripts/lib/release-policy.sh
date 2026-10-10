#!/bin/bash
# Validate the release branch, source commit and maintenance ancestry.

# shellcheck source=scripts/lib/release-plan-common.sh
source "$(dirname "${BASH_SOURCE[0]}")/release-plan-common.sh"

verify_release_commit() {
    if [[ $# != 3 ]]; then
        echo "Usage: verify_release_commit BRANCH SHA TAG" >&2
        return 2
    fi
    local branch="$1" sha="$2" tag="$3"
    local vm_version base_tag
    local tag_refs tag_ref candidate_tag candidate_patch release_line
    release_policy branch "$branch" "$tag" || return 1
    git fetch --no-tags origin "refs/heads/$branch" || return 1
    if [[ "$(git rev-parse 'FETCH_HEAD^{commit}')" != "$sha" || "$(git rev-parse HEAD)" != "$sha" ]]; then
        echo "::error::Release commit $sha must match the checkout and origin/$branch HEAD." >&2
        return 1
    fi
    tag_refs="$(git ls-remote --tags origin "refs/tags/$tag")" || return 1
    if [[ -n "$tag_refs" ]]; then
        git fetch --no-tags origin "refs/tags/$tag" || return 1
        if [[ "$(git rev-parse 'FETCH_HEAD^{commit}')" != "$sha" ]]; then
            echo "::error::Tag $tag must point to release commit $sha." >&2
            return 1
        fi
    fi

    vm_version="$(cargo metadata --locked --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "miden-vm") | .version')" || return 1
    if [[ "$tag" != "v$vm_version" ]]; then
        echo "::error::Tag $tag does not match miden-vm version $vm_version. Update release manifests before dispatching." >&2
        return 1
    fi

    if [[ "$branch" == release/* || "$branch" == release-* ]]; then
        base_tag="v${vm_version%.*}.0"
        git fetch --no-tags origin "refs/tags/$base_tag:refs/tags/$base_tag" || return 1
        if ! git merge-base --is-ancestor "refs/tags/$base_tag^{commit}" "$sha"; then
            echo "::error::Patch release $tag must descend from $base_tag." >&2
            return 1
        fi

        release_line="${vm_version%.*}"
        tag_refs="$(git ls-remote --tags origin "refs/tags/v$release_line.*")" || return 1
        while IFS=$'\t' read -r _tag_sha tag_ref; do
            candidate_tag="${tag_ref#refs/tags/}"
            candidate_patch="${candidate_tag#v"$release_line".}"
            [[ "$candidate_patch" =~ ^(0|[1-9][0-9]*)$ ]] || continue
            if [[ "$(version_cmp "${candidate_tag#v}" "$vm_version")" -lt 0 &&
                  "$(version_cmp "${candidate_tag#v}" "${base_tag#v}")" -gt 0 ]]; then
                base_tag="$candidate_tag"
            fi
        done <<< "$tag_refs"
        git fetch --no-tags origin "refs/tags/$base_tag:refs/tags/$base_tag" || return 1
        if ! git merge-base --is-ancestor "refs/tags/$base_tag^{commit}" "$sha"; then
            echo "::error::Patch release $tag must descend from $base_tag." >&2
            return 1
        fi
    fi

}
