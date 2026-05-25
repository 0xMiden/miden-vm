#!/bin/bash

# RELEASE_TAG, EVENT_NAME, GH_TOKEN, GH_REPO, GITHUB_OUTPUT are set on the
# workspace-publish.yml workflow.

set -euo pipefail

git fetch origin main --depth=1
main_sha="$(git rev-parse origin/main)"

if [[ "${EVENT_NAME}" == "workflow_dispatch" ]]; then
    # Canonical release path: operators provide only the tag. The commit is
    # derived from origin/main so release assets, crates, and the GitHub
    # release all point at the same protected revision.
    release_sha="${main_sha}"

    if git rev-parse --verify --quiet "refs/tags/${RELEASE_TAG}^{commit}" >/dev/null; then
        tag_sha="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"
        if [[ "${tag_sha}" != "${release_sha}" ]]; then
            echo "::error::Existing tag ${RELEASE_TAG} points at ${tag_sha}, expected ${release_sha}."
            echo "::error::Tags are immutable under the release ruleset. Do not move or delete ${RELEASE_TAG}; choose a new tag after main points at the intended release commit."
            echo "::error::Recovery: gh workflow run workspace-publish.yml --ref main -f tag=<new-tag>"
            exit 1
        fi
    fi
else
    # Guardrail path: a release is already public. We do not build or
    # upload assets here, because doing so would recreate the public-first
    # race this workflow is meant to avoid. Instead, require the expected
    # assets to already be present before crates are published.
    git fetch origin "refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}" --force --depth=1
    release_sha="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"

    if [[ "${release_sha}" != "${main_sha}" ]]; then
        echo "::error::Release tag ${RELEASE_TAG} points at ${release_sha}, but origin/main is ${main_sha}."
        echo "::error::Tags are immutable under the release ruleset. Do not move or delete ${RELEASE_TAG}; publish a follow-up release from the current main commit instead."
        echo "::error::Recovery: gh workflow run workspace-publish.yml --ref main -f tag=<new-tag>"
        exit 1
    fi

    release_assets="$(gh release view "${RELEASE_TAG}" --json assets -q '.assets[].name')"
    required_assets=(
        "miden-vm-aarch64-apple-darwin"
        "miden-vm-x86_64-unknown-linux-gnu"
        "core.masp"
    )

    missing=0
    for asset in "${required_assets[@]}"; do
        if ! grep -Fxq "${asset}" <<< "${release_assets}"; then
            echo "::error::Release ${RELEASE_TAG} is already public but is missing required asset ${asset}."
            missing=1
        fi
    done

    if [[ "${missing}" -ne 0 ]]; then
        echo "::error::This fallback never builds assets after a release is public."
        echo "::error::If this release can still be converted back to draft, do that first, then rerun: gh workflow run workspace-publish.yml --ref main -f tag=${RELEASE_TAG}"
        echo "::error::If release/tag immutability prevents making it draft again, leave this release alone and cut a new tag with: gh workflow run workspace-publish.yml --ref main -f tag=<new-tag>"
        exit 1
    fi
fi

echo "tag=${RELEASE_TAG}" >> "${GITHUB_OUTPUT}"
echo "sha=${release_sha}" >> "${GITHUB_OUTPUT}"
