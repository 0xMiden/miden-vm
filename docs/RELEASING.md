# VM releases

Start `workspace-publish.yml` manually from the branch that contains the release commit.
The workflow builds and publishes that commit.

| Branch | Allowed release |
| --- | --- |
| `main` | Stable releases, including the final `1.0.0` |
| `release/vVERSION` or `release-vVERSION` | The matching stable patch release |
| `next` | Release candidates with an `rc.N` suffix |

A patch branch must include its `.0` tag and the latest earlier stable patch tag in the same major/minor line.
For example, `release-v0.35.1` must descend from `v0.35.0`.
You can publish a patch after publishing a newer minor version.
The package version gate checks version order against published prereleases.
It checks API compatibility against stable releases in the same major/minor line.
For a new line, it uses the latest stable version when one exists.

## Prepare the commit

Apply the release workflow and script changes to each release branch.
Each branch runs its own copy of the workflow.
Keep the workflow filename and the `release` environment name because crates.io uses them to identify the trusted publisher.

Update the versions of the crates you intend to release.
For a release candidate, update their workspace dependency requirements to the intended prerelease too.
The tag must equal `v` followed by the `miden-vm` crate version.
Run the package version gate and workspace dry-run on that commit.
Keep the branch at that commit until publication finishes.

## Approval

The `release` environment requires approval from an authorized repository admin.
An admin can approve their own release. Keep admin bypass disabled.
Configure named users as required reviewers. The workflow checks that each user has repository admin access.
It repeats the check after approval before publication jobs proceed.
Update the reviewer list when admin access changes.
Allow deployments from `main`, `next`, `release/v*`, and `release-v*`.

## Start the release

To release a patch from its matching branch, run:

```sh
gh workflow run workspace-publish.yml --repo 0xMiden/miden-vm \
  --ref release-v0.35.1 -f tag=v0.35.1
```

For a release candidate, use `--ref next -f tag=v1.0.0-rc.1`.
Use `--ref main` for stable minor releases and the final `v1.0.0`.
Review the branch and commit in the Actions run before approving its pending jobs.
Builds and package verification run without publication credentials.
The publisher receives its token only for the Cargo upload step, which skips compilation.
The workflow checks the branch before tag creation and crate publication.
It checks the remote tag again before making the GitHub release public.
GitHub marks release candidates as prereleases.
Patch branches do not replace GitHub's latest release. Stable releases from `main` do.

## Recover a partial release

Rerun the workflow for the same commit with `allow_existing=true` to finish a partial publication.
The package version gate checks existing crate archives against local packages and excludes them from publication.
The gate is required for every release.
Do not move or delete release tags. If the commit must change after tag creation, prepare a new version.
If the GitHub release is already public, convert it back to draft if permitted before retrying.
Otherwise, prepare a new version.
