# miden-vm release procedure

Release crates from the current `main` commit. Crates imported into this
workspace, including the Miden crypto crates, are released from this repository.

## Choose the scope

Leave `packages` empty for a full release. Every publishable crate must have an
unused version.

Set `packages` for a limited release, such as a patch or minor release of one
crate. Include every workspace dependency whose required version is not yet on
crates.io.

The `packages` input limits crates.io publication only. The workflow still
creates a repository tag, builds the VM assets, and publishes a GitHub release.
It cannot publish only to crates.io.

For crates below version 1.0, a minor bump is incompatible. For example,
`0.28.1` to `0.29.0` may remove public API. A compatible fix uses a patch bump
such as `0.28.1` to `0.28.2`.

## Prepare `main`

- Give each selected crate an unused version.
- Update its entry in `[workspace.dependencies]` in the root `Cargo.toml`.
- Update `Cargo.lock` and any affected fuzz lockfiles.
- Add a dated section to `CHANGELOG.md`. Name the crate in the heading for a
  limited release.

Bump a downstream crate only when it must publish a new dependency requirement.
Merge all release changes to `main` before continuing.

## Check and publish

Check the exact package list locally, then run the same list through the dry run.

```bash
scripts/check-package-release-plan.sh miden-crypto

gh workflow run workspace-dry-run.yml \
  --ref main \
  -f packages="miden-crypto"
```

Publish from the
[Actions page](https://github.com/0xMiden/miden-vm/actions), or use `gh`.

```bash
gh workflow run workspace-publish.yml \
  --ref main \
  -f tag=v0.28.2 \
  -f packages="miden-crypto"
```

Use the same package list for every command. Leave `packages` out for a full
release. The publish workflow rejects versions that already exist on crates.io.
Set `allow_existing=true` only when resuming a partial publish.

After the workflow finishes, check the
[GitHub release](https://github.com/0xMiden/miden-vm/releases) and every selected
crate on crates.io.
