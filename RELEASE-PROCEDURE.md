# miden-vm release procedure

Releases are made from `main`.

## Prepare the source tree

- In `CHANGELOG.md`, replace `(TBD)` for the release version with the release date.
- Set the version for each crate that will be published.
- Set matching workspace dependency versions in the root `Cargo.toml`.
- Update `release-packages.txt` if the default release set changed.

Publishable crates have their own `version` field. Private workspace members use
the workspace version in the root `Cargo.toml`.

Keep `release-packages.txt` in dependency order. If a crate depends on another
workspace crate that is not already on crates.io at the required version, include
that dependency earlier in the list.

## Check the release

Run the dry run before publishing.

```bash
gh workflow run workspace-dry-run.yml \
  --ref main \
  -f packages_file=release-packages.txt
```

To dry-run a smaller set of crates, pass the list directly.

```bash
gh workflow run workspace-dry-run.yml \
  --ref main \
  -f packages="midenc-hir-type miden-assembly-syntax"
```

For a local check, run the same script used by CI.

```bash
scripts/release-selected.sh \
  --mode dry-run \
  --packages-file release-packages.txt \
  --allow-dirty
```

## Publish the release

On the [Actions page](https://github.com/0xMiden/miden-vm/actions), run
`Publish workspace to crates.io`.

Use the release tag as the `tag` input. Use `packages_file` for the default list,
or use `packages` for a smaller release.

```bash
gh workflow run workspace-publish.yml \
  --ref main \
  -f tag=v0.24.0 \
  -f packages_file=release-packages.txt
```

The workflow creates or checks a draft GitHub release, uploads release assets,
publishes the selected crates, and then publishes the GitHub release.

After the workflow finishes, check the
[releases page](https://github.com/0xMiden/miden-vm/releases) and crates.io.
