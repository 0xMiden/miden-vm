# miden-vm release procedure

Releases are made from `main`.

## Prepare the source tree

- In `CHANGELOG.md`, replace `(TBD)` for the release version with the release date.
- Set the version for each crate that will be published.
- Set matching workspace dependency versions in the root `Cargo.toml`.

Publishable crates have their own `version` field. Private workspace members use
the workspace version in the root `Cargo.toml`.

## Check the release

Run the dry run before publishing.

```bash
gh workflow run workspace-dry-run.yml \
  --ref main
```

To dry-run a smaller set of crates, pass the list directly.

```bash
gh workflow run workspace-dry-run.yml \
  --ref main \
  -f packages="midenc-hir-type miden-assembly-syntax"
```

For a local check, use the same workspace publish path in dry-run mode.

```bash
cargo publish --workspace --locked --dry-run
```

## Publish the release

On the [Actions page](https://github.com/0xMiden/miden-vm/actions), run
`Publish workspace to crates.io`.

Use the release tag as the `tag` input. Leave `packages` empty for all publishable
workspace crates, or pass `packages` for a smaller release.

```bash
gh workflow run workspace-publish.yml \
  --ref main \
  -f tag=v0.24.0
```

The workflow creates or checks a draft GitHub release, uploads release assets,
publishes the selected crates, and then publishes the GitHub release. The
dry-run workflow skips crate versions that already exist on crates.io; the
publish workflow stays strict unless a package list is supplied.

After the workflow finishes, check the
[releases page](https://github.com/0xMiden/miden-vm/releases) and crates.io.
