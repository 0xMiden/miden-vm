# miden-vm release procedure - how to do a release

Releases are made against the `main` branch. Make sure all the following changes
are present on the said branch at the time of release.

## in the source code repo

- in `CHANGELOG.md`, update the `(TBD)` next to the upcoming version with today's date
- bump the workspace version in `Cargo.toml`

## on GitHub

- on the [Actions page](https://github.com/0xMiden/miden-vm/actions), click the
  "Publish workspace to crates.io" tab. There, click the `"Run workflow"` button
  - when prompted for a release version, make sure to provide the same version as the one present on the `Cargo.toml` file
  - wait for the action to finish running
- publish the newly added draft release found on the [releases page](https://github.com/0xMiden/miden-vm/releases).
