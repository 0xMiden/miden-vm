# miden-vm release procedure - how to do a release

## in the source code repo

- in `CHANGELOG.md`, update the `(TBD)` next to the upcoming version with today's date

- bump the workspace version in `Cargo.toml`

## on GitHub

- on the [Actions page](https://github.com/0xMiden/miden-vm/actions), click the
  "Publish workspace to crates.io" tab. There, click the `"Run workflow"` button
  - wait for the action to run

- publish the newly added draft release found on the [releases page](https://github.com/0xMiden/miden-vm/releases).
