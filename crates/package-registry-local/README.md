# miden-package-registry-local

Local filesystem-backed registry and CLI for publishing and inspecting Miden packages.

The data managed by this registry using the local filesystem is as follows:

- The registry index, stored at `$MIDEN_SYSROOT/etc/registry/index.toml`
- The artifacts of registered packages, as `$MIDEN_SYSROOT/lib/<digest>.masp`

The `MIDEN_SYSROOT` directory is managed by [`midenup`](https://github.com/0xMiden/midenup), and automatically made available to `miden-registry` when invoked as `miden registry`. If running `miden-registry` directly, you must ensure that the `MIDEN_SYSROOT` environment variable is set in your shell.

## Usage

When installed via `midenup`, this tool can be invoked with `miden registry`, otherwise it can be built and used directly as `miden-registry`. In the docs here, we will use `miden registry`.

The `miden registry` command has the following subcommands:

- `list`, for listing registered packages and their available versions
- `show`, for showing details of a specific package version
- `publish`, for publishing packages to the registry

See below for more details.

### Listing packages

To show a list of available packages, use the `list` subcommand:

```
miden registry list [--json]
```

The `--json` flag will cause the output to be in JSON format, which makes it easier to consume by other tools if needed.

### Showing package details

To show details of a specific package version, use the `show` subcommand:

```
# Show details for the latest version of `<package>`
miden registry show <package> [--json] [--quiet]

# Show details for version `<version>` of `<package>`
miden registry show <package> --version <version> [--json] [--quiet]
```

The `--json` flag will cause the output to be in JSON format, which makes it easier to consume by other tools if needed.

The `--quiet` flag causes error output to be suppressed if a given package or version doesn't exist in the registry. This can be convenient when used in scripts to test for the existence of a package in the registry. By default, the specific reason for an error is emitted to stderr.

### Publishing a package

To make a newly-assembled package available via the registry, it must be published, like so:

```
miden registry publish path/to/<package>.masp
```

This will output an error if the package is invalid, that version of the package has already been registered, or if there is an issue persisting the updated index.

In addition to ensuring the package artifact is valid, additional rules are enforced as part of the publishing process:

- The package must embed semantic version metadata
- Each package semantic version maps to at most one canonical published artifact in the local registry, i.e. a given version of a package may only be published once.
- Every dependency in the package manifest must already exist in the registry by exact digest
- Dependency requirements are persisted as exact resolved digests, not the original declared version requirements

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
