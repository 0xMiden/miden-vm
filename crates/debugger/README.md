# Miden Debugger

This repo provides the implementation of the `miden debug` command, i.e. an interactive debugger for Miden programs.

The underlying `miden-debug` crate may also be used as a library, for use cases where you want to use the debugger as an executor for Miden programs, such as
in tests, etc.

See the [documentation](https://github.com/0xMiden/compiler/tree/next/docs/external/src/guides/debugger.md) for more details on the `miden debug` command, and how to use the debugger.

## Engine features

`miden-debug-engine` uses `#![no_std]` and `alloc`. Without default features, it provides
in-memory package decoding, typed variable resolution, memory inspection, input parsing, and
replay serialization. The default `std` feature adds interactive execution, profiling, filesystem
access, and CLI parsers; `dap` also enables `std`.

The engine is checked and tested separately with `--no-default-features`. Fully bare-metal builds
still require upstream dependency fixes: VM 0.30 pulls in std-only dependencies such as `flume`
through `miden-crypto` and `textwrap` through `miden-miette/fancy-no-syscall`.

## Coverage

Run the workspace tests with LLVM source coverage locally with:

```bash
cargo make coverage
```

This writes a Cobertura report to `rust-coverage.xml`. CI uploads the same report as the
`rust-coverage` artifact, and [octocov](https://github.com/k1LoW/octocov) comments on each pull
request with the coverage changes against the base branch, including the files the pull request
touches. The coverage is only reported: below 75% line coverage the report carries a warning,
but CI does not fail. Unit tests live in separate `tests.rs` or `*_tests.rs` files, and shared
test helpers live under `tests/`. These paths are excluded from the report by cargo-llvm-cov's
default filename filters. All workspace tests still run, including TUI rendering tests using
Ratatui's in-memory test backend; the production code they exercise contributes to coverage.

## License

MIT
