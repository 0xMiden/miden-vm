# Miden Debugger

`miden-debug` is an interactive debugger for Miden VM programs. It provides a terminal UI
and a command prompt. Editors can connect through the Debug Adapter Protocol, and Rust
programs can use the crate as a library.

The debugger is part of the Miden VM workspace and follows its release cycle.
See the [debugger guide](../../docs/src/user_docs/debugger/index.md) for installation and usage.

Build the command from the workspace root with:

```bash
cargo build --locked -p miden-debug --bin miden-debug
```

Run Rust tests with `make test-debugger`. Run the lit/FileCheck fixtures with
`make test-debugger-lit`, which requires litcheck and a CPython development installation
for the optional Python scripting tests. Set `PYO3_PYTHON` to choose the interpreter.

`miden-debug-engine` provides the execution and inspection APIs. Its `std` feature enables
interactive execution and profiling, along with filesystem access and CLI parsers.
Default builds enable the terminal UI and command prompt, with DAP and flamegraph support.
Python scripting is optional.

Crates are checked and published through the workspace release workflows. The fixture
builders in `tests/lit/support` remain private. The standalone debugger release history is
preserved in [CHANGELOG.md](CHANGELOG.md) and [CHANGELOG-legacy.md](CHANGELOG-legacy.md).

## License

MIT. See [LICENSE.md](LICENSE.md).
