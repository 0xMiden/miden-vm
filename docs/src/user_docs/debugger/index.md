---
title: The Miden Debugger
sidebar_position: 1
---

# The Miden Debugger

`miden-debug` loads a compiled `.masp` package and lets you inspect its execution.
You can set breakpoints and step through instructions while inspecting memory and the stack.
Packages with debug information also expose source locations and typed variables.

The debugger is part of the Miden VM workspace and follows its release cycle.
It provides the following interfaces.

| Interface | Selection | Guide |
| --- | --- | --- |
| Terminal UI | Default | [TUI](./tui.md) |
| Command prompt | `--repl` | [REPL](./repl.md) |
| Remote DAP connection | `--dap-connect ADDR` | [DAP](./dap.md) |

## Installation

Use `midenup` to install a released toolchain that includes the debugger. Invoke that
component as `miden debug`. You can also install `miden-debug` from crates.io with
`cargo install --locked miden-debug`, selecting a version that matches your VM toolchain.

To build from a Miden VM checkout, run:

```bash
cargo build --locked -p miden-debug --bin miden-debug
```

To install that checkout's debugger, run:

```bash
cargo install --locked --path crates/debugger --bin miden-debug
```

Default builds enable the terminal UI and command prompt, with DAP and flamegraph support.
Python scripting requires a CPython development installation. See the
[Python scripting guide](./python-scripting.md) for its configuration.

## Start a debugging session

Pass a compiled package to the debugger:

```bash
miden-debug path/to/program.masp
```

Use `--repl` for a command prompt or `--dap-connect 127.0.0.1:4711` to connect to a
running DAP server. The debugger stops at cycle zero so you can set breakpoints before
execution begins. Examples elsewhere in this guide use the `miden debug` form provided
by midenup. Replace it with `miden-debug` when using a standalone installation.

The [CLI reference](./cli.md) describes command flags and input options.
For Rust integrations, see [debugging programmatically](./debugging-programmatically.md).
