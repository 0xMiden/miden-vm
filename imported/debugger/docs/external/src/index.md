---
title: The Miden Debugger
sidebar_position: 1
---

# The Miden Debugger

`miden-debug` is the interactive debugger for Miden VM programs. It loads a
compiled `.masp` (Miden Assembly Package), sets up the Miden VM, and lets you
step through execution at the cycle, instruction, or source-line level — with
breakpoints, memory inspection, stack views, and source-level variable
resolution from package debug information.

The same crate ships three execution modes:

| Mode | Flag | When to use |
| ---- | ---- | ----------- |
| **TUI** (default) | _none_ | Full-screen interactive UI with live source, disassembly, operand stack, call stack, and breakpoints. See [TUI mode](./tui.md). |
| **REPL** | `--repl` | Plain-text interactive prompt — useful over slow terminals, for scripting, or when ANSI/UTF-8 features aren't available. See [REPL mode](./repl.md). |
| **DAP client** | `--dap-connect ADDR` | Connect to a remote DAP server (typically `miden-client exec --start-debug-adapter`) and drive it through the same TUI. See [DAP](./dap.md). |

The TUI and REPL share the same execution engine and breakpoint model — the
difference is purely how the UI is rendered and how you type commands.

## Installation

Use `midenup` to install and manage your Miden toolchain. When using `midenup`,
invoke the debugger as `miden debug`; the examples throughout this guide use
that form.

You can also install the standalone debugger from crates.io:

```bash
cargo install --locked miden-debug
```

Or from source:

```bash
git clone https://github.com/0xMiden/miden-debug && cd miden-debug
cargo make miden-debug
```

For standalone installations, replace `miden debug` in the examples with
`miden-debug`, or `bin/miden-debug` when building from source.

The default build enables the `tui`, `dap`, `repl`, and `flamegraph` features.

To strip everything except what you need, combine `--no-default-features` with
the explicit feature list, for example `--features tui,repl`. Batch command
files only need the smaller `script` feature.

## Quick start

```bash
# Compile your Miden project first
miden build

# Drop into the TUI
miden debug target/miden/dev/my-package.masp

# Or the plain REPL
miden debug --repl target/miden/dev/my-package.masp

# Or attach to a running miden-client DAP server
miden debug --dap-connect 127.0.0.1:4711
```

`miden build` uses the `dev` profile by default. Replace `my-package.masp` with
the package filename reported by the build.

When the debugger starts on a freshly-loaded program, it stops at cycle 0 so
you can set breakpoints before execution begins.

## Where to go next

- **[CLI reference](./cli.md)** — every flag accepted by `miden debug`, including
  inputs, linker, working directory, and entrypoint selection.
- **[TUI mode](./tui.md)** — keyboard shortcuts, panes, the `:` command prompt,
  breakpoints, reading memory, and `:vars` for source variables.
- **[REPL mode](./repl.md)** — text-only command reference for the same
  capabilities, organised for quick lookup.
- **[DAP integration](./dap.md)** — how the debugger wires up to `miden-client`
  for transaction-script debugging, the architecture of the DAP server,
  and how IDE clients (VS Code, Zed, the TUI itself) attach to it.
- **[Debugging Programmatically](./debugging-programmatically.md) - how to set up and use the debug engine in Rust for use in tests and as a general program execution engine
