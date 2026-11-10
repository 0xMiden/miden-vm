---
title: CLI reference
sidebar_position: 2
---

# CLI reference

```text
miden debug [OPTIONS] [FILE] [-- ARGV...]
```

`miden debug` accepts a single positional `FILE` (the program to debug) and an
optional trailing `-- ARGV...` block whose elements are pushed onto the operand
stack before the program runs.

Run `miden debug --help` for the canonical, version-pinned list. The tables
below describe every option that's stable today.

## Program input

| Flag | Value | Description |
| ---- | ----- | ----------- |
| `FILE` | path or `-` | Path to a compiled `.masp` Miden Assembly Package. Use `-` to read package bytes from stdin. Omit when using `--dap-connect`. |
| `-- ARGV...` | field elements | Arguments pushed on the operand stack in order — the first element ends up at the top of the stack. Decimal or `0x`-prefixed hex. **These override** any `inputs.stack` set in the inputs file. |
| `--inputs FILE` | path | TOML file describing program inputs (operand stack, advice stack, advice map) and execution options. See [Program inputs](#program-inputs). |
| `--entrypoint <module>::<function>` | symbol | Override the program's entrypoint. Defaults to the package's declared entry. |

## Execution

| Flag | Value | Description |
| ---- | ----- | ----------- |
| `--working-dir DIR` | path | Working directory the debugger uses for source lookups. Defaults to the current shell `cwd`. |
| `--repl` | _flag_ | Use the plain-text REPL instead of the TUI. Requires the binary to be built with the `repl` feature. See [REPL mode](./repl.md). |
| `-x`, `--commands FILE` | path | Run a script of REPL commands non-interactively, then exit — analogous to `gdb -x FILE -batch`. Blank lines and lines starting with `#` are skipped. Requires the `script` feature (also enabled by `repl`). |
| `--dap-connect ADDR` | `host:port` | Connect to a remote DAP server (e.g. `127.0.0.1:4711`) and drive it through the TUI. Mutually exclusive with passing a `FILE`. See [DAP](./dap.md). |

## Linker

The package loader makes compiled dependency packages available during
execution. It never compiles MASM files or Miden projects.

| Flag | Value | Description |
| ---- | ----- | ----------- |
| `-L`, `--search-path PATH` | path | Add a directory to the library search path. Repeat to add several. |
| `-l`, `--link-library [KIND[:LINKAGE]=]NAME` | name | Load a compiled package by path or namespace. `KIND` currently supports only `masp` (the default). `LINKAGE` is `static` or `dynamic` and defaults to `dynamic`. Repeat for multiple libraries. |
| `--sysroot DIR` | path | Root of the Miden toolchain. Defaults to `$(midenup show home)/toolchains/$(midenup show active-toolchain)`. Read from the `MIDEN_SYSROOT` env var when neither flag nor `midenup` is available. |

## Output

| Flag | Value | Description |
| ---- | ----- | ----------- |
| `--color MODE` | `auto`, `always`, `always-ansi`, `never` | Control terminal colouring. Defaults to `auto` — colours when the terminal supports them, off when `NO_COLOR` is set or `TERM=dumb`. |

## Environment variables

| Variable | Effect |
| -------- | ------ |
| `MIDENC_TRACE` | Standard `env_logger` filter (`info`, `miden_debug=debug`, etc.). Logs are emitted to stderr. |
| `MIDENC_TRACE_TIMING` | Set to `s`, `ms`, `us`, or `ns` to include timestamps with the chosen precision. |
| `MIDEN_SYSROOT` | Fallback for `--sysroot`. |
| `NO_COLOR` | When set, suppresses colour even with `--color auto`. |

## Program inputs

For programs that expect operands or advice-provider data, you have two
options that can be combined.

### Stack arguments on the command line

```bash
miden debug fib.masp -- 1 2 0xdeadbeef
```

The first argument lands on top of the stack, the next below it, and so on.
Each argument must be a valid field element in decimal or `0x`-prefixed hex.

### Inputs file (`--inputs`)

The TOML format below mirrors the one accepted by `midenc debug` so configs
can be reused.

```toml
# Execution options.
[options]
max_cycles      = 5000
expected_cycles = 4000

# Operand stack — leftmost element is on top.
[inputs]
stack = [1, 2, 0xdeadbeef]

# Advice provider.
[inputs.advice]
stack = [1, 2, 3, 4]

# Advice-map entries (arbitrary number; last write wins on duplicate keys).
[[inputs.advice.map]]
digest = "0x3cff5b58a573dc9d25fd3c57130cc57e5b1b381dc58b5ae3594b390c59835e63"
values = [1, 2, 3, 4]

[[inputs.advice.map]]
digest = "0x20234ee941e53a15886e733cc8e041198c6e90d2a16ea18ce1030e8c3596dd38"
values = [5, 6, 7, 8]
```

When `--inputs` and `-- ARGV...` are used together, command-line stack
arguments **override** `inputs.stack`. The advice stack and advice map come
from the file in either case.

## Examples

```bash
# TUI on a compiled package
miden debug target/miden/dev/fib.masp

# REPL with operand stack arguments
miden debug --repl fib.masp -- 10

# Use an inputs file
miden debug fib.masp --inputs ./fib.toml

# Custom entrypoint
miden debug lib.masp --entrypoint mylib::main

# Override search path and load a compiled library
miden debug prog.masp -L ./target/masp -l my_lib

# Attach to a remote DAP server
miden debug --dap-connect 127.0.0.1:4711
```
