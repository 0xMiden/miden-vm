# lit / FileCheck debugger tests

End-to-end tests that drive `miden-debug` over small Miden Assembly programs and
check its output with [`litcheck`](https://crates.io/crates/litcheck) (a
pure-Rust implementation of LLVM `lit` + `FileCheck`).

The debugger only loads compiled packages. Every test explicitly builds a temporary `.masp`
fixture before invoking `miden-debug`, making the producer/consumer boundary visible in its `RUN`
directives. The private fixture builders live under `tests/lit/support`; they are test
infrastructure, not debugger inputs or installed CLI tools.

When a package entrypoint carries a component-model signature, trailing CLI arguments are encoded
with that signature's canonical ABI and the completed result is decoded with the same metadata.
This lets Rust values such as `u64` use their multi-felt representation while untyped MASM
programs retain raw-felt argument handling.
Typed frame-base and expression locations are read from packed byte-addressed memory before being
lifted into that canonical representation, including values that cross Miden element boundaries.

Backtraces use the VM's cached call-frame resolver to retain callers across plain `exec`,
`call`, and dynamic boundaries. Frames recovered by inference are labeled `[inferred]`;
source inline frames remain labeled `[inlined]`. The trace-event stack continues to drive
execution control and profiling, and provides a fallback when source metadata is absent.

Variable tests inspect values at a live breakpoint. After successful termination, `vars`,
`vars all`, and `locals` report that there are no live variables, and Python variable queries
return an empty dictionary. Completed program results remain available separately.

Python scripting tests run `miden-debug-python`, a second local copy built with
the `python` feature, and pass `--no-user-python-init` so user configuration
cannot affect their output.

## Layout

```
tests/lit/
  lit.suite.toml     # suite config: only *.test files are test entry points
  support/           # private fixture builders
  add.masm           # a MASM fixture ...
  add.test           # ... and the test that builds and debugs it
  breakpoint.masm
  breakpoint.test
  error.masm
  error.test
```

## How a test works

A `.test` file is, at once:

1. A **command script** for the debugger. `miden-debug --commands <file>` runs
   each non-`#` line as a REPL command (gdb's `-x` / lldb's `-s`). Lines starting
   with `#` are ignored by the debugger.
2. A **FileCheck input**. `filecheck` reads the `# CHECK:` lines and matches them
   against the debugger's output.
3. A **lit test**. The `# RUN:` line tells lit what to execute.

For example, `add.test`:

```text
# RUN: compile-masm %S/add.masm -o %t.masp
# RUN: miden-debug --commands %s %t.masp 2>&1 | filecheck %s

continue
stack

# CHECK: Program terminated successfully
# CHECK: [0] 7
```

`%s` is the test file, `%S` its directory, and `%t` a per-test temporary path. The first
command assembles the source fixture; the second loads only the resulting package, runs the
`continue` and `stack` commands, and pipes the output to `filecheck`.

## Running

```sh
cargo make test-lit
```

This installs the lit tools; builds `miden-debug`, its Python-enabled variant, and the private
fixture builders into `./bin`; then runs the suite via `litcheck lit run`.

## Adding a test

Add a `<name>.masm` fixture and `<name>.test` beside it. The test must explicitly build `%t.masp`
before passing it to the debugger. Do not check generated `.masp` files into the repository.
Two MASM facts to keep in mind:

- The operand stack starts as 16 padding zeros and is always shown padded.
- The VM requires at most 16 elements at program end — fold results into a
  padding zero (e.g. a trailing `add`) to terminate cleanly, or assert on the
  resulting error like `error.test`.

Prefer asserting on stable facts (a known computed result) over incidental
formatting.

Specialized tests may use `compile-abi-fixture` or `compile-masm` options to inject metadata that
has no textual MASM representation. Those helpers remain private to the lit suite; production
debugger code never parses or assembles source files.
