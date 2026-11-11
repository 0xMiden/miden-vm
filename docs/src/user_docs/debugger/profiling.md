---
title: Profiling
sidebar_position: 10
---

# Profiling

Profiling generates an execution profile that shows which operations consume the most cycles. This helps identify hotspots in Miden Assembly programs.

## Usage

Run the debugger with

- `--commands` to execute a script
- `--profiling-reports-dir` to set the output directory
- and `--profiling-instruments` to enable one or more profiling instruments

```bash
miden debug \
    --profiling-reports-dir ./reports \
    --profiling-instruments op-histogram-global \
    --commands cmds.txt \
    fibonacci:fibonacci.masp -- 42
```

The `cmds.txt` script should contain:

```text
# Run until completion
continue
# Optionally print stack outputs
stack
```

Once passing commands as CLI parameters is supported [[#97](https://github.com/0xMiden/miden-debug/issues/97)], no separate `cmds.txt` file will be needed.

Reports are written to the directory specified by `--profiling-reports-dir`, with one file per instrument named after the instrument.

## Instruments

Two instruments are available:

- `op-histogram-global`: one histogram over all executed operations, regardless of which
  procedure they belong to.
- `op-histogram-proc`: separate histograms per procedure, for attributing cycles to specific
  procedures.

## Interpretation

The output file contains a histogram of operation counts sorted by frequency. Counts are weighted by cycle, so if `opx` takes 4 cycles and is executed twice, its value in the histogram will be 8.

### Global histogram

The global histogram combines operations from every procedure executed during the run into one histogram. It does not provide a per-procedure breakdown.

### Procedure histograms

`op-histogram-proc` writes a single file containing one histogram section per procedure, each prefixed with the procedure name. Sections are ordered by descending cycle count, so the most expensive procedure comes first. Operations that cannot be attributed to a procedure (e.g. during program setup) are collected in a separate `<unknown>` section.

For packages compiled from Rust, each procedure name corresponds to a function in the Rust source — qualified with the crate namespace, e.g. `"root_ns:root@1.0.0"::fibonacci::entrypoint`. Compiler-generated functions, such as intrinsics, appear under their own names. Attribution does not see through inlining, so inlined functions have no section of their own.

Per-procedure attribution relies on debug info embedded in the package. For packages without debug info, all operations are attributed to `<unknown>`.

