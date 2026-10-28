# Compiler advice analysis for core MASM

This unpublished tool runs the compiler's advice analysis for
[VM #3710](https://github.com/0xMiden/miden-vm/issues/3710) and
[compiler #1209](https://github.com/0xMiden/compiler/issues/1209).
It reads `crates/lib/core/asm/miden-project.toml` directly, without filtering
source files or creating an adapter project.

Core analysis on VM `next` is blocked by the compiler pin's VM 0.35 instruction
set. See [Current validation](#current-validation) for the first parser failure.

## Running it

```sh
make build-masm-advice-lint
make test-masm-advice-lint
make lint-masm-advice-lint
make masm-advice-lint
make masm-advice-lint args=--verbose
make masm-advice-lint args='--target miden::core'
bash scripts/check-masm-advice-taint.sh --help
bash scripts/check-masm-advice-taint.sh --verbose
bash scripts/check-masm-advice-taint.sh --verbose path/to/miden-project.toml
```

`tools/midenc-masm-lint` is a separate Cargo workspace with its own manifest and
lockfile. Its Rust toolchain is pinned. The compiler dependencies use commit
`2be47a4e15559c66c821882c7c91a6ac0ca18656` from
[compiler #1473](https://github.com/0xMiden/compiler/pull/1473).
That compiler retains its published VM 0.35 and HIR type 0.17 dependencies.
Existing VM workspace dependencies and lockfiles are unchanged.

Update the pin and tool lockfile together when adopting compiler changes.

`make test-masm-advice-lint` runs the renderer test and CLI fixtures.
`make lint-masm-advice-lint` checks Rust formatting and Clippy, then runs ShellCheck
on the runner and test scripts.

The runner accepts an optional manifest path and defaults to core when none is given.
Use `--target <name>` to select a target from that manifest. The default is the
library target, or the first executable if there is no library. Each report names
the manifest and selected target. `--help` or `-h` prints usage without analyzing code.
`MIDENC_MASM_LINT` can select
another already built copy of the tool. No installed Miden sysroot is required.
The tool clears the implicit compiled core import before loading core from source.

## Output and failure policy

Default output shows source locations for operation sinks and groups return
advisories by function and result index. A coverage footer counts root failures
separately from callers that depend on skipped procedures. Individual skip warnings
and full source/call diagnostics appear with `--verbose` or `-v`.
Both modes run the same interprocedural analysis with a 10,000-work-item budget.
Display detail does not change the counts or exit status.

| Exit status | Meaning |
| --- | --- |
| 0 | A complete scan found no issues or skipped procedures. |
| 1 | Findings cause failure. Skips or budget exhaustion also fail. |
| 2 | Invalid arguments or a project-loading, lifting, or analysis error. |

Public-return advisories remain fatal in this implementation. Any later change to
that enforcement policy needs review and must preserve taint through callers.

The pinned compiler tracks [stream and Horner memory propagation](https://github.com/0xMiden/compiler/issues/1469)
and skips [compiled procedures](https://github.com/0xMiden/compiler/issues/1470)
with neither a body nor a complete advice and memory effect summary.
It preserves [stack taint and advice origins during deferred-data registration](https://github.com/0xMiden/compiler/issues/1471).
The [`u32cast` and `eq.0` controls](https://github.com/0xMiden/compiler/issues/1472) from the VM review now pass.
The report's coverage counts describe procedures the compiler lifted, so those
counts do not account for missing rules within a lifted procedure.

## Manual CI evidence

`Core MASM advice evidence` runs only through `workflow_dispatch`. It builds the
CLI and checks the fixtures in both modes. It then collects compact and
verbose core reports and exit statuses, uploads the evidence even on failure,
and fails if the modes disagree or the analysis returns a failing status.
It is not a required PR check while the core still has coverage gaps and reports.
No release workflows or branch protections change in this branch.

## Current validation

The VM `next` branch uses version 1.0.0-rc.1. The pinned compiler still uses VM 0.35
and cannot parse the `compress` instruction in `sys/vm/ood_frames.masm`.
Both modes exit with status 2 before taint analysis starts. The core scan has no
finding or coverage counts on `next`. The compiler must support the VM 1.0
instruction set before this tool can analyze the current core library.

The last VM 0.36 core scan completed with the same compiler pin. Both modes reported
12 diagnostics and 359 skipped procedures, and exited with status 1.
The reports comprised six operation sinks and six public-return advisories. They need
triage before classification as MASM defects. The 117 root failures cause another
242 callers to be skipped. Root failures include 46 analysis-size limits and
67 stack/signature inference failures, with four unsupported constructs.

Evidence from the current VM `next` scan is in
`target/masm-advice-lint/evidence/core-taint-compact.txt` and
`target/masm-advice-lint/evidence/core-taint-verbose.txt`.
Both files contain the parser failure described above. Each evidence run overwrites
both files.
The CLI cases cover clean code, sink findings,
grouped returns, and advice passing through declared word and pointer arguments.
They verify that skipped dependencies cause failure even when unrelated code is clean.
An empty child module and budget exhaustion cannot return success.
Argument errors and missing or malformed manifests must return status 2 in both modes.
Target tests distinguish the default library from an executable with findings.
They also cover the first executable default and reject unknown target names.
The CLI passes formatting and Clippy with warnings denied. Both scripts pass
ShellCheck, and the manual workflow passes Actionlint.
