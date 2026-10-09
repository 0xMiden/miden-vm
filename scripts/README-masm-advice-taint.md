# Compiler advice analysis for core MASM

This unpublished tool runs the compiler's advice analysis for
[VM #3710](https://github.com/0xMiden/miden-vm/issues/3710) and
[compiler #1209](https://github.com/0xMiden/compiler/issues/1209).
It analyzes `crates/lib/core/asm/miden-project.toml` directly, without filtering
source files or creating an adapter project.

## Running it

```sh
make build-masm-advice-lint
make test-masm-advice-lint
make masm-advice-lint
bash scripts/check-masm-advice-taint.sh --verbose
bash scripts/check-masm-advice-taint.sh --verbose path/to/miden-project.toml
```

`tools/midenc-masm-lint` is a separate Cargo workspace with its own manifest,
lockfile, and pinned Rust toolchain. Its compiler dependencies use commit
`9b6991137254823a6bf9e7a9b6d68600204a3312` from the compiler fixes branch.
That compiler retains its published VM 0.35 and HIR type 0.17 dependencies.
Existing VM workspace dependencies and lockfiles are unchanged.

The compiler commit is currently local. For local validation, its objects were
fetched from the compiler worktree into Cargo's Git source cache, without changing
Git hooks or repository dependency declarations. This pin must be available from
`0xMiden/compiler` before a fresh network checkout or hosted workflow can build.
Update the pin and tool lockfile after the compiler PR merges if its SHA changes.

The runner accepts an optional manifest path. `MIDENC_MASM_LINT` can select
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
| 0 | No diagnostics or skipped procedures, and analysis completed. |
| 1 | Diagnostics, skipped procedures, or exhausted analysis budget. |
| 2 | Invalid arguments or a project-loading, lifting, or analysis error. |

Public-return advisories remain fatal in this implementation. Any later change to
that enforcement policy needs review and must preserve taint through callers.

## Manual CI evidence

`Core MASM advice evidence` runs only through `workflow_dispatch`. It builds the
CLI and checks all eight fixtures in both modes. It then collects compact and
verbose core reports and exit statuses, uploads the evidence even on failure,
and fails if the modes disagree or the analysis returns a failing status.
It is not a required PR check while the core still has coverage gaps and reports.
No release workflows or branch protections change in this branch.

## Current validation

The VM 0.36 core source runs with the compiler's existing VM 0.35 dependencies.
Both modes report 39 diagnostics and 359 skipped procedures, and exit with status 1.
The reports comprise 12 operation sinks and 27 public-return advisories. They need
triage before classification as MASM defects. The 117 root failures cause another
242 callers to be skipped. Root failures include 46 analysis-size limits and
67 stack/signature inference failures, with four unsupported constructs.

Compact output has 26 lines and verbose output has 15,341. Local evidence is in
`target/masm-advice-lint/evidence/core-taint-compact.txt` and
`target/masm-advice-lint/evidence/core-taint-verbose.txt`.
All eight CLI cases pass in both modes. They cover clean code, sink findings,
grouped returns, and advice passing through declared word and pointer arguments.
They also verify skipped dependencies, an empty child module, and budget exhaustion.
The CLI passes formatting and Clippy with warnings denied. Both scripts pass
ShellCheck, and the manual workflow passes Actionlint. Hosted CI has not run.
