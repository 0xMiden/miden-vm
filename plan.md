# Error Handling Refactor — Status and TODO

This document tracks the current state of the processor error-handling refactor and what remains.
It replaces an older, much longer plan that no longer reflected the code.

## Summary

- Two-tier errors are implemented and used consistently:
  - `OperationError`: context-free, returned by ops; holds runtime data only.
  - `ExecutionError`: user-facing; wraps `OperationError` with source info where available, and
    also represents program-level errors.
- Wrapping happens at boundaries (decoder, slow/fast/parallel executors) via
  `err_ctx!(...)` + `ErrorContext::wrap_op_err`.
- The `no_err_ctx` feature removes error-context overhead in performance builds.

Key files:
- Errors and context: `processor/src/errors.rs`
- Slow path ops: `processor/src/operations/*.rs` (return `Result<_, OperationError>`)
- Slow dispatcher: `processor/src/operations/mod.rs:execute_op`
- Fast dispatcher: `processor/src/processor/operations/mod.rs:execute_sync_op`
- Decoder and boundaries: `processor/src/decoder/mod.rs`, `processor/src/lib.rs`

## Current State

- Error types
  - `ExecutionError` has `OperationError` and `OperationErrorNoContext` variants plus
    program-level variants (e.g., cycle limit, init failure, prover errors).
  - `OperationError` covers validation, arithmetic, stack/flow, dynamic exec, advice, crypto/Fri,
    and wraps subsystem errors (e.g., `MemoryError`, `AceError`).
  - Diagnostic messages and help are declared via `thiserror` + `miette::Diagnostic` derives and
    attributes on variants; there is no separate diagnostic trait in use.

- Wrapping pattern
  - All op implementations are context-free and return `OperationError`.
  - Boundaries create `err_ctx!(program, node, host, [op_idx], clk)` and map `OperationError` to
    `ExecutionError` using `err_ctx.wrap_op_err(err)`.
  - Where source info is unavailable (e.g., external MAST loads), code returns
    `ExecutionError::OperationErrorNoContext` by design. When execution re-enters a boundary with
    source info, `add_error_ctx_to_external_error(...)` upgrades those to
    `ExecutionError::OperationError` when possible.

- Paths covered
  - Slow path: `Process::execute_op` returns `OperationError`; decoder/lib.rs wraps at call sites.
  - Fast/parallel paths: synchronous executor returns `OperationError`; call sites wrap via
    `err_ctx.wrap_op_err`. Some fast paths use `OperationErrorNoContext` intentionally when no
    debug info is present (e.g., external nodes).
  - DYN/DYNCALL: setup errors (e.g., memory read/write, invalid return depth) are reported as
    `OperationError` and wrapped at the DYN/DYNCALL boundary; no specialized `DynCallError` type.

## What Remains

- Audit direct `ExecutionError` construction
  - Keep direct constructors for program-level cases and explicit no-context cases.
  - Ensure operation-level failures at boundaries consistently use `err_ctx.wrap_op_err`.

- External-node error context policy
  - `add_error_ctx_to_external_error(...)` is the current mechanism to upgrade
    `OperationErrorNoContext` when returning from external calls. Confirm this is the intended
    long-term policy and document it briefly in code comments (it already has a docstring).

- Diagnostic polish
  - Spot-check `OperationError`/`MemoryError` variants for helpful `#[diagnostic(help(...))]` and
    align wording/tone. Add missing help annotations as needed.

- Developer docs
  - Add a short “Error Handling” section to the processor crate README or docs pointing to the
    boundary pattern, the `err_ctx!` macro, and `no_err_ctx` feature.

## Notes on Removed/Outdated Items

- Removed from the plan: `DynCallError` enum and `OperationDiagnostic` trait. The code uses
  `OperationError` variants with `miette::Diagnostic` attributes instead, which keeps the system
  simple and consistent.
- Old references to `execute_op_with_error_ctx` were replaced by `execute_op` returning
  `OperationError`; boundaries own wrapping via `wrap_op_err`.

## How to Verify

- Slow path focus: `make test-processor test='-E "not test(#*proptest)"'`
- Fast path focus: `make test-fast`
- End-to-end: `make test`

To debug error spans interactively, run with `RUST_BACKTRACE=1` and use a program compiled with
debug info so `err_ctx!(...)` can attach source spans.

