# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Migration and breaking changes

- Upgrade the Miden VM crates from 0.36.2 to 1.0.0-rc.0. Rust integrations exchanging VM, package, or debug-info types with the debugger must use matching dependencies. Recompile packages with the new toolchain, and replace `hperm` operation breakpoints with `compress`.
- Replay snapshots use format version 4 and reject older snapshots. Snapshot export rejects custom execution or verification precompile limits until the VM exposes a complete serialization API. `ReplaySnapshot::to_bytes` and `write_into` now return `Result`, and `ReplaySnapshot` no longer implements the infallible `Serializable` trait. `write_to_file` reports unsupported policies as `InvalidInput` before modifying the file.

### Fixed

- Keep DAP source breakpoints pending until dynamically loaded package debug information is available, then verify them with stable breakpoint IDs. Reconsider relocated bindings when another package contributes executable lines for the same source. Source-line validation also reads matching local files when the execution host does not provide source text.

## [0.19.0]

### Added

- Rust integrations can use `replay_call_trace` to build a call tree from a `ReplaySnapshot`, including call timing, arguments, and returned field elements when debug information is available. Calls must have frame-start/frame-end markers. Failed executions return a partial trace alongside the error; missing metadata leaves call details unknown rather than attributing them to a later callee.
- `RecordingHost` lets Rust integrations record a host's advice mutations and loaded code for replay.
- Rust scripts can inspect individual logical stack frames with `ScriptDebugger::frame_at`.

### Changed

- Debugger and DAP stack traces recover callers and source inline frames across nested calls, recursion, and package boundaries. Inferred frames are labeled separately from inline frames, and event-based frames remain available when source metadata is missing.

### Fixed

- Function breakpoints now match demangled Rust source names as well as mangled linkage names in local and DAP sessions.

### Migration and breaking changes

- The debugger now uses Miden VM 0.36.2 instead of 0.35.0. Rust integrations exchanging VM, package, or debug-info types with the debugger must use matching 0.36.2 dependencies.
- REPL/TUI variable commands now inspect the selected physical invocation, including suspended and recursive callers, instead of using the executing frame's values. Select the executing physical frame for its current values. Inline frames have no separate locals or lexical scopes. Unreadable values now display as `<unavailable>` instead of a storage-location expression.
- Flamegraphs now attribute cycles to recovered source stacks, including uninstrumented callers and `[inferred]`/`[inlined]` frames. Tools comparing folded stacks must account for the additional frames and changed labels; VM cycle accounting is unchanged.
- Local `finish` and DAP step-out now follow the current invocation through recursive and uninstrumented calls. With source metadata, they stop at a caller assembly operation after return; frame events remain the fallback when metadata is unavailable. Scripts relying on the previous stop cycle must account for this. A pending local return breakpoint remains tied to its original invocation when another breakpoint interrupts execution.
- DAP frame IDs and variable references now expire on resume or restart; fetch `stackTrace` and `scopes` again after each stop. Rust clients must replace the removed `SCOPE_STACK` and `SCOPE_MEMORY` constants with scope references returned by `DapClient::scopes(frame_id)`. Operand Stack and Memory scopes are available only for the executing physical frame; inspect callers through their Local Variables and Other Locals scopes or `evaluate` with `frameId`. Other Locals contains compiler-generated and source-hidden variables.
- Python `miden.thread.frames()` now returns all logical frames in innermost-first order. Frames returned by it and `miden.thread.selected_frame()` are snapshots that retain their values after execution resumes; fetch them again after each stop for current values. `miden.frame` and breakpoint callback frames still inspect the executing invocation.
- `LogicalStackFrame::physical_index()` now returns `Option<usize>` instead of `usize`. Rust callers must handle `None` for recovered source frames without an event-frame index.
- DAP, recording, and diagnostic execution now invoke the wrapped host's trace handlers and propagate their errors. Integrations using trace handlers must account for their side effects and for execution failing when a handler returns an error.
- With the DAP crate's `integration_testing` feature, generated `Source` and `ExceptionDetails` fixtures now leave `sources` and `inner_exception` unset to prevent stack overflows. Tests needing nested sources or exceptions must populate those fields explicitly.

## [0.18.0]

### Migration and breaking changes

- Switch to the Miden VM v0.35;

## [0.17.0]

### Added

- Rust integrations can bind a DAP listener before starting execution with `DapExecutor::bind_listener` and `DapExecutor::execute_on_listener`, including discovering an automatically assigned port before accepting a client.
- Rust DAP clients can use an established TCP connection with `DapClient::from_stream`, preserving socket options and timeouts configured before the handshake.

### Changed

- The DAP server log now reports the actual listening address, including the assigned port when started with port `0`.

### Migration and breaking changes

- The debugger now uses Miden VM 0.34.0 instead of 0.33.0. Rust integrations exchanging VM, package, or debug-info types with the debugger must use matching 0.34.0 dependencies.
- Standalone DAP mode now binds its listening socket before loading the program and its dependencies. The port is reserved during loading, and invalid addresses or occupied ports are reported before package-loading errors.

## [0.16.0]

### Changed

- Switch to the Miden VM v0.33;

### Fixed

- Unqualified function breakpoints now consistently match fully-qualified procedure-name suffixes in local and DAP sessions ([#88](https://github.com/0xMiden/miden-debug/issues/88)).

## [0.15.0]

### Added

- Incompatible package and debug-info format errors now explain how to select the producing toolchain with `miden +<toolchain> debug <FILE>`.

### Migration and breaking changes

- Debugger inputs and linked libraries must now be compiled `.masp` packages, including when starting a DAP server or generating a flamegraph. Compile sources and projects with `midenc` or `miden build` first, and replace source paths, project directories, and `-l masm=...` arguments with compiled package paths.
- Rust scripting integrations must replace `ScriptDebugger::from_masm_source` with `ScriptDebugger::from_config`, supplying a compiled package through `DebuggerConfig.input`. Calls to `LinkLibrary::load` must drop the registry argument and pass only the search paths.
- The debugger now uses Miden VM 0.32.1 instead of 0.30.0. Rust integrations exchanging VM, package, or debug-info types with the debugger must use matching 0.32.1 dependencies.
- Builds with default features disabled must enable `std` for filesystem package loading, CLI parsers, and automatic profiling report output. The engine retains in-memory package decoding, variable and memory inspection, input parsing, and replay serialization without `std`; enabling `dap` or `proptest` now also enables `std`.
- `InputFile` is now a struct: replace `InputFile::Real(path)` with `InputFile::from_path(path)` and `InputFile::Stdin(bytes)` with `InputFile::new("stdin://", Some(bytes))`. Use `uri()` or `to_path()` instead of matching enum variants, and handle the `Result` returned by `bytes()` instead of an `Option`.
- Rust callers constructing `BreakpointType::File`, `Line`, or `Called` must replace `glob::Pattern` with `miden_debug_engine::glob::Glob::new(pattern)?.compile_matcher()`. Existing breakpoint patterns also need checking: URI schemes are stripped before matching, braces denote alternatives, and backslashes escape characters on Unix. Use `[{]` and `[}]` to match literal braces.
- `CallStack::new` now takes an event map wrapped in `Arc<miden_utils_sync::RwLock<_>>` instead of `Arc<std::sync::Mutex<_>>`; update callers and their event-map locking accordingly.
- Custom profiling instruments must change `Instrument::write_report_to` to accept `&mut dyn profiling::OutputWriter` and return `profiling::OutputResult<()>`. The `path` fields in `ReplaySnapshotWrite` and `ReplaySnapshotWriteError` now use `debug_types::Uri` instead of `PathBuf`; convert paths when constructing or reading these records.
- `LinkLibrary.linkage` no longer accepts `miden_assembly::Linkage`, it uses its own type, but is currently unused, and exists only as a placeholder for if/when linkage becomes relevant to the debugger.
- Function breakpoints now stop after entry-block variable declarations have been recorded, so entry variables are available for inspection in local and DAP sessions. Scripts relying on the previous stop cycle must account for the later stop. Rust integrations using `DebugExecutor::procedure_has_debug_vars` must adapt to `should_wait_for_entry_variables`, which checks pending entry declarations rather than whether a procedure has any debug variables ([#89](https://github.com/0xMiden/miden-debug/issues/89)).
- After successful termination, the REPL and TUI no longer display stale variables, and scripting variable queries return an empty list. Inspect variables at a breakpoint before completion; final stack outputs and typed results remain available, as do variables after execution errors ([#90](https://github.com/0xMiden/miden-debug/issues/90)).
- Package loading now validates debug information immediately and rejects malformed or incompatible debug-info sections. Rebuild affected artifacts, or select their producing toolchain for format mismatches.

## [0.14.0]

A trivial version bump to unify the versions of the various debugger crates. You can find the legacy changelog entries in [CHANGELOG-legacy.md].

### Changed

- The `miden-debug-engine` and `miden-debug-dap` crates now release at the same version as `miden-debug` itself.
