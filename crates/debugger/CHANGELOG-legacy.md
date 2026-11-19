# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.10.3...miden-debug-v0.11.0) - 2026-08-29

### Added

- *(debug)* use canonical ABI entrypoint codecs
- *(debug)* pretty-print ABI typed variables

### Fixed

- show TUI program errors in a popup ([#110](https://github.com/0xMiden/miden-debug/pull/110)) ([#119](https://github.com/0xMiden/miden-debug/pull/119))
- *(debug)* resolve typed byte-addressed values
- *(debug)* use canonical ABI type metadata

### Other

- update pyo3 to v0.29
- verify Cargo feature combinations
- merge next into feat/contract-benchmark
- reset stack selection after remote reload
- clear source for unresolved frame selection
- render physical frame procedure directly
- track exec procedure changes in physical frames
- print selected postmortem frame
- restore typed results after continue
- synchronize inline frames on control cycles
- merge next into feat/inline-calls
- fix ABI value reporting regressions
- *(debug)* cover ABI type pretty-printing in lit
- migrate to miden-vm 0.30.0

### Added

- Generate flamegraphs from replay snapshots with `miden-debug flamegraph --replay <FILE>`, or
  programmatically with `FlamegraphProfile::collect_replay`.


## [0.10.3](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.10.2...miden-debug-v0.10.3) - 2026-08-27

### Other

- enable env_logger under std feature

## [0.10.2](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.10.1...miden-debug-v0.10.2) - 2026-08-27

### Other

- ensure nightly toolchain is installed

## [0.10.1](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.10.0...miden-debug-v0.10.1) - 2026-08-27

### Other

- don't require tui feature unless needed
- Merge pull request #102 from 0xMiden/feat/python-scripting-tests
- simplify binary target tasks
- *(repl)* add Python scripting lit coverage

## [0.10.0](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.9.2...miden-debug-v0.10.0) - 2026-08-07

### Other

- migrate to vm 0.29

## [0.9.2](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.9.1...miden-debug-v0.9.2) - 2026-07-27

### Other

- prepare for next release
- migrate to miden-vm v0.25.8 ([#106](https://github.com/0xMiden/miden-debug/pull/106))

## [0.9.1](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.9.0...miden-debug-v0.9.1) - 2026-07-20

### Other

- update Cargo.lock dependencies

## [0.9.0](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.8.1...miden-debug-v0.9.0) - 2026-07-13

### Added

- *(prof)* collect and print op histogram
- *(repl)* add Python scripting support
- auto resolve package dependencies ([#92](https://github.com/0xMiden/miden-debug/pull/92))
- add test harness ([#79](https://github.com/0xMiden/miden-debug/pull/79))

### Other

- 0.9.0
- support externally-defined instruments
- configure `reports_dir` where all reports are written
- migrate to miden-vm v0.25
- Merge branch 'next' into fix/record
- Merge branch 'next' into feature/python-scripting
- run `format-rust` on nightly ([#83](https://github.com/0xMiden/miden-debug/pull/83))

## [0.8.1](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.8.0...miden-debug-v0.8.1) - 2026-05-26

### Fixed

- resolve relative source paths from debugger

### Other

- update deps

## [0.8.0](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.7.1...miden-debug-v0.8.0) - 2026-05-20

### Added

- *(dap)* support standalone debug adapter launch
- extend memory queries to DebugExecutor
- re-export crates whose types appear in our public api

### Fixed

- fix clippy
- *(dap)* track source variables accurately

### Other

- 0.8.0
- merge next into feature/flamegraph
- address PR comments
- bump miden-vm to 0.23 / miden-crypto to 0.25
- simplify opcode breakpoints
- describe how to use debugger programmatically

## [0.7.1](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.7.0...miden-debug-v0.7.1) - 2026-05-06

### Fixed

- remove miden-tx/miden-protocol dependencies
- *(repl)* fix rustfmt
- *(repl)* make --repl build cleanly and document it as opt-in

### Other

- merge main into next
- build docs in CI
- add user-facing debugger documentation

## [0.7.0](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.6.1...miden-debug-v0.7.0) - 2026-05-01

### Added

- implement more ergonomic testing primitives, update tests
- enable `println` via trace
- *(ui)* add :proc / :p / :where command to show current procedure
- add REPL mode as alternative to TUI debugger
- add vars command to display debug variables
- record log targets in DebugLogger

### Fixed

- use released miden vm debug APIs
- *(ui)* avoid startup trace capture hang
- resolve source variables from frame base
- *(ui)* display live procedure in disassembly and stacktrace
- *(ui)* procedure breakpoints match exec'd procedures
- cleanup
- use human-readable breakpoint display in REPL
- FrameBase resolution
- adapt debug variable tracking to v0.22 API

### Other

- fix formatting
- update dependencies
- expand on integration tests README
- rename MAX_CAPTURED_LOGS to HISTORY_SIZE to more accurately describe its semantics
- make `DebugLogger::install` propagate `Err` instead of panic
- remove test of log plumbing
- make `println` tests integration tests
- output `println` content to `DebugLogger`
- increase max number of entries in DebugLogger
- add helpers to use DebugLogger in tests
- fix formatting after rebase
- apply rustfmt formatting

## [0.6.1](https://github.com/0xMiden/miden-debug/compare/miden-debug-v0.6.0...miden-debug-v0.6.1) - 2026-04-08

### Added

- add transaction DAP debugging support

### Fixed

- VM v0.22.1 compatibility
- make nextest pickup tests
- align deps with miden-client beta base
- support function/pattern breakpoints in DAP server
- resolve PR review comments
- resolve hostname in DAP listen address
- handle edit-and-continue and terminate-and-reconnect
- event-driven remote UI refresh via custom miden/uiState DAP event
- add --no-tests=pass
- fix clippy
- pin protocol rev and align debugger DAP support
- resolve remote refresh, crate split, reload, and review follow-up
- address comments
- adopt to latest changes in protocol

### Other

- Merge pull request #49 from 0xMiden/next
- switch to crates.io deps for protocol and VM
- Use advice, memory and final_pc_transcript from processor
- Use direct transaction program executors

## [0.6.0](https://github.com/0xMiden/miden-debug/compare/v0.5.0...v0.6.0) - 2026-03-25

### Fixed

- more LE order fixes, add tests
- register event handlers with VM
- LE order in the `read_from_rust_memory_in_context` and

### Other

- Migrate miden-debug to VM 0.22
- install nextest using dedicated action
- fix lint warnings on 1.94 toolchain
- bump toolchain to 1.94
- remove `miden-crypto` dependency

## [0.5.0](https://github.com/0xMiden/miden-debug/compare/v0.4.7...v0.5.0) - 2026-03-06

### Added

- migrate to miden-vm v0.21 FastProcessor API

### Fixed

- fix rust fmt
- fix felts endianess
- populate StackOutputs on program completion
- use module path for Continuation import

### Other

- Merge pull request #36 from 0xMiden/next
- fix felt accessor in wasm stack test
- use crates.io miden-vm 0.21.1 deps
- use miden-vm v0.21.1 git deps for CI
- Use self.processor.memory
- use re-exported Continuation and Memory

## [0.4.7](https://github.com/0xMiden/miden-debug/compare/v0.4.6...v0.4.7) - 2026-03-05

### Added

- add fn `push_wasm_ty_to_operand_stack`

### Other

- Merge branch 'next' into main

### Added

- Add function `push_wasm_ty_to_operand_stack`

## [0.4.6](https://github.com/0xMiden/miden-debug/compare/v0.4.5...v0.4.6) - 2026-01-31

### Other

- Merge pull request #26 from 0xMiden/next

## [0.4.5](https://github.com/0xMiden/miden-debug/compare/v0.4.4...v0.4.5) - 2026-01-30

### Other

- load all libs from sysroot
- load base as well
- load libraries BEFORE resolving package dependencies

## [0.4.4](https://github.com/0xMiden/miden-debug/compare/v0.4.3...v0.4.4) - 2025-12-31

### Other

- ensure release builds use correct profile

## [0.4.3](https://github.com/0xMiden/miden-debug/compare/v0.4.2...v0.4.3) - 2025-12-31

### Other

- update deps
- Merge branch 'next' into main
- *(release)* use separate runner for macos artifact builds
- *(release)* generate build attestations
- release v0.4.2


## [0.4.2](https://github.com/0xMiden/miden-debug/compare/v0.4.1...v0.4.2) - 2025-12-31

### Other

- update Cargo.lock dependencies
- Search through context for a valid location

## [0.4.1](https://github.com/0xMiden/compiler/compare/midenc-debug-v0.4.0...midenc-debug-v0.4.1) - 2025-09-03

### Other

- Add 128-bit wide arithmetic support to the compiler.

## [0.4.0](https://github.com/0xMiden/compiler/compare/midenc-debug-v0.1.5...midenc-debug-v0.4.0) - 2025-08-15

### Fixed

- handle empty iterator returned by `into_remainder()`
- remove incorrect(order) `FromMidenRepr::from_words()` for `[Felt; 4]`

### Other

- update Rust toolchain nightly-2025-07-20 (1.90.0-nightly)
- add `test_hmerge` integration test for `hmerge` Rust API

## [0.1.5](https://github.com/0xMiden/compiler/compare/midenc-debug-v0.1.0...midenc-debug-v0.1.5) - 2025-07-01

### Fixed

- invoke `init` in the lifting function prologue, load the advice

### Other

- add format for entrypoint option

## [0.0.8](https://github.com/0xMiden/compiler/compare/midenc-debug-v0.0.7...midenc-debug-v0.0.8) - 2025-04-24

### Added
- *(types)* clean up hir-type for use outside the compiler
- *(codegen)* migrate to element-addressable vm
- add custom dependencies to `Executor` resolver,
- *(cargo-miden)* support building Wasm component from a Cargo project

### Fixed
- *(codegen)* incomplete global/data segment lowering

### Other
- *(codegen)* implement initial tests for load_sw/load_dw intrinsics
- update rust toolchain, clean up deps
- enrich Miden package loading error with the file path
- rename hir2 crates
- disable compilation of old hir crates, clean up deps
- switch uses of hir crates to hir2
- update to the latest `miden-mast-package` (renamed from
- update the Miden VM with updated `miden-package` crate
- update rust toolchain to 1-16 nightly @ 1.86.0
- Update midenc-debug/src/exec/executor.rs
- fix doc test false positive
- switch to `Package` without rodata,
- [**breaking**] move `Package` to `miden-package` in the VM repo

## [0.0.7](https://github.com/0xPolygonMiden/compiler/compare/midenc-debug-v0.0.6...midenc-debug-v0.0.7) - 2024-09-17

### Other
- update rust toolchain

## [0.0.6](https://github.com/0xpolygonmiden/compiler/compare/midenc-debug-v0.0.5...midenc-debug-v0.0.6) - 2024-09-06

### Added
- implement 'midenc run' command

### Other
- revisit/update documentation and guides
- switch all crates to a single workspace version (0.0.5)

## [0.0.2](https://github.com/0xPolygonMiden/compiler/compare/midenc-debug-v0.0.1...midenc-debug-v0.0.2) - 2024-08-30

### Fixed
- *(codegen)* broken return via pointer transformation
- *(debugger)* infinite loop in breakpoint id computation

### Other
- fix clippy warnings in tests

## [0.0.1](https://github.com/0xPolygonMiden/compiler/compare/midenc-debug-v0.0.0...midenc-debug-v0.0.1) - 2024-08-16

### Other
- set `midenc-debug` version to `0.0.0` to be in sync with crates.io
- clean up naming in midenc-debug
- rename midenc-runner to midenc-debug
- fix typos ([#243](https://github.com/0xPolygonMiden/compiler/pull/243))
- a few minor improvements
- set up mdbook deploy
- add guides for compiling rust->masm
- add mdbook skeleton
- provide some initial usage instructions
- Initial commit
