//! Project assembler plugins that embed Wasm event handlers into an assembled Miden package.
//!
//! The Miden project assembler holds no knowledge of event handlers. This crate supplies that
//! knowledge as a [`PackagePostProcessor`](miden_assembly::PackagePostProcessor): a caller
//! registers one of the two processors with
//! [`ProjectAssembler::with_package_post_processor`](miden_assembly::ProjectAssembler::with_package_post_processor),
//! and every package of the project under assembly (its root target and its required
//! libraries, whatever the target type — never a source dependency) then carries the
//! `event_handlers` section the project manifest declares.
//!
//! Which of the two a caller registers decides whether assembly may run native code.
//! [`WasmEventHandlerProcessor`] serves the `module` key only — it reads a prebuilt module, and a
//! manifest that declares `crate` fails the build — so registering it never executes code from the
//! assembled project. [`WasmEventHandlerCargoBuildProcessor`] serves both keys, and building a
//! guest crate runs `cargo build`, and with it the build scripts and procedural macros of that
//! source, with the permissions of the assembler process; register it only for source that is
//! trusted, such as a local compiler building the developer's own project.
//!
//! # Manifest schema
//!
//! The processors read one table from the project manifest:
//!
//! ```toml
//! [package.metadata.midenc.event-handlers]
//! crate = "handlers"          # a Rust guest crate directory, XOR:
//! module = "handlers.wasm"    # a prebuilt core-Wasm module
//! ```
//!
//! Both paths resolve against the directory of the `miden-project.toml` file. A package declares
//! at most one handler module, and the section attaches to every target the package assembles.
//! When the table is absent a processor changes nothing.
//!
//! # Toolchain
//!
//! The `crate` key needs `cargo` and the `wasm32-unknown-unknown` target, and only
//! [`WasmEventHandlerCargoBuildProcessor`] serves it. That processor runs the build once per
//! assembled package, and the builds of one project assembly run one at a time; cargo is
//! incremental, so every build after the first one does no work until the guest crate changes.
//!
//! The build pins [`GUEST_RUSTFLAGS`](miden_wasm_event_handlers::GUEST_RUSTFLAGS) through
//! `RUSTFLAGS`, so the module is the same whatever the environment of the caller holds. By cargo
//! precedence `RUSTFLAGS` replaces the `[target.*] rustflags` of the guest crate's own
//! `.cargo/config.toml`, so a guest crate must not depend on flags it sets there.
//!
//! # Validation
//!
//! The derived section is checked against the default
//! [`WasmHandlerLimits`](miden_wasm_event_handlers::WasmHandlerLimits) at build time, so a
//! forbidden import, a SIMD instruction, a start section, a bad export, or an over-budget
//! instantiation fails the build instead of every host that later loads the package. Limits are
//! host policy, so a host may still run stricter ones.
//!
//! # Memoization
//!
//! One project assembles several targets, and a processor runs once per assembled package. The
//! module bytes are produced on every run — a file read, or a `cargo` build that is a fast no-op
//! when the guest crate did not change — and only the derivation is memoized, keyed by those
//! bytes. An edited source therefore publishes its new section instead of the previous one, and a
//! failure is never memoized, so a fixed source builds on the next run.
//!
//! # One package per host
//!
//! Every package of a project carries the same, full handler set, so a host registers the
//! handlers of ONE package of a project. A host that loads the handlers of a second package of
//! the same project fails with a duplicate-handler error, because the two packages declare the
//! same events. The failure is deliberate: a silent second registration would hide which package
//! answers an event.

mod config;
mod guest;
mod module;
mod processor;

pub use self::processor::{WasmEventHandlerCargoBuildProcessor, WasmEventHandlerProcessor};
