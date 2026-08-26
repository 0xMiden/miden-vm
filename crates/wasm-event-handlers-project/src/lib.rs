//! Project assembler plugin that embeds Wasm event handlers into an assembled Miden package.
//!
//! The Miden project assembler holds no knowledge of event handlers. This crate supplies that
//! knowledge as a [`PackagePostProcessor`](miden_assembly::PackagePostProcessor): a caller
//! registers [`WasmEventHandlerProcessor`] with
//! [`ProjectAssembler::with_package_post_processor`](miden_assembly::ProjectAssembler::with_package_post_processor),
//! and every package the assembler builds from the project sources then carries the
//! `event_handlers` section the project manifest declares.
//!
//! # Manifest schema
//!
//! The processor reads one table from the project manifest:
//!
//! ```toml
//! [package.metadata.wasm-event-handlers]
//! crate = "handlers"          # a Rust guest crate directory, XOR:
//! module = "handlers.wasm"    # a prebuilt core-Wasm module
//! ```
//!
//! Both paths resolve against the directory of the `miden-project.toml` file. A package declares
//! at most one handler module, and the section attaches to every target the package assembles.
//! When the table is absent the processor changes nothing.
//!
//! # Toolchain
//!
//! The `crate` key needs `cargo` and the `wasm32-unknown-unknown` target. The processor builds the
//! guest crate once per project assembly, whatever number of targets the project holds.

mod config;
mod guest;
mod processor;

pub use self::processor::WasmEventHandlerProcessor;
