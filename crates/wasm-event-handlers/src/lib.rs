//! Host-side runner for Wasm-compiled Miden VM event handlers.
//!
//! A Wasm event handler is an untrusted core Wasm module that ships inside a Miden package. This
//! crate loads such a module, validates it, and adapts each declared handler to the processor's
//! [`EventHandler`](miden_event_handler::EventHandler) trait, so that the existing host and
//! registry machinery runs it like a native handler.
//!
//! # Model
//!
//! - [`WasmHandlerModule::new`] parses and validates the module once: only `miden:event/v1` imports
//!   are allowed, the module must not have a start section, every manifest export must exist with
//!   signature `() -> ()`, and the manifest must not contain duplicate or reserved event names.
//! - [`WasmHandlerModule::handlers`] returns one [`WasmEventHandler`] per manifest entry, ready for
//!   registration in a host (for example through
//!   [`DefaultHost::load_library`](miden_processor::DefaultHost)).
//! - Each event call runs in a fresh store and instance: handlers are stateless across calls. The
//!   call is metered with fuel, the linear memory is capped, and the total size of buffered advice
//!   mutations is capped. See [`WasmHandlerLimits`].
//! - The handler buffers mutations through host calls. The host applies them to the advice provider
//!   only when the handler returns without a trap; a trap or a `fail` call discards them all.
//!
//! The ABI contract (data types, host functions, failure rules) lives in the
//! `miden-event-handler-abi` crate.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
mod host;
mod module;
mod package;

// CONSTANTS
// ================================================================================================

/// The rustflags a guest-crate build must pin so the module it produces passes the loader's
/// non-SIMD policy.
///
/// The handler runner executes a deterministic, non-SIMD instruction set, so a module that holds
/// `simd128` instructions is refused at load. A toolchain or a `.cargo/config.toml` can turn
/// `simd128` on for `wasm32-unknown-unknown`, so a toolchain that builds guest crates sets this
/// string as `RUSTFLAGS` and removes `CARGO_ENCODED_RUSTFLAGS`, which would replace it.
pub const GUEST_RUSTFLAGS: &str = "-C target-feature=-simd128";

pub use error::{WasmHandlerLoadError, WasmHandlerRunError};
pub use module::{WasmEventHandler, WasmHandlerLimits, WasmHandlerModule};
#[doc(hidden)]
pub use package::{fuzz_module_statics, fuzz_walk_sections, test_append_manifest_section};
pub use package::{
    handlers_from_package, host_library_from_package, manifest_from_module, section_from_module,
};
