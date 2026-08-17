//! Host-side runner for Wasm-compiled Miden VM event handlers.
//!
//! A Wasm event handler is an untrusted core Wasm module that ships inside a Miden package. This
//! crate loads such a module, validates it, and adapts each declared handler to the processor's
//! [`EventHandler`](miden_processor::event::EventHandler) trait, so that the existing host and
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

pub use error::WasmHandlerLoadError;
pub use module::{WasmEventHandler, WasmHandlerLimits, WasmHandlerModule};
