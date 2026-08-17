//! Guest SDK for writing Wasm-compiled Miden VM event handlers in Rust.
//!
//! Compile handler crates for `wasm32-unknown-unknown` with `crate-type = ["cdylib"]`. Declare a
//! handler with the [`miden_event_handler`] attribute:
//!
//! ```rust,ignore
//! use miden_event_handler_sdk as sdk;
//! use sdk::abi::RawFelt;
//!
//! #[sdk::miden_event_handler("myapp::double")]
//! fn double() {
//!     let value = sdk::stack_get(1);
//!     sdk::adv_stack_extend(&[RawFelt::new(value.as_u64() * 2)]);
//! }
//! ```
//!
//! The macro exports the handler under the event name and writes a manifest record into the
//! `miden:event-manifest` custom section, so package tooling derives the `(event, export)`
//! manifest from the compiled module.
//!
//! The wrapper functions in this crate talk to the host through the raw imports declared in the
//! `miden-event-handler-abi` crate. Conditions a correct handler cannot meet (for example an
//! unknown status code) end the handler through [`fail`]. Enable the `panic-handler` feature in
//! the final handler crate to forward panic messages to the host the same way.

#![no_std]

pub use miden_event_handler_abi as abi;
pub use miden_event_handler_macros::miden_event_handler;

#[cfg(all(target_arch = "wasm32", feature = "panic-handler"))]
mod panic_handler;
#[cfg(target_arch = "wasm32")]
mod wrappers;
#[cfg(target_arch = "wasm32")]
pub use wrappers::*;
