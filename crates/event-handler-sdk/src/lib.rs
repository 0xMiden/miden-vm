//! Guest SDK for writing Wasm-compiled Miden VM event handlers in Rust.
//!
//! Compile handler crates for `wasm32-unknown-unknown` with `crate-type = ["cdylib"]`. Declare a
//! handler with the [`miden_event_handler`] attribute:
//!
//! ```rust,ignore
//! use miden_event_handler_sdk as sdk;
//! use sdk::Felt;
//!
//! #[sdk::miden_event_handler("myapp::double")]
//! fn double() {
//!     let value = sdk::stack_get(1);
//!     sdk::adv_stack_extend(&mut [value * Felt::from_u32(2)]);
//! }
//! ```
//!
//! The macro exports the handler under the event name and writes a manifest record into the
//! `miden:event-manifest` custom section, so package tooling derives the `(event, export)`
//! manifest from the compiled module.
//!
//! # Value types
//!
//! Handlers work with [`Felt`], [`Word`] and [`MerkleNode`], which this crate re-exports from the
//! [`abi`] crate; a handler crate needs no direct `miden-field` dependency. These types are also
//! the wire types, so there is no conversion layer: the wrappers only canonicalize the field
//! elements they send. See the wire-format section of the [`abi`] crate documentation.
//!
//! The wrapper functions in this crate talk to the host through the raw imports declared in the
//! `miden-event-handler-abi` crate. Conditions a correct handler cannot meet (for example an
//! unknown status code) end the handler through the `fail` wrapper.
//!
//! # Features for the final handler crate
//!
//! A `no_std` handler crate needs a panic handler and a global allocator. This crate provides
//! both behind features; enable them in the final crate only, so libraries stay free to choose:
//!
//! - `panic-handler` forwards the panic message to the host through `fail`;
//! - `bump-allocator` installs a bump allocator over the guest's own memory.

#![no_std]

pub use miden_event_handler_abi as abi;
pub use miden_event_handler_abi::{Felt, MerkleNode, Word};
pub use miden_event_handler_macros::miden_event_handler;

#[cfg(all(target_arch = "wasm32", feature = "bump-allocator"))]
mod allocator;
#[cfg(all(target_arch = "wasm32", feature = "panic-handler"))]
mod panic_handler;
#[cfg(target_arch = "wasm32")]
mod wrappers;
#[cfg(target_arch = "wasm32")]
pub use wrappers::*;
