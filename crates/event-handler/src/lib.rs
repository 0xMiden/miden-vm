//! Portable event handling for Miden VM, with `no_std + alloc` support.
//!
//! One [`EventHandler`] receives both regular events and optional traces. [`EventContext`] is a
//! copyable view of pre-callback VM state: stack position zero is the first payload element, and
//! memory reads address the current or root context. Pending advice is invisible to these reads.
//!
//! Handlers record typed advice through [`AdviceRecorder`]. The execution engine owns the
//! [`AdviceBatch`], discards it on callback error or cancellation, and validates the complete batch
//! against live state and resource limits before applying anything. Successful trace callbacks must
//! leave it empty. Host-owned side effects are outside this advice guarantee.
//!
//! This crate depends on `miden-core` and never on `miden-processor`. The public provider and batch
//! construction/consumption interfaces serve execution engines; handlers need only the context and
//! recorder.

#![no_std]

extern crate alloc;

mod advice;
mod context;
mod errors;
mod handlers;

pub use advice::{AdviceBatch, AdviceRecorder};
pub use context::{EventContext, EventContextProvider, Invocation, InvocationKind, MemoryReadMode};
pub use errors::EventContextError;
pub use handlers::{EventError, EventHandler, NoopHandler, UnsupportedInvocationKind};
pub use miden_core::{Felt, MemoryAddress, Word};

/// Maximum input size for one bundled native Keccak invocation (1 MiB).
pub const MAX_KECCAK_INPUT_BYTES: usize = 1 << 20;

/// Maximum serialized plaintext size accepted by bundled native AEAD decryption (16 MiB).
/// Excludes padding and authentication tag; the processor separately enforces its advice budget.
pub const MAX_AEAD_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
