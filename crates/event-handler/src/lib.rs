//! Processor-independent native event and trace handlers for Miden VM.
//!
//! [`EventContext`] exposes a stable, read-only capability interface. Event handlers return
//! declarative [`AdviceMutation`] values; the processor validates the whole batch before applying
//! any mutation. Trace handlers use the same context but cannot return mutations.
//! Memory addresses enter the interface as `u64`; [`EventContext`] validates the VM's `u32`
//! address space and derives value, word, and allocating slice reads from one strict buffer read.
//!
//! This crate depends on `miden-core`, not `miden-processor`. The Wasm `miden:event/v1` ABI is a
//! separate contract and is not changed by this interface.
//!
//! # Migration from `miden-processor`
//!
//! In v0.31, `miden-processor` retains a small re-export facade, aliases its old `ProcessorState`
//! to [`EventContext`], and retains deprecated legacy read methods. This compatibility surface is
//! scheduled for removal in v0.32. Three concrete details are not reproduced: the processor's
//! concrete advice-provider type, unrestricted `ExecutionOptions` access, and the old
//! `miden_air::trace::RowIndex` return type of `clock()`.

#![no_std]

extern crate alloc;

mod compatibility;
mod context;
mod handlers;
mod mutations;

#[allow(deprecated)]
pub use compatibility::AdviceProviderView;
pub use context::{
    AdviceReadError, BuiltinEventContext, BuiltinEventContextProvider, EventContext,
    EventContextProvider, Invocation, InvocationKind, MemoryReadError, MerkleReadError,
};
pub use handlers::{
    EventError, EventHandler, NoopEventHandler, NoopTraceHandler, TraceError, TraceHandler,
};
pub use miden_core::{ContextId, Felt, MemoryAddress, Word};
pub use mutations::AdviceMutation;
