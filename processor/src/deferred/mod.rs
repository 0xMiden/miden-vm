// Public surface is wired into the host registry in commit 5; until then the types are
// exercised only by unit tests.
#![allow(unused)]

//! Processor-side state for the deferred-DAG subsystem.
//!
//! The shared data model (tags, nodes, payloads, witness) lives in `miden-core::deferred`. This
//! module owns the in-memory state mutated by event handlers during VM execution: the node map,
//! the list of equality assertions, the per-value-type handler trait, and the registry that
//! routes tags to handlers. The three generic system event handlers are added in a later commit.

mod events;
mod handlers;
mod registry;
mod state;
mod transaction;

pub use events::{
    EVENT_ASSERT_EQ, EVENT_REGISTER_LEAF, EVENT_REGISTER_OP, assert_eq, binary_op_payload,
    register_node,
};
pub use handlers::{DeferredTypeHandler, Field0Handler};
pub use registry::TypeHandlerRegistry;
pub use state::DeferredState;
pub use transaction::{DeferredMutation, HandlerTransaction, VmMutation};
