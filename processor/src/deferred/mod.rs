//! Processor-side state and event handlers for the deferred-DAG subsystem.
//!
//! The shared data model (tags, nodes, payloads, witness) lives in `miden-core::deferred` and is
//! re-exported here for convenience. This module additionally owns the in-memory state mutated
//! by VM event handlers, the per-value-type handler trait, the registry, and the three generic
//! system event handlers intercepted by [`crate::DefaultHost`].

mod events;
mod handlers;
mod registry;
mod state;
mod transaction;
mod witness;

pub use miden_core::deferred::{
    Assertion, DeferredError, DeferredTag, DeferredWitness, Digest, FIELD, FIELD_0, Node, Payload,
    TagKind, ValueType, hash_node,
};

pub use events::{
    EVENT_ASSERT_EQ, EVENT_REGISTER_LEAF, EVENT_REGISTER_OP, assert_eq, binary_op_payload,
    register_node,
};
pub use handlers::{DeferredTypeHandler, Field0Handler};
pub use registry::TypeHandlerRegistry;
pub use state::DeferredState;
pub use transaction::{DeferredMutation, HandlerTransaction, VmMutation};
pub use witness::extract_witness;
