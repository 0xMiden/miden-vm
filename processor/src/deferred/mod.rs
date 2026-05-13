//! Processor-side state and event handlers for the deferred-DAG subsystem.
//!
//! The shared data model (tags, nodes, payloads, witness) lives in `miden-core::deferred` and is
//! re-exported here for convenience. This module additionally owns the in-memory state mutated
//! by VM event handlers, the per-value-type handler trait, the registry, and the three generic
//! system event handlers intercepted by [`crate::DefaultHost`].

mod events;
mod handlers;
mod schema;
mod state;
mod transaction;

pub use miden_core::deferred::{
    DeferredError, DeferredWitness, Digest, Node, Payload, Tag, hash_node,
};

pub use events::binary_op_payload;
pub use handlers::{FIELD0_ADD, FIELD0_ASSERT_EQ, FIELD0_LEAF, FIELD0_MUL, Field0Handler};
pub use schema::{NodeType, NoopSchema, Schema, SchemaError};
pub use state::DeferredState;
pub use transaction::{DeferredMutation, HandlerTransaction, VmMutation};
