//! Processor-side state and event handlers for the deferred-DAG subsystem.
//!
//! The shared data model (tags, nodes, payloads, witness) lives in `miden-core::deferred` and is
//! re-exported here for convenience. This module additionally owns the in-memory state mutated
//! by VM event handlers, the per-value-type handler trait, the registry, and the two generic
//! system events intercepted by [`crate::DefaultHost`].

mod handlers;
mod schema;
mod state;

pub use miden_core::deferred::{DeferredError, DeferredWitness, Digest, Node, Payload, Tag};

pub use handlers::Field0Handler;
pub use schema::{NodeType, NoopSchema, Schema, SchemaError};
pub use state::DeferredState;
