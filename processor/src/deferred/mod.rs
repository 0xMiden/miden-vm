// Public surface is wired into the host registry in commit 5; until then the types are
// exercised only by unit tests.
#![allow(unused)]

//! Processor-side state for the deferred-DAG subsystem.
//!
//! The shared data model (tags, nodes, payloads, witness) lives in `miden-core::deferred`. This
//! module owns the in-memory state mutated by event handlers during VM execution: the node map
//! and the list of equality assertions. Type-handler traits, the registry, and the three generic
//! system event handlers are added in later commits.

mod state;
mod transaction;

pub use state::DeferredState;
pub use transaction::{DeferredMutation, HandlerTransaction, VmMutation};
