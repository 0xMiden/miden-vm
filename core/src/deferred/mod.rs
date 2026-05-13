//! Content-addressed DAG of *deferred algebraic operations*.
//!
//! The deferred subsystem represents expensive precompile work (e.g. 256-bit non-native field
//! arithmetic, future curve ops) as a DAG of typed [`Node`]s addressed by their 4-felt Poseidon2
//! digest. The VM uses three generic system events (`RegisterLeaf`, `RegisterOp`, `AssertEq`) to
//! populate the DAG; an external prover later consumes a [`DeferredWitness`] containing the
//! reachable nodes and equality assertions.
//!
//! This crate (`miden-core`) defines only the shared data model. The processor-side state, event
//! handlers, and per-value-type semantics live in `miden-processor`.

mod error;
mod hash;
mod node;
mod payload;
mod tag;
mod witness;

pub use error::DeferredError;
pub use hash::hash_node;
pub use node::Node;
pub use payload::Payload;
pub use tag::Tag;
pub use witness::DeferredWitness;

/// Content-addressed digest of a [`Node`]. A 4-felt Poseidon2 output.
pub type Digest = crate::Word;
