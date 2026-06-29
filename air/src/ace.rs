//! ACE circuit integration for the Miden multi-AIR proof.
//!
//! The public API is split by responsibility:
//! - `recursive` builds the encoded circuit consumed by the recursive verifier.
//! - `multi_air` combines the per-AIR ACE DAGs into one proof-order-aware circuit.
//! - `boundary` appends the shared LogUp auxiliary-boundary identity.

mod boundary;
mod multi_air;
mod recursive;

pub use boundary::{
    BusFraction, LogUpBoundaryConfig, MessageElement, Sign, batch_logup_boundary_into_builder,
    multi_air_logup_boundary_config,
};
pub use multi_air::build_multi_air_ace_circuit_for_order;
pub use recursive::{RecursiveAceCircuit, build_recursive_verifier_ace_circuit};
