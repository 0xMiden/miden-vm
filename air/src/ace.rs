//! ACE circuit integration for the Miden multi-AIR proof.
//!
//! The public API is split by responsibility:
//! - `recursive` builds the encoded circuit consumed by the recursive verifier.
//! - `multi_air` combines the per-AIR ACE DAGs into one proof-order-aware circuit.
//!
//! The cross-AIR LogUp boundary identity is checked outside the circuit as
//! `sum_i(n_i * sigma_prime_i) + c_boundary = 0`, where `sigma_prime_i` is AIR `i`'s
//! normalized committed LogUp sum and `n_i` is its trace length.

mod multi_air;
mod recursive;

pub use multi_air::{
    FactoredMultiAirCircuit, build_factored_multi_air_ace_circuit,
    build_multi_air_ace_circuit_for_order,
};
#[cfg(feature = "std")]
pub(crate) use recursive::shared_recursive_factory;
pub use recursive::{
    RecursiveAceCircuit, RecursiveAceCircuitFactory, RecursiveRegistryEntry,
    build_recursive_verifier_ace_circuit, recursive_registry_entry,
};
