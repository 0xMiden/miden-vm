//! PVM protocol identities and regeneration support.
//!
//! Canonical accepted values live beside production AIR artifacts.

#[cfg(any(test, feature = "constants-tools"))]
pub use miden_air::precompile::protocol::PVM_PROTOCOL_ID;
#[cfg(any(test, feature = "constants-tools", feature = "std"))]
pub use miden_air::precompile::protocol::PVM_RELATION_DIGEST;
#[cfg(any(test, feature = "constants-tools"))]
pub use miden_air::precompile::protocol::{
    PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
};
#[cfg(any(test, feature = "constants-tools"))]
use miden_core::{Felt, Word};

/// Command line that regenerates the production identities and generated MASM modules, quoted in
/// their headers.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) const GENERATED_BY: &str = "cargo run -p miden-precompiles-verifier --release \
     --features constants-tools --bin pvm-constants-regen -- --write";

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::vm::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
