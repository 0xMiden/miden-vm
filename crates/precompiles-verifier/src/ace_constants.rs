//! Protocol constants for the full PVM recursive-verifier AIR variant.
//!
//! Each hash variant has one order-invariant circuit. The full variant's constants below retain
//! the original protocol commitment; the generator also emits the trusted configuration table
//! used by the shared MASM verifier to select all eight variants.
//!
//! The values are pinned in `miden_air::precompiles`; the tests here and there recompute them from
//! the chiplet AIRs.

#[cfg(any(test, feature = "constants-tools"))]
use miden_core::{Felt, Word};

/// Command line that regenerates the generated MASM modules, quoted in their headers.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) const GENERATED_BY: &str = "cargo run -p miden-precompiles-verifier --release \
     --features constants-tools --bin pvm-constants-regen -- --write";

/// Protocol version included in the PVM relation digest.
///
/// The circuit digest binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM and PVM use distinct protocol versions.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) const PVM_PROTOCOL_ID: u64 = miden_air::precompiles::policy::PROTOCOL_ID;

#[cfg(test)]
pub use miden_air::precompiles::protocol::PVM_RELATION_DIGEST;
#[cfg(test)]
pub use miden_air::precompiles::protocol::{
    PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
};

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
