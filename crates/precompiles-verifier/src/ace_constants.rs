//! Protocol constants of the PVM recursive-verifier ACE circuit.
//!
//! One order-invariant circuit serves every proof ordering, so the accepted circuit is named
//! outright by its digest: [`miden_precompiles_air::protocol::PVM_ACE_CIRCUIT_DIGEST`] is the
//! advice-map key its instruction stream is served under, the value the MASM loader pins that
//! stream to, and — through [`PVM_RELATION_DIGEST`] — what binds the Fiat-Shamir transcript to the
//! relation.
//!
//! The values are pinned in `miden-precompiles-air`; the tests here and there recompute them from
//! the chiplet AIRs.

#[cfg(test)]
use miden_core::{Felt, Word};

/// Protocol version included in the PVM relation digest.
///
/// The circuit digest binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM and PVM use distinct protocol versions.
#[cfg(test)]
pub(crate) const PVM_PROTOCOL_ID: u64 = miden_precompiles_air::policy::PROTOCOL_ID;

pub use miden_precompiles_air::protocol::PVM_RELATION_DIGEST;
#[cfg(test)]
pub use miden_precompiles_air::protocol::{PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE};

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(test)]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
