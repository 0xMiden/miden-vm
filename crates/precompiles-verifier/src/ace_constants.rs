//! Protocol constants of the PVM recursive-verifier ACE circuit.
//!
//! One order-invariant circuit serves every proof ordering, so the accepted circuit is named
//! outright by its digest: [`miden_air::precompiles::protocol::PVM_ACE_CIRCUIT_DIGEST`] is the
//! advice-map key its instruction stream is served under, the value the MASM loader pins that
//! stream to, and — through [`PVM_RELATION_DIGEST`] — what binds the Fiat-Shamir transcript to the
//! relation.
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

pub use miden_air::precompiles::protocol::PVM_RELATION_DIGEST;
#[cfg(any(test, feature = "constants-tools"))]
pub use miden_air::precompiles::protocol::{
    PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
};

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::vm::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
