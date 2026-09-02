//! Protocol constants of the PVM recursive-verifier ACE circuit.
//!
//! One order-invariant circuit serves every proof ordering, so the accepted circuit is named
//! outright by its digest: [`PVM_ACE_CIRCUIT_DIGEST`] is the advice-map key its instruction stream
//! is served under, the value the MASM loader pins that stream to, and — through
//! [`PVM_RELATION_DIGEST`] — what binds the Fiat-Shamir transcript to the relation.
//!
//! The values below are written by `pvm-constants-regen`; do not edit them by hand.

#[cfg(any(test, feature = "constants-tools"))]
use miden_core::{Felt, Word};

/// Command line that regenerates every artifact below and the generated MASM modules, quoted in
/// their headers.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) const GENERATED_BY: &str = "cargo run -p miden-precompiles-verifier --release \
     --features constants-tools --bin pvm-constants-regen -- --write";

/// Protocol version included in the PVM relation digest.
///
/// The circuit digest binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM and PVM use distinct protocol versions.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) const PVM_PROTOCOL_ID: u64 = 2;

/// Relation digest binding the accepted circuit into the Fiat-Shamir transcript
/// (raw canonical u64 limbs): `Eidos(PVM_PROTOCOL_ID || PVM_ACE_CIRCUIT_DIGEST)`.
#[cfg(any(test, feature = "constants-tools", feature = "std"))]
pub const PVM_RELATION_DIGEST: [u64; 4] = [
    6587660001117274832,
    5869676935261161425,
    7063803722444350762,
    7843579492266924388,
];

/// Eidos digest of the order-invariant PVM ACE circuit's instruction stream (raw canonical u64
/// limbs).
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [
    5866826002340252643,
    7636916198557459504,
    1264744801825455326,
    826327314964018021,
];

/// Commitment to the preprocessed (setup) trace tree under the Eidos config (raw canonical
/// u64 limbs). A trusted verifier input, not proof data: an in-VM verifier cannot rebuild the
/// bundle, so it observes this pinned value into the transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [
    6268951225194987386,
    4849911536323772979,
    8427269700199674086,
    7952151839024097748,
];

/// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts). An in-VM
/// verifier needs these as compile-time constants to size its reads and its ACE evaluation.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (3238, 10300, 13336);

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
