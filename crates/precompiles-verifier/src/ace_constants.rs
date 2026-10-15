//! Protocol constants for the full PVM recursive-verifier AIR variant.
//!
//! Each hash variant has one order-invariant circuit. The full variant's constants below retain
//! the original protocol commitment; the generator also emits the trusted configuration table
//! used by the shared MASM verifier to select all eight variants.
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
pub(crate) const PVM_PROTOCOL_ID: u64 = 4;

/// Relation digest binding the accepted circuit into the Fiat-Shamir transcript
/// (raw canonical u64 limbs): `Eidos(PVM_PROTOCOL_ID || PVM_ACE_CIRCUIT_DIGEST)`.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_RELATION_DIGEST: [u64; 4] = [
    3430130751249333112,
    3923292911056463301,
    9102369175960030177,
    2472984497279583389,
];

/// Eidos digest of the order-invariant PVM ACE circuit's instruction stream (raw canonical u64
/// limbs).
#[cfg(any(test, feature = "constants-tools"))]
#[rustfmt::skip]
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [
    6538378689345343479,
    2699441165468814929,
    5325642021112777038,
    4153236842813463216,
];

/// Commitment to the preprocessed (setup) trace tree under the Eidos config (raw canonical
/// u64 limbs). A trusted verifier input, not proof data: an in-VM verifier cannot rebuild the
/// bundle, so it observes this pinned value into the transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];

/// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts). An in-VM
/// verifier needs these as compile-time constants to size its reads and its ACE evaluation.
#[cfg(feature = "constants-tools")]
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (2632, 13008, 14240);

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
