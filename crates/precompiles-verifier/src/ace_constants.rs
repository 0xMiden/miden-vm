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
pub(crate) const PVM_PROTOCOL_ID: u64 = 3;

/// Relation digest binding the accepted circuit into the Fiat-Shamir transcript
/// (raw canonical u64 limbs): `Eidos(PVM_PROTOCOL_ID || PVM_ACE_CIRCUIT_DIGEST)`.
#[cfg(any(test, feature = "constants-tools", feature = "std"))]
pub const PVM_RELATION_DIGEST: [u64; 4] = [
    3374563497008389658,
    2791167805176002504,
    705876328355633128,
    5486124368475199955,
];

/// Eidos digest of the order-invariant PVM ACE circuit's instruction stream (raw canonical u64
/// limbs).
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [
    5337761886284738556,
    3006894364745823619,
    7971036537506463636,
    4001318441535671129,
];

/// Commitment to the preprocessed (setup) trace tree under the Eidos config (raw canonical
/// u64 limbs). A trusted verifier input, not proof data: an in-VM verifier cannot rebuild the
/// bundle, so it observes this pinned value into the transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [
    7435130241103350969,
    2209492810180294937,
    2763208909109372110,
    5080896414781165458,
];

/// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts). An in-VM
/// verifier needs these as compile-time constants to size its reads and its ACE evaluation.
#[cfg(any(test, feature = "constants-tools"))]
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (2712, 13040, 14272);

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
#[cfg(any(test, feature = "constants-tools"))]
pub(crate) fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_air::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
