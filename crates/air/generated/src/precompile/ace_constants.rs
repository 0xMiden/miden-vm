//! Protocol constants of the PVM recursive-verifier ACE circuit.
//!
//! One order-invariant circuit serves every proof ordering, so the accepted circuit is named
//! outright by its digest: [`PVM_ACE_CIRCUIT_DIGEST`] is the advice-map key its instruction stream
//! is served under, the value the MASM loader pins that stream to, and — through
//! [`PVM_RELATION_DIGEST`] — what binds the Fiat-Shamir transcript to the relation.
//!
//! Checked by `air-codegen`; changes to accepted values require deliberate protocol review.

use miden_core::{Felt, Word};

/// Command that regenerates managed MASM after checking these protected constants.
pub const GENERATED_BY: &str = "cargo run -p miden-air-source --features tooling --bin air-codegen -- <workspace-root> --write";

/// Protocol version included in the PVM relation digest.
///
/// The circuit digest binds the generated circuit, but not external multi-AIR assertions such as
/// `ChipletMultiAir::eval_external`. Changes to those semantics require a protocol-version bump.
/// The Miden VM and PVM use distinct protocol versions.
pub const PVM_PROTOCOL_ID: u64 = 4;

/// Relation digest binding the accepted circuit into the Fiat-Shamir transcript
/// (raw canonical u64 limbs): `Eidos(PVM_PROTOCOL_ID || PVM_ACE_CIRCUIT_DIGEST)`.
#[rustfmt::skip]
pub const PVM_RELATION_DIGEST: [u64; 4] = [
    5618632176883261929,
    5091169848121332946,
    9110857118546866548,
    100418585322354598,
];

/// Eidos digest of the order-invariant PVM ACE circuit's instruction stream (raw canonical u64
/// limbs).
#[rustfmt::skip]
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [
    2255028588524991477,
    8088146176287763667,
    1935595524963351362,
    5560235558590875651,
];

/// Commitment to the preprocessed (setup) trace tree under the Eidos config (raw canonical
/// u64 limbs). A trusted verifier input, not proof data: an in-VM verifier cannot rebuild the
/// bundle, so it observes this pinned value into the transcript.
#[rustfmt::skip]
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];

/// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts). An in-VM
/// verifier needs these as compile-time constants to size its reads and its ACE evaluation.
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (2520, 13000, 14232);

/// Computes the relation digest binding an ACE circuit commitment into the Fiat-Shamir transcript.
pub fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_stark::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
