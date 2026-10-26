//! Pinned identity and build-compiled artifacts of the precompile relation.
//!
//! Independent capture and setup tests verify that the authored AIRs still reproduce these pins.

use miden_ace_codegen::RecursiveAceCircuit as PvmRecursiveAceCircuit;
use miden_core::{Felt, Word};
use p3_security::budget::{AirShape, LookupShape};

/// Pinned identity of the precompile relation (raw canonical u64 limbs).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationPins {
    /// `Eidos(PROTOCOL_ID || ace_circuit_digest)`, binding the relation's circuit into the
    /// Fiat-Shamir transcript.
    pub relation_digest: [u64; 4],
    /// Eidos digest of the relation's order-invariant ACE instruction stream.
    pub ace_circuit_digest: [u64; 4],
    /// Commitment to the relation's preprocessed (setup) trace tree under the Eidos config. A
    /// trusted verifier input, not proof data: an in-VM verifier cannot rebuild the bundle, so it
    /// observes this pinned value into the transcript.
    pub preprocessed_commitment: [u64; 4],
}

/// Pinned identity of the canonical precompile relation.
#[rustfmt::skip]
pub const PINS: RelationPins = RelationPins {
    relation_digest: [
        5618632176883261929,
        5091169848121332946,
        9110857118546866548,
        100418585322354598,
    ],
    ace_circuit_digest: [
        2255028588524991477,
        8088146176287763667,
        1935595524963351362,
        5560235558590875651,
    ],
    preprocessed_commitment: [
        1070440981155119101,
        2022626773377316756,
        6941685244114430330,
        5172579525468662096,
    ],
};

/// Relation digest of the precompile relation.
pub const PVM_RELATION_DIGEST: [u64; 4] = PINS.relation_digest;

/// ACE circuit digest of the precompile relation.
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = PINS.ace_circuit_digest;

/// Setup commitment of the precompile relation.
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = PINS.preprocessed_commitment;

/// Pinned identity of the precompile relation.
pub fn pins() -> &'static RelationPins {
    &PINS
}

/// Geometry of the precompile relation, compiled from the chiplet AIRs.
#[derive(Clone, Copy, Debug)]
pub struct ProtocolMetadata {
    /// Encoded circuit shape: (READ variables, evaluation gates, stream length in felts).
    pub circuit_shape: (usize, usize, usize),
    /// Security shape of the relation at the default commitment alignment.
    pub air_shape: AirShape,
    /// Raw `(preprocessed, main, auxiliary)` widths of each AIR, in canonical order.
    pub raw_widths: &'static [(usize, usize, usize)],
    pub num_quotient_chunks: usize,
}

impl ProtocolMetadata {
    pub fn num_deep_terms(&self, alignment: usize) -> u32 {
        crate::geometry::num_deep_terms_for_widths(
            self.raw_widths,
            self.num_quotient_chunks,
            alignment,
        )
    }
}

include!(concat!(env!("OUT_DIR"), "/pvm_protocol.rs"));

static ACE_INSTRUCTIONS: &[u64] = &include!(concat!(env!("OUT_DIR"), "/pvm_ace_instructions.rs"));

/// Encoded circuit shape of the precompile relation.
pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = PROTOCOL.circuit_shape;

/// Build-compiled metadata of the precompile relation.
pub fn metadata() -> &'static ProtocolMetadata {
    &PROTOCOL
}

/// Materialize the relation's embedded instruction stream without symbolic AIR capture.
///
/// The commitment is the relation's pinned ACE circuit digest; the recursive verifier rejects a
/// stream that does not hash to it.
pub fn recursive_circuit() -> PvmRecursiveAceCircuit {
    let (num_inputs, num_eval_gates, stream_len) = metadata().circuit_shape;
    PvmRecursiveAceCircuit {
        num_inputs,
        num_eval_gates,
        stream_len,
        commitment: Word::new(pins().ace_circuit_digest.map(Felt::new_unchecked)),
        instructions: ACE_INSTRUCTIONS.iter().copied().map(Felt::new_unchecked).collect(),
    }
}

#[cfg(test)]
mod tests {
    use miden_air_definitions::compiler::precompiles::build_pvm_recursive_verifier_ace_circuit;

    use super::*;
    use crate::precompiles::policy;

    const UPDATE_HINT: &str = "an intentional relation change must update PINS in air/src/precompiles/protocol.rs and CURRENT_PVM_VERIFIER_ROOT in core/src/proof.rs";

    #[test]
    fn embedded_circuit_matches_the_authored_relation() {
        let independent = build_pvm_recursive_verifier_ace_circuit().unwrap();
        assert_eq!(recursive_circuit(), independent, "{UPDATE_HINT}");
    }

    #[test]
    fn relation_digest_binds_the_circuit_digest() {
        let digest = crate::shared::config::relation_digest(
            policy::PROTOCOL_ID,
            &Word::new(PINS.ace_circuit_digest.map(Felt::new_unchecked)),
        );
        assert_eq!(
            digest.map(|felt| felt.as_canonical_u64()),
            PINS.relation_digest,
            "{UPDATE_HINT}"
        );
    }

    #[test]
    fn preprocessed_commitment_matches_the_authored_setup() {
        use alloc::vec;

        use miden_core::field::QuadFelt;
        let statement = miden_lifted_air::Statement::<
            Felt,
            QuadFelt,
            miden_air_definitions::precompiles::ChipletMultiAir,
        >::new(
            miden_air_definitions::precompiles::ChipletMultiAir::new(),
            vec![(
                miden_air_definitions::precompiles::ChipletAir::TRANSCRIPT_EVAL_INDEX,
                vec![Felt::ZERO; crate::precompiles::logup::NUM_PUBLIC_VALUES],
            )],
            vec![],
        )
        .unwrap();
        let config = crate::precompiles::stark_config::eidos_config(
            policy::precompile_pcs_params(),
            PINS.relation_digest.map(Felt::new_unchecked),
        );
        let commitment = <[u64; 4]>::from(
            miden_lifted_stark::Preprocessed::build(&statement, &config)
                .unwrap()
                .commitment(),
        );
        assert_eq!(commitment, PVM_PREPROCESSED_COMMITMENT, "{UPDATE_HINT}");
        assert_eq!(
            <[u64; 4]>::from(crate::precompiles::preprocessed::eidos().commitment()),
            commitment,
            "{UPDATE_HINT}"
        );
    }
}
