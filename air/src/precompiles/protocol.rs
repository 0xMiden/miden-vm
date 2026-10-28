//! Pinned identity and build-compiled artifacts of the precompile relation.
//!
//! Independent capture and setup tests verify that the authored AIRs still reproduce these pins.

use miden_core::{Felt, Word};

use crate::{
    precompiles::ace::PvmRecursiveAceCircuit,
    shared::security::{AirShape, LookupShape},
};

/// Pinned relation identity and setup commitments for the supported proof configurations.
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
    /// Setup commitment for native proofs using Blake3.
    pub blake3_preprocessed_commitment: [u8; 32],
    /// Setup commitment for native proofs using Keccak.
    pub keccak_preprocessed_commitment: [u64; 4],
}

/// Pinned identity of the canonical precompile relation.
#[rustfmt::skip]
pub const PINS: RelationPins = RelationPins {
    relation_digest: [
        577643653330231829,
        8049569379806614310,
        9065231626553763524,
        8410282077427902040,
    ],
    ace_circuit_digest: [
        3139198613463016739,
        5267671753421984926,
        8940512396910594546,
        7747458865038124780,
    ],
    preprocessed_commitment: [
        1070440981155119101,
        2022626773377316756,
        6941685244114430330,
        5172579525468662096,
    ],
    blake3_preprocessed_commitment: [
        237, 165, 181, 150, 170, 183, 11, 117, 116, 34, 106, 27, 89, 68, 113, 212,
        124, 97, 90, 201, 199, 30, 220, 145, 185, 5, 104, 155, 67, 55, 138, 126,
    ],
    keccak_preprocessed_commitment: [
        8953595915908445159,
        18286975921588085812,
        1662605580119539545,
        8308041584975270064,
    ],
};

/// Relation digest of the precompile relation.
pub const PVM_RELATION_DIGEST: [u64; 4] = PINS.relation_digest;

/// ACE circuit digest of the precompile relation.
pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = PINS.ace_circuit_digest;

/// Setup commitment of the precompile relation under the Eidos config.
pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = PINS.preprocessed_commitment;

/// Setup commitment for native precompile proofs using Blake3.
pub const PVM_BLAKE3_PREPROCESSED_COMMITMENT: [u8; 32] = PINS.blake3_preprocessed_commitment;

/// Setup commitment for native precompile proofs using Keccak.
pub const PVM_KECCAK_PREPROCESSED_COMMITMENT: [u64; 4] = PINS.keccak_preprocessed_commitment;

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
    /// One-time lookup fractions added at the boundary by the fixed `UintVal` and `EcGroup`
    /// messages, counted from the fixed-message catalogue.
    pub fixed_boundary_lookup_terms: u32,
}

impl ProtocolMetadata {
    pub fn num_deep_terms(&self, alignment: usize) -> u32 {
        miden_air_definitions::geometry::num_deep_terms_for_widths(
            self.raw_widths,
            self.num_quotient_chunks,
            alignment,
        )
    }
}

include!(concat!(env!("OUT_DIR"), "/pvm_protocol.rs"));

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

static ACE_INSTRUCTIONS: &[u64] = &include!(concat!(env!("OUT_DIR"), "/pvm_ace_instructions.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::{policy, stark_config};

    const UPDATE_HINT: &str = "an intentional relation change must update PINS in air/src/precompiles/protocol.rs and CURRENT_PVM_VERIFIER_ROOT in core/src/proof.rs";

    #[test]
    fn embedded_circuit_matches_the_authored_relation() {
        let independent =
            crate::precompiles::ace::build_pvm_recursive_verifier_ace_circuit().unwrap();
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
        let relation_digest = PINS.relation_digest.map(Felt::new_unchecked);
        let blake3_config =
            stark_config::blake3_256_config(policy::precompile_pcs_params(), relation_digest);
        assert_eq!(
            <[u8; 32]>::from(
                miden_lifted_stark::Preprocessed::build(&statement, &blake3_config)
                    .unwrap()
                    .commitment(),
            ),
            PVM_BLAKE3_PREPROCESSED_COMMITMENT,
            "{UPDATE_HINT}"
        );
        let keccak_config =
            stark_config::keccak_config(policy::precompile_pcs_params(), relation_digest);
        assert_eq!(
            <[u64; 4]>::from(
                miden_lifted_stark::Preprocessed::build(&statement, &keccak_config)
                    .unwrap()
                    .commitment(),
            ),
            PVM_KECCAK_PREPROCESSED_COMMITMENT,
            "{UPDATE_HINT}"
        );
        let config = stark_config::eidos_config(policy::precompile_pcs_params(), relation_digest);
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
