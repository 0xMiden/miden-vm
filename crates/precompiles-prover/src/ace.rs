//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`ChipletAir::all`] as its stable instance order and canonical ACE fold order,
//! and aligns each per-AIR trace region to eight base-field elements. The lifted STARK proof
//! derives its own ordering from trace heights. The cross-chiplet LogUp identity enforced by
//! `ChipletMultiAir::eval_external` remains an external multi-AIR assertion.

use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError, LayoutKind, build_multi_air_ace_circuit};
use miden_core::{Felt, field::QuadFelt};

use crate::session::{ChipletAir, NUM_CHIPLETS};

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Per-AIR trace regions are padded to this width before concatenation, matching the LMCS wire
/// alignment used by the commitment scheme.
const LMCS_ALIGNMENT: usize = 8;

/// Number of quotient chunks the precompile relation commits to.
///
/// The lifted STARK verifier derives this quantity symbolically from the AIRs. Deriving it through
/// the same implementation keeps the ACE circuit's READ layout coupled to the proof protocol.
fn num_quotient_chunks() -> usize {
    let max_log_quotient_degree = ChipletAir::all()
        .iter()
        .map(miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>)
        .max()
        .expect("the chiplet stack is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings for the precompile chiplet relation.
fn precompile_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: num_quotient_chunks(),
        layout: LayoutKind::Masm,
        num_airs: NUM_CHIPLETS,
    }
}

/// Builds the ACE circuit for the precompile chiplet multi-AIR relation.
///
/// The circuit uses the stable [`ChipletAir::all`] instance order as its canonical ACE fold order
/// and aligns trace regions to eight base-field elements. These choices define the committed ACE
/// encoding; they do not prescribe the lifted STARK proof order. The cross-chiplet LogUp identity
/// is checked separately by `ChipletMultiAir::eval_external`.
pub fn build_precompile_multi_air_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = ChipletAir::all();
    let proof_order: Vec<_> = (0..airs.len()).collect();

    build_multi_air_ace_circuit::<ChipletAir>(
        &airs,
        &proof_order,
        precompile_ace_config(),
        LMCS_ALIGNMENT,
    )
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec::Vec};

    use miden_core::{Felt, field::QuadFelt};

    use super::{build_precompile_multi_air_ace_circuit, precompile_ace_config};
    use crate::session::{ChipletAir, NUM_CHIPLETS};

    #[test]
    fn precompile_multi_air_ace_circuit_builds() {
        let circuit =
            build_precompile_multi_air_ace_circuit().expect("precompile multi-AIR ACE circuit");
        assert_eq!(circuit.layout().counts.num_public, crate::logup::NUM_PUBLIC_VALUES);
        assert_eq!(circuit.layout().counts.num_aux_boundary, NUM_CHIPLETS);
        assert!(circuit.layout().counts.preprocessed_width >= 8);
    }

    /// Pin the complete quotient-degree vector, not merely its maximum: otherwise a chiplet could
    /// drift between degrees while another chiplet kept the relation-wide maximum unchanged.
    #[test]
    fn quotient_chunks_match_the_symbolic_derivation() {
        const EXPECTED: [(&str, u8); NUM_CHIPLETS] = [
            ("ChunkNodeSponge", 2),
            ("Poseidon2", 2),
            ("KeccakRound", 2),
            ("BytePairLut", 1),
            ("TranscriptEval", 1),
            ("UintStoreMul", 1),
            ("UintAdd", 1),
            ("EcPointStoreGroups", 1),
            ("EcGroupAdd", 1),
            ("EcMsm", 1),
        ];

        let derived: Vec<(String, u8)> = ChipletAir::all()
            .iter()
            .map(|air| {
                (
                    format!("{air:?}"),
                    miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>(air),
                )
            })
            .collect();
        let expected: Vec<(String, u8)> =
            EXPECTED.iter().map(|(name, degree)| ((*name).into(), *degree)).collect();
        assert_eq!(
            derived, expected,
            "a chiplet's quotient degree moved; if intended, re-mint the relation digest"
        );

        let max = derived.iter().map(|(_, degree)| *degree).max().expect("non-empty stack");
        let expected_chunks = 1usize << max;
        assert_eq!(
            precompile_ace_config().num_quotient_chunks,
            expected_chunks,
            "the ACE circuit must read exactly the quotient chunks the proof carries"
        );
        let circuit =
            build_precompile_multi_air_ace_circuit().expect("precompile multi-AIR ACE circuit");
        assert_eq!(
            circuit.layout().counts.num_quotient_chunks,
            expected_chunks,
            "the built circuit must preserve the derived quotient arity"
        );
    }
}
