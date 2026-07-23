//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`ChipletAir::all`] as its stable instance order and canonical ACE fold order,
//! and aligns each per-AIR trace region to eight base-field elements. The lifted STARK proof
//! derives its own ordering from trace heights. The cross-chiplet LogUp identity enforced by
//! `ChipletMultiAir::eval_external` remains an external multi-AIR assertion.

use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError, build_multi_air_ace_circuit};
use miden_core::{Felt, field::QuadFelt};

use crate::session::ChipletAir;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Builds the ACE circuit for the precompile chiplet multi-AIR relation.
///
/// The circuit uses the stable [`ChipletAir::all`] instance order as its canonical ACE fold order
/// and aligns trace regions to eight base-field elements. These choices define the committed ACE
/// encoding; they do not prescribe the lifted STARK proof order. The cross-chiplet LogUp identity
/// is checked separately by `ChipletMultiAir::eval_external`.
pub fn build_precompile_multi_air_ace_circuit(
    config: AceConfig,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    const LMCS_ALIGNMENT: usize = 8;

    let airs = ChipletAir::all();
    let proof_order: Vec<_> = (0..airs.len()).collect();

    build_multi_air_ace_circuit::<ChipletAir, Felt, QuadFelt>(
        &airs,
        &proof_order,
        config,
        LMCS_ALIGNMENT,
    )
}

#[cfg(test)]
mod tests {
    use miden_ace_codegen::{AceConfig, LayoutKind};

    use super::build_precompile_multi_air_ace_circuit;
    use crate::session::NUM_CHIPLETS;

    #[test]
    fn precompile_multi_air_ace_circuit_builds() {
        let config = AceConfig {
            num_quotient_chunks: 8,
            layout: LayoutKind::Masm,
            num_airs: NUM_CHIPLETS,
        };

        let circuit = build_precompile_multi_air_ace_circuit(config)
            .expect("precompile multi-AIR ACE circuit");
        assert_eq!(circuit.layout().counts.num_public, crate::logup::NUM_PUBLIC_VALUES);
        assert_eq!(circuit.layout().counts.num_aux_boundary, NUM_CHIPLETS);
        assert!(circuit.layout().counts.preprocessed_width >= 8);
    }
}
