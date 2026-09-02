use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError};
use miden_core::field::QuadFelt;

use crate::{AIRS, HandwrittenMidenAir, ProofOrder};

/// Per-AIR preprocessed, main, and aux regions are padded to this width before concatenation.
const LMCS_ALIGNMENT: usize = 8;

/// Builds the Miden multi-AIR ACE circuit for the supplied proof order.
///
/// The circuit evaluates the proof-order Horner fold of the per-AIR alpha-folded constraint
/// roots, with each AIR's trace data read from the slots that order commits it in. The recursive
/// verifier evaluates the order-invariant circuit instead; this construction is the independent
/// reference that one is tested against.
pub fn build_multi_air_ace_circuit_for_order(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = AIRS.map(HandwrittenMidenAir);
    let proof_order: Vec<usize> = order.airs().iter().map(|air| air.instance_index()).collect();
    miden_ace_codegen::build_multi_air_ace_circuit(&airs, &proof_order, config, LMCS_ALIGNMENT)
}

/// Build the canonical (order-invariant) Miden multi-AIR ACE circuit.
///
/// Unlike [`build_multi_air_ace_circuit_for_order`] there is exactly one circuit — no per-order
/// construction — because every AIR's trace data sits at a canonical offset and its fold
/// coefficient has its own READ slot.
pub fn build_canonical_multi_air_ace_circuit(
    config: AceConfig,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = AIRS.map(HandwrittenMidenAir);
    miden_ace_codegen::build_canonical_multi_air_ace_circuit(&airs, config, LMCS_ALIGNMENT)
}

#[cfg(test)]
mod tests {
    use miden_ace_codegen::{InputKey, LayoutKind};

    use super::*;
    use crate::MIDEN_AIR_COUNT;

    #[test]
    fn canonical_multi_air_circuit_exposes_one_fold_coefficient_per_air() {
        let config = AceConfig {
            num_quotient_chunks: 8,
            layout: LayoutKind::Masm,
            num_airs: MIDEN_AIR_COUNT,
        };
        let circuit = build_canonical_multi_air_ace_circuit(config).expect("canonical circuit");
        let layout = circuit.layout();

        for air_index in 0..MIDEN_AIR_COUNT {
            let index = layout
                .index(InputKey::MultiAirFoldCoeff(air_index))
                .unwrap_or_else(|| panic!("canonical layout exposes fold coefficient {air_index}"));
            assert!(index < layout.total_inputs, "fold coefficient {air_index} is out of bounds");
        }
        assert!(layout.index(InputKey::MultiAirFoldCoeff(MIDEN_AIR_COUNT)).is_none());

        // The extra fold-coefficient slots must not break the READ-section alignment the
        // recursive verifier's `adv_pipe` ingestion relies on.
        let encoded = circuit.to_ace().expect("canonical circuit must be MASM encodable");
        assert!(
            encoded.size_in_felt().is_multiple_of(8),
            "encoded canonical circuit must be 8-felt aligned for adv_pipe"
        );
    }
}
