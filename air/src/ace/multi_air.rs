use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError, InputLayout};
use miden_core::field::QuadFelt;

use crate::{AIRS, HandwrittenMidenAir, ProofOrder};

/// Per-AIR preprocessed, main, and aux regions are padded to this width before concatenation.
const LMCS_ALIGNMENT: usize = 8;

/// Builds the Miden multi-AIR ACE circuit for the supplied proof order.
///
/// The assembled circuit evaluates the proof-order Horner fold of the per-AIR alpha-folded
/// constraint roots. It is the factored form: a per-order shuffle section routing the
/// proof-order READ slots (and fold coefficients) into canonical wires, followed by the
/// order-invariant common section.
pub fn build_multi_air_ace_circuit_for_order(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    build_factored_multi_air_ace_circuit(config)?.circuit_for_order(order)
}

/// Factored Miden multi-AIR circuit: canonical common section plus per-order shuffle assembly.
#[derive(Debug, Clone)]
pub struct FactoredMultiAirCircuit {
    inner: miden_ace_codegen::FactoredMultiAirCircuit<QuadFelt>,
}

impl FactoredMultiAirCircuit {
    /// Return the input layout shared by every proof order.
    pub fn layout(&self) -> &InputLayout {
        self.inner.layout()
    }

    /// Number of shuffle-section ops (also the section length in stream felts).
    pub fn num_shuffle_ops(&self) -> usize {
        self.inner.num_shuffle_ops()
    }

    /// Assemble the full circuit for one proof order.
    pub fn circuit_for_order(&self, order: &ProofOrder) -> Result<AceCircuit<QuadFelt>, AceError> {
        let proof_order: Vec<usize> = order.airs().iter().map(|air| air.instance_index()).collect();
        self.inner.circuit_for_order(&proof_order)
    }
}

/// Build the canonical Miden multi-AIR composition and lower it into the factored form.
pub fn build_factored_multi_air_ace_circuit(
    config: AceConfig,
) -> Result<FactoredMultiAirCircuit, AceError> {
    let airs = AIRS.map(HandwrittenMidenAir);
    let inner =
        miden_ace_codegen::build_factored_multi_air_ace_circuit(&airs, config, LMCS_ALIGNMENT)?;
    Ok(FactoredMultiAirCircuit { inner })
}

/// Build the canonical (order-invariant) Miden multi-AIR ACE circuit.
///
/// Unlike [`build_factored_multi_air_ace_circuit`] there is exactly one circuit — no per-order
/// assembly step — because every AIR's trace data sits at a canonical offset and its fold
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
