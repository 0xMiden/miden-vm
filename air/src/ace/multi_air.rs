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

    /// Unwrap into the generic ace-codegen composition (for [`FactoredCircuitFactory`]).
    ///
    /// [`FactoredCircuitFactory`]: miden_ace_codegen::FactoredCircuitFactory
    pub(crate) fn into_inner(self) -> miden_ace_codegen::FactoredMultiAirCircuit<QuadFelt> {
        self.inner
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
