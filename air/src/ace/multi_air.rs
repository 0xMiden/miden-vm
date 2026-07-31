use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError, build_multi_air_ace_circuit};
use miden_core::field::QuadFelt;

use crate::{AIRS, HandwrittenMidenAir, ProofOrder};

/// Builds the Miden multi-AIR ACE circuit for the supplied proof order.
pub fn build_multi_air_ace_circuit_for_order(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<QuadFelt>, AceError> {
    const LMCS_ALIGNMENT: usize = 8;

    let airs = AIRS.map(HandwrittenMidenAir);
    let proof_order: Vec<usize> = order.airs().iter().map(|air| air.instance_index()).collect();

    build_multi_air_ace_circuit(&airs, &proof_order, config, LMCS_ALIGNMENT)
}
