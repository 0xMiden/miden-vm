use alloc::vec::Vec;

use miden_ace_codegen::{AceCircuit, AceConfig, AceError, build_multi_air_ace_circuit};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{field::Algebra, stark::air::symbolic::SymbolicExpressionExt};

use crate::{AIRS, ProofOrder};

/// Builds the Miden multi-AIR ACE circuit for the supplied proof order.
pub fn build_multi_air_ace_circuit_for_order<EF>(
    config: AceConfig,
    order: &ProofOrder,
) -> Result<AceCircuit<EF>, AceError>
where
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    const LMCS_ALIGNMENT: usize = 8;

    let proof_order: Vec<usize> = order.airs().iter().map(|air| air.instance_index()).collect();

    build_multi_air_ace_circuit::<_, Felt, EF>(&AIRS, &proof_order, config, LMCS_ALIGNMENT)
}
