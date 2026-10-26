//! Production VM statement adapter over the authored statement semantics.

use alloc::vec::Vec;

use miden_air_definitions as definitions;
use miden_core::{Felt, field::ExtensionField};
use miden_lifted_air::{MultiAir, ReductionError};
use p3_challenger::CanObserve;

use crate::{airs::MidenAir, proof_order::AIRS};

#[derive(Copy, Clone, Debug, Default)]
pub struct MidenMultiAir;

impl MidenMultiAir {
    /// Construct the Miden multi-AIR statement marker.
    pub const fn new() -> Self {
        Self
    }
}

impl<EF: ExtensionField<Felt>> MultiAir<Felt, EF> for MidenMultiAir {
    type Air = MidenAir;

    fn airs(&self) -> &[MidenAir] {
        &AIRS
    }

    fn max_aux_inputs(&self) -> usize {
        <definitions::MidenMultiAir as MultiAir<Felt, EF>>::max_aux_inputs(
            &definitions::MidenMultiAir,
        )
    }

    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        heights: &[u8],
    ) {
        <definitions::MidenMultiAir as MultiAir<Felt, EF>>::observe(
            &definitions::MidenMultiAir,
            challenger,
            air_inputs,
            aux_inputs,
            heights,
        )
    }

    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        definitions::MidenMultiAir
            .eval_external(challenges, air_inputs, aux_inputs, aux_values, heights)
    }
}
