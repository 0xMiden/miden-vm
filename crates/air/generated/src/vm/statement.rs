//! Production VM statement adapter for the authored transcript and reductions.

use alloc::vec::Vec;

use miden_air_definitions::vm as source;
use miden_core::{Felt, field::ExtensionField};
use miden_stark::air::{MultiAir, ReductionError};
use p3_challenger::CanObserve;

use super::{MidenAir, proof_order::AIRS};

#[derive(Copy, Clone, Debug)]
pub struct MidenMultiAir;

impl MidenMultiAir {
    /// Construct the Miden multi-AIR statement marker.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MidenMultiAir {
    fn default() -> Self {
        Self::new()
    }
}

impl<EF: ExtensionField<Felt>> MultiAir<Felt, EF> for MidenMultiAir {
    type Air = MidenAir;
    fn airs(&self) -> &[MidenAir] {
        &AIRS
    }
    fn max_aux_inputs(&self) -> usize {
        source::statement::max_aux_inputs()
    }
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        heights: &[u8],
    ) {
        source::statement::observe(challenger, air_inputs, aux_inputs, heights)
    }
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        source::statement::eval_external(challenges, air_inputs, aux_inputs, aux_values, heights)
    }
}
