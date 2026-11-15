//! Prepared native kernels for independently completed precompile source ports.

use miden_core::Felt;
use miden_stark::air::native::{
    AirDescriptor, AirKernel, Frame, Inputs, LiftedAirBuilder, UniformInputs,
};
use p3_field::Algebra;

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_descriptors.rs"));
}

/// Generated execution of the authored Keccak-round relation.
///
/// Construction owns a checked embedded descriptor without source recapture or fixed-table
/// construction. Witness construction remains on the authored
/// [`KeccakRoundAir`](miden_air_definitions::precompiles::hash::keccak::round::KeccakRoundAir).
/// The canonical multi-AIR runtime continues to select its current wrapper until activation.
#[derive(Clone, Debug)]
pub struct KeccakRoundKernel {
    descriptor: AirDescriptor<Felt>,
}

impl KeccakRoundKernel {
    pub fn new() -> Self {
        Self {
            descriptor: descriptors::descriptor_keccak_round(),
        }
    }
}

impl Default for KeccakRoundKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl AirKernel for KeccakRoundKernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = [E; evaluators::KECCAK_ROUND_PREPARED_TERMS];

    fn descriptor(&self) -> &AirDescriptor<Felt> {
        &self.descriptor
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E> {
        evaluators::precompute_keccak_round(inputs)
    }

    fn eval_row<S: LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &Frame<'_, S>,
        inputs: Inputs<'_, S>,
        prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
        sink: &mut S,
    ) {
        evaluators::eval_keccak_round(frame, inputs, sink, prepared);
    }
}
