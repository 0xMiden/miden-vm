//! Handwritten VM evaluation exposed through the production AIR adapter.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_lifted_air::{BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder};

use crate::airs::MidenAir;

#[derive(Copy, Clone, Debug)]
pub struct HandwrittenMidenAir(pub MidenAir);

impl BaseAir<Felt> for HandwrittenMidenAir {
    fn width(&self) -> usize {
        self.0.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.0.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }

    fn num_public_values(&self) -> usize {
        BaseAir::<Felt>::num_public_values(&self.0)
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.0.periodic_columns()
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for HandwrittenMidenAir {
    fn num_randomness(&self) -> usize {
        LiftedAir::<Felt, EF>::num_randomness(&self.0)
    }

    fn aux_width(&self) -> usize {
        LiftedAir::<Felt, EF>::aux_width(&self.0)
    }

    fn num_aux_values(&self) -> usize {
        LiftedAir::<Felt, EF>::num_aux_values(&self.0)
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.0.build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.0.build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        LiftedAir::<Felt, EF>::constraint_degree(&self.0)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        self.0.eval_handwritten(builder)
    }
}
