//! Production VM AIR adapters and build-generated evaluation.

use alloc::{borrow::Cow, vec::Vec};

use miden_air_definitions::{self as definitions, lookup};
use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_lifted_air::{BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder};

mod degrees {
    use miden_lifted_air::ConstraintDegrees;

    use super::MidenAir;

    include!(concat!(env!("OUT_DIR"), "/degrees.rs"));
}

#[allow(clippy::eq_op)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/evaluators.rs"));
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MidenAir {
    Core,
    Chiplets,
    EidosCompression,
    And8Lookup,
}

impl MidenAir {
    pub const CORE: Self = Self::Core;
    pub const CHIPLETS: Self = Self::Chiplets;
    pub const EIDOS_COMPRESSION: Self = Self::EidosCompression;
    pub const AND8_LOOKUP: Self = Self::And8Lookup;

    pub const fn instance_index(self) -> usize {
        self.definition().instance_index()
    }

    pub const fn name(self) -> &'static str {
        self.definition().name()
    }

    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    ///
    /// Available without naming a lookup builder, so callers that only need the shape — such as
    /// the security estimator — do not have to pick an unrelated builder type to read it.
    pub fn column_shape(self) -> &'static [usize] {
        self.definition().column_shape()
    }

    pub const fn file_token(self) -> &'static str {
        self.definition().file_token()
    }

    /// Evaluate the hand-written constraint definitions.
    ///
    /// [`LiftedAir::eval`] runs the generated evaluators instead; use this entry
    /// point (via [`HandwrittenMidenAir`](crate::HandwrittenMidenAir) where an AIR value is
    /// expected) when the hand-written source itself is required — capturing the AIRs the build
    /// specializes, or checking the generated evaluators for drift.
    pub fn eval_handwritten<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        LiftedAir::<Felt, miden_core::field::QuadFelt>::eval(&self.definition(), builder)
    }

    pub const fn from_definition(air: definitions::MidenAir) -> Self {
        match air {
            definitions::MidenAir::Core => Self::Core,
            definitions::MidenAir::Chiplets => Self::Chiplets,
            definitions::MidenAir::EidosCompression => Self::EidosCompression,
            definitions::MidenAir::And8Lookup => Self::And8Lookup,
        }
    }

    pub const fn definition(self) -> definitions::MidenAir {
        match self {
            Self::Core => definitions::MidenAir::Core,
            Self::Chiplets => definitions::MidenAir::Chiplets,
            Self::EidosCompression => definitions::MidenAir::EidosCompression,
            Self::And8Lookup => definitions::MidenAir::And8Lookup,
        }
    }
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        self.definition().width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.definition().preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.definition().preprocessed_width()
    }

    fn num_public_values(&self) -> usize {
        BaseAir::<Felt>::num_public_values(&self.definition())
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.definition().periodic_columns().into_owned().into()
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
    fn num_randomness(&self) -> usize {
        LiftedAir::<Felt, EF>::num_randomness(&self.definition())
    }

    fn aux_width(&self) -> usize {
        LiftedAir::<Felt, EF>::aux_width(&self.definition())
    }

    fn num_aux_values(&self) -> usize {
        LiftedAir::<Felt, EF>::num_aux_values(&self.definition())
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.definition().build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.definition().build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        degrees::generated_degrees(*self)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core => generated::eval_core(builder),
            Self::Chiplets => generated::eval_chiplets(builder),
            Self::EidosCompression => generated::eval_eidos_compression(builder),
            Self::And8Lookup => generated::eval_and8_lookup(builder),
        }
    }
}

impl<LB> lookup::LookupAir<LB> for MidenAir
where
    LB: lookup::LookupBuilder<F = Felt>,
    definitions::MidenAir: lookup::LookupAir<LB>,
{
    fn column_shape(&self) -> &[usize] {
        MidenAir::column_shape(*self)
    }

    fn max_message_width(&self) -> usize {
        <definitions::MidenAir as lookup::LookupAir<LB>>::max_message_width(&self.definition())
    }

    fn num_bus_ids(&self) -> usize {
        <definitions::MidenAir as lookup::LookupAir<LB>>::num_bus_ids(&self.definition())
    }

    fn eval(&self, builder: &mut LB) {
        <definitions::MidenAir as lookup::LookupAir<LB>>::eval(&self.definition(), builder)
    }

    fn eval_boundary<B>(&self, builder: &mut B)
    where
        B: lookup::BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        <definitions::MidenAir as lookup::LookupAir<LB>>::eval_boundary(&self.definition(), builder)
    }
}
