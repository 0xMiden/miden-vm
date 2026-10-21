//! Production AIR evaluators and proof protocol for the Miden VM.
//!
//! Authored constraints and trace layouts live in [`miden_air_source::vm`]. This module
//! combines their metadata and lookup construction with build-generated native evaluators.

use alloc::{borrow::Cow, vec::Vec};

use miden_air_source::vm as source;
pub use miden_air_source::vm::{NUM_PUBLIC_VALUES, PublicInputs};
pub use miden_core::{Felt, serde::DeserializationError};
use miden_core::{field::ExtensionField, utils::RowMajorMatrix};
pub use miden_stark::{
    StarkConfig,
    air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement,
    },
    debug,
    pcs::PcsParams,
};
use miden_stark::{air::ReductionError, lookup};
use p3_challenger::CanObserve;

pub mod ace;
pub mod config;
mod proof_order;
pub mod security;
pub use proof_order::{AIRS, MIDEN_AIR_COUNT, PROOF_ORDER_COUNT, ProofOrder};

include!(concat!(env!("OUT_DIR"), "/degrees.rs"));
#[allow(clippy::eq_op)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/evaluators.rs"));
}

/// Production evaluator for an authored VM AIR.
///
/// Constraint evaluation and degrees use build-generated code. Trace metadata, auxiliary-trace
/// construction, and lookup interactions delegate to the authored definition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MidenAir(pub source::MidenAir);

impl MidenAir {
    pub const CORE: Self = Self(source::MidenAir::CORE);
    pub const CHIPLETS: Self = Self(source::MidenAir::CHIPLETS);
    pub const EIDOS_COMPRESSION: Self = Self(source::MidenAir::EIDOS_COMPRESSION);
    pub const AND8_LOOKUP: Self = Self(source::MidenAir::AND8_LOOKUP);

    pub const fn instance_index(self) -> usize {
        self.0.instance_index()
    }
    pub const fn name(self) -> &'static str {
        self.0.name()
    }
    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    ///
    /// Available without naming a lookup builder, so callers that only need the shape — such as
    /// the security estimator — do not have to pick an unrelated builder type to read it.
    pub fn column_shape(self) -> &'static [usize] {
        self.0.column_shape()
    }

    pub const fn file_token(self) -> &'static str {
        self.0.file_token()
    }
}

impl BaseAir<Felt> for MidenAir {
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
impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
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
        generated_degrees(*self)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self.0 {
            source::MidenAir::Core => generated::eval_core(builder),
            source::MidenAir::Chiplets => generated::eval_chiplets(builder),
            source::MidenAir::EidosCompression => generated::eval_eidos_compression(builder),
            source::MidenAir::And8Lookup => generated::eval_and8_lookup(builder),
        }
    }
}

impl<LB> lookup::LookupAir<LB> for MidenAir
where
    LB: lookup::LookupBuilder<F = Felt>,
    source::MidenAir: lookup::LookupAir<LB>,
{
    fn column_shape(&self) -> &[usize] {
        MidenAir::column_shape(*self)
    }
    fn max_message_width(&self) -> usize {
        <source::MidenAir as lookup::LookupAir<LB>>::max_message_width(&self.0)
    }
    fn num_bus_ids(&self) -> usize {
        <source::MidenAir as lookup::LookupAir<LB>>::num_bus_ids(&self.0)
    }
    fn eval(&self, builder: &mut LB) {
        <source::MidenAir as lookup::LookupAir<LB>>::eval(&self.0, builder)
    }
    fn eval_boundary<B>(&self, builder: &mut B)
    where
        B: lookup::BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        <source::MidenAir as lookup::LookupAir<LB>>::eval_boundary(&self.0, builder)
    }
}
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
        <source::MidenMultiAir as MultiAir<Felt, EF>>::max_aux_inputs(&source::MidenMultiAir)
    }
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        heights: &[u8],
    ) {
        <source::MidenMultiAir as MultiAir<Felt, EF>>::observe(
            &source::MidenMultiAir,
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
        source::MidenMultiAir.eval_external(challenges, air_inputs, aux_inputs, aux_values, heights)
    }
}
