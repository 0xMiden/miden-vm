//! Production VM AIR. Evaluation uses the staged optimized Rust artifact; statement, fixed-data,
//! and auxiliary-trace semantics are delegated to the independent authored relation.

use alloc::{borrow::Cow, vec::Vec};

use miden_air_source::vm as source;
use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{
        BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, MultiAir as MultiAirTrait,
        ReductionError,
    },
    challenger::CanObserve,
    lookup::{BoundaryBuilder, LookupAir, LookupBuilder},
};

mod generated;
mod proof_order;
pub use proof_order::{AIRS, MIDEN_AIR_COUNT, PROOF_ORDER_COUNT, ProofOrder};
pub use source::PublicInputs;

/// A production VM AIR instance in the protocol's stable instance order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Air {
    Core,
    Chiplets,
    EidosCompression,
    And8Lookup,
}

impl Air {
    pub const CORE: Self = Self::Core;
    pub const CHIPLETS: Self = Self::Chiplets;
    pub const EIDOS_COMPRESSION: Self = Self::EidosCompression;
    pub const AND8_LOOKUP: Self = Self::And8Lookup;

    /// The independent authored relation with the same instance identity.
    pub const fn source(self) -> source::Air {
        match self {
            Self::Core => source::Air::Core,
            Self::Chiplets => source::Air::Chiplets,
            Self::EidosCompression => source::Air::EidosCompression,
            Self::And8Lookup => source::Air::And8Lookup,
        }
    }

    pub const fn instance_index(self) -> usize {
        self.source().instance_index()
    }
    pub const fn name(self) -> &'static str {
        self.source().name()
    }
    pub const fn file_token(self) -> &'static str {
        self.source().file_token()
    }
    pub fn column_shape(self) -> &'static [usize] {
        self.source().column_shape()
    }
}

impl From<source::Air> for Air {
    fn from(air: source::Air) -> Self {
        match air {
            source::Air::Core => Self::Core,
            source::Air::Chiplets => Self::Chiplets,
            source::Air::EidosCompression => Self::EidosCompression,
            source::Air::And8Lookup => Self::And8Lookup,
        }
    }
}

impl From<Air> for source::Air {
    fn from(air: Air) -> Self {
        air.source()
    }
}

impl BaseAir<Felt> for Air {
    fn width(&self) -> usize {
        self.source().width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.source().preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.source().preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.source().num_public_values()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(self.source().periodic_columns().into_owned())
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for Air {
    fn max_periodic_length(&self) -> usize {
        <source::Air as LiftedAir<Felt, EF>>::max_periodic_length(&self.source())
    }
    fn num_randomness(&self) -> usize {
        <source::Air as LiftedAir<Felt, EF>>::num_randomness(&self.source())
    }
    fn aux_width(&self) -> usize {
        <source::Air as LiftedAir<Felt, EF>>::aux_width(&self.source())
    }
    fn num_aux_values(&self) -> usize {
        <source::Air as LiftedAir<Felt, EF>>::num_aux_values(&self.source())
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.source().build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.source().build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }
    fn constraint_degree(&self) -> ConstraintDegrees {
        <source::Air as LiftedAir<Felt, EF>>::constraint_degree(&self.source())
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

impl<LB: LookupBuilder> LookupAir<LB> for Air
where
    source::Air: LookupAir<LB>,
{
    fn column_shape(&self) -> &[usize] {
        Air::column_shape(*self)
    }
    fn max_message_width(&self) -> usize {
        <source::Air as LookupAir<LB>>::max_message_width(&self.source())
    }
    fn num_bus_ids(&self) -> usize {
        <source::Air as LookupAir<LB>>::num_bus_ids(&self.source())
    }
    fn eval(&self, builder: &mut LB) {
        LookupAir::eval(&self.source(), builder)
    }
    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        <source::Air as LookupAir<LB>>::eval_boundary(&self.source(), boundary)
    }
}

/// Production VM collection, carrying the authored statement's exact observation and reduction.
#[derive(Copy, Clone, Debug, Default)]
pub struct MultiAir;
impl MultiAir {
    pub const fn new() -> Self {
        Self
    }
}

impl<EF: ExtensionField<Felt>> MultiAirTrait<Felt, EF> for MultiAir {
    type Air = Air;
    fn airs(&self) -> &[Air] {
        &AIRS
    }
    fn num_air_inputs(&self) -> usize {
        <source::MultiAir as MultiAirTrait<Felt, EF>>::num_air_inputs(&source::MultiAir)
    }
    fn max_aux_inputs(&self) -> usize {
        <source::MultiAir as MultiAirTrait<Felt, EF>>::max_aux_inputs(&source::MultiAir)
    }
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        log_trace_heights: &[u8],
    ) {
        <source::MultiAir as MultiAirTrait<Felt, EF>>::observe(
            &source::MultiAir,
            challenger,
            air_inputs,
            aux_inputs,
            log_trace_heights,
        );
    }
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        source::MultiAir.eval_external(
            challenges,
            air_inputs,
            aux_inputs,
            aux_values,
            log_trace_heights,
        )
    }
}

pub use crate::config;
pub mod ace;
pub mod artifacts;
