//! Authored VM AIR implementations and canonical per-instance dispatch.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use miden_core::{Felt, WORD_SIZE, field::ExtensionField, utils::RowMajorMatrix};
use miden_lifted_stark::air::{
    BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, ReductionError, WindowAccess,
};

use crate::{
    boundary::ReduceBoundaryBuilder,
    constraints::{
        self, and8_lookup,
        and8_lookup::columns::And8LookupCols,
        columns::{ChipletCols, CoreCols},
        eidos_compression::{
            EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS,
            constraints::{
                enforce_footer_rows, enforce_fused_rows, enforce_inactive_footer_input_aux,
                enforce_inactive_footer_output_aux,
            },
            lookup::{
                EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionLookupBuilder,
                emit_lookup_columns,
            },
            periodic::get_periodic_column_values,
            selectors::EidosCompressionSelectors,
        },
        lookup::{
            and8_lookup_air::And8LookupBuilder,
            chiplet_air::ChipletLookupBuilder,
            main_air::{MainLookupAir, MainLookupBuilder},
        },
    },
    inputs::{AUX_KERNEL_DIGESTS, NUM_PUBLIC_VALUES},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        BoundaryBuilder, Challenges, ConstraintLookupBuilder, LookupAir,
        build_logup_aux_trace_with_preprocessed,
    },
    trace,
};

// MIDEN AIR BUILDER
// ================================================================================================

/// Convenience super-trait that pins `LiftedAirBuilder` to the Miden base field.
///
/// Constraint functions use `AB: MidenAirBuilder` instead of the longer
/// `LiftedAirBuilder<F = Felt>` bound.
pub trait MidenAirBuilder: LiftedAirBuilder<F = Felt> {}
impl<T: LiftedAirBuilder<F = Felt>> MidenAirBuilder for T {}

/// Combined LogUp width used by constraint test harnesses: 4 core columns, 4 chiplet
/// columns, and the byte-pair table column. Standalone Eidos compression tests size their aux
/// matrix from the AIR directly.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 9;

// CORE AIR
// ================================================================================================

/// Core trace AIR.
///
/// Enforces the system, decoder, stack, and range-check constraints.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoreAir;

impl CoreAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CORE_COLS
    }

    fn periodic_columns(self) -> Vec<Vec<Felt>> {
        Vec::new()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the core trace: the running sum of every
    /// boundary interaction reduced to its denominator contribution. The single var-len slice
    /// carries `[program_hash (4) | deferred_root (4)]`, the statement inputs the core
    /// boundary cancels against the block-hash and log-deferred buses.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "CoreAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if boundary_inputs[0].len() != 2 * WORD_SIZE {
            return Err(format!(
                "CoreAir expects {} boundary felts (program hash + deferred root), got {}",
                2 * WORD_SIZE,
                boundary_inputs[0].len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            var_len_public_inputs: boundary_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_core_boundary(&mut reducer);
        reducer.finalize()
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let main = builder.main();
        let local: &CoreCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &CoreCols<AB::Var> = (*main.next_slice()).borrow();

        let op_flags =
            constraints::op_flags::OpFlags::new(&local.decoder, &local.stack, &next.decoder);

        constraints::enforce_core(builder, local, next, &op_flags);
        constraints::public_inputs::enforce_main(builder, local);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Core);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::main_air::MAIN_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: MainLookupBuilder>(self, builder: &mut LB) {
        MainLookupAir.eval(builder);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_core_boundary(boundary);
    }
}

// CHIPLETS AIR
// ================================================================================================

/// Chiplets trace AIR.
///
/// Enforces the chiplet selector hierarchy, chiplet transition constraints, and
/// chiplet-side LogUp buses.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    pub(super) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the chiplets trace.
    ///
    /// The boundary input slice contains the kernel-procedure digests; these statement values
    /// close the kernel-ROM bus.
    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "ChipletsAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if !boundary_inputs[0].len().is_multiple_of(WORD_SIZE) {
            return Err(format!(
                "kernel digest felts length {} is not a multiple of {}",
                boundary_inputs[0].len(),
                WORD_SIZE
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            var_len_public_inputs: boundary_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_chiplets_boundary(&mut reducer);
        reducer.finalize()
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let main = builder.main();
        let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &ChipletCols<AB::Var> = (*main.next_slice()).borrow();

        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);

        constraints::enforce_chiplets(builder, local, next, &selectors);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Chiplets);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: ChipletLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();

        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(builder, local, next);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

// EIDOS COMPRESSION AIR
// ================================================================================================

/// Standalone Eidos compression AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct EidosCompressionAir;

impl EidosCompressionAir {
    fn width(self) -> usize {
        NUM_EIDOS_COMPRESSION_COLS
    }

    pub(super) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }

    fn aux_width(self) -> usize {
        EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !boundary_inputs.is_empty() {
            return Err(format!(
                "EidosCompressionAir expects 0 boundary input slices, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let periodic_values: Vec<AB::Expr> =
                builder.periodic_values().iter().map(|value| (*value).into()).collect();
            let selectors = EidosCompressionSelectors::new(&periodic_values, 0);

            enforce_fused_rows(builder, local, next, &selectors);
            enforce_footer_rows(builder, local, next, &selectors);
            enforce_inactive_footer_input_aux(builder, &selectors);
            enforce_inactive_footer_output_aux(builder, local, &selectors);
        }
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::EidosCompression);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: EidosCompressionLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &EidosCompressionCols<_> = main.current_slice().borrow();
        let next: &EidosCompressionCols<_> = main.next_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);

        emit_lookup_columns(builder, local, next, &selectors);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

// BYTE-PAIR LOOKUP AIR
// ================================================================================================

/// Standalone byte-AND and range lookup-table AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct And8LookupAir;

impl And8LookupAir {
    fn width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_COLS
    }

    fn preprocessed_trace(self) -> RowMajorMatrix<Felt> {
        and8_lookup::preprocessed_trace()
    }

    fn preprocessed_width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS
    }

    fn aux_width(self) -> usize {
        constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        _challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if !boundary_inputs.is_empty() {
            return Err(format!(
                "And8LookupAir expects 0 boundary input slices, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        Ok(EF::ZERO)
    }

    fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::And8Lookup);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }

    fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    fn lookup_eval<LB: And8LookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &And8LookupCols<_> = main.current_slice().borrow();
        constraints::lookup::and8_lookup_air::emit_and8_lookup_columns(builder, local);
    }

    fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

// MIDEN AIR
// ================================================================================================

/// AIR instance identifier for the Miden multi-AIR statement.
///
/// [`MultiAir::Air`](miden_lifted_stark::air::MultiAir) is a single associated type, so every
/// instance in the multi-AIR proof must have the same type. This enum identifies which concrete
/// AIR logic to dispatch to.
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
        match self {
            Self::Core => 0,
            Self::Chiplets => 1,
            Self::EidosCompression => 2,
            Self::And8Lookup => 3,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Core => "Core",
            Self::Chiplets => "Chiplets",
            Self::EidosCompression => "EidosCompression",
            Self::And8Lookup => "And8Lookup",
        }
    }

    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    ///
    /// Available without naming a lookup builder, so callers that only need the shape — such as
    /// the security estimator — do not have to pick an unrelated builder type to read it.
    pub fn column_shape(self) -> &'static [usize] {
        match self {
            Self::Core => CoreAir.lookup_column_shape(),
            Self::Chiplets => ChipletsAir.lookup_column_shape(),
            Self::EidosCompression => EidosCompressionAir.lookup_column_shape(),
            Self::And8Lookup => And8LookupAir.lookup_column_shape(),
        }
    }

    pub const fn file_token(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Chiplets => "chiplets",
            Self::EidosCompression => "eidos_compression",
            Self::And8Lookup => "and8_lookup",
        }
    }

    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        aux_inputs: &[Felt],
    ) -> Result<EF, ReductionError> {
        if aux_inputs.len() < AUX_KERNEL_DIGESTS {
            return Err(format!(
                "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
                aux_inputs.len()
            )
            .into());
        }

        match self {
            Self::Core => {
                CoreAir.boundary_correction(challenges, &[&aux_inputs[..AUX_KERNEL_DIGESTS]])
            },
            Self::Chiplets => {
                ChipletsAir.boundary_correction(challenges, &[&aux_inputs[AUX_KERNEL_DIGESTS..]])
            },
            Self::EidosCompression => EidosCompressionAir.boundary_correction(challenges, &[]),
            Self::And8Lookup => And8LookupAir.boundary_correction(challenges, &[]),
        }
    }
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        match self {
            Self::Core => CoreAir.width(),
            Self::Chiplets => ChipletsAir.width(),
            Self::EidosCompression => EidosCompressionAir.width(),
            Self::And8Lookup => And8LookupAir.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        match self {
            Self::And8Lookup => Some(And8LookupAir.preprocessed_trace()),
            Self::Core | Self::Chiplets | Self::EidosCompression => None,
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::And8Lookup => And8LookupAir.preprocessed_width(),
            Self::Core | Self::Chiplets | Self::EidosCompression => 0,
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Core => NUM_PUBLIC_VALUES,
            Self::Chiplets | Self::EidosCompression | Self::And8Lookup => 0,
        }
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(match self {
            Self::Core => CoreAir.periodic_columns(),
            Self::Chiplets => ChipletsAir.periodic_columns(),
            Self::EidosCompression => EidosCompressionAir.periodic_columns(),
            Self::And8Lookup => Vec::new(),
        })
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
    fn num_randomness(&self) -> usize {
        // Instance-level: every AIR shares the same LogUp challenge set.
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        match self {
            Self::Core => CoreAir.aux_width(),
            Self::Chiplets => ChipletsAir.aux_width(),
            Self::EidosCompression => EidosCompressionAir.aux_width(),
            Self::And8Lookup => And8LookupAir.aux_width(),
        }
    }

    fn num_aux_values(&self) -> usize {
        // One committed normalized LogUp sum `sigma_prime = sigma / n` per AIR instance.
        1
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let preprocessed = self.preprocessed_trace();
        self.build_aux_trace_with_preprocessed(
            main,
            preprocessed.as_ref(),
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let (aux_trace, committed) =
            build_logup_aux_trace_with_preprocessed(self, main, preprocessed, challenges);
        debug_assert_eq!(
            committed.len(),
            1,
            "build_logup_aux_trace returns one normalized LogUp sum per AIR"
        );
        (aux_trace, committed)
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        ConstraintDegrees::from_air::<Felt, EF, _>(self)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::Core => CoreAir.eval(builder),
            Self::Chiplets => ChipletsAir.eval(builder),
            Self::EidosCompression => EidosCompressionAir.eval(builder),
            Self::And8Lookup => And8LookupAir.eval(builder),
        }
    }
}

impl<LB> LookupAir<LB> for MidenAir
where
    LB: MainLookupBuilder
        + ChipletLookupBuilder
        + EidosCompressionLookupBuilder
        + And8LookupBuilder,
{
    fn column_shape(&self) -> &[usize] {
        MidenAir::column_shape(*self)
    }

    fn max_message_width(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_max_message_width(),
            Self::Chiplets => ChipletsAir.lookup_max_message_width(),
            Self::EidosCompression => EidosCompressionAir.lookup_max_message_width(),
            Self::And8Lookup => And8LookupAir.lookup_max_message_width(),
        }
    }

    fn num_bus_ids(&self) -> usize {
        match self {
            Self::Core => CoreAir.lookup_num_bus_ids(),
            Self::Chiplets => ChipletsAir.lookup_num_bus_ids(),
            Self::EidosCompression => EidosCompressionAir.lookup_num_bus_ids(),
            Self::And8Lookup => And8LookupAir.lookup_num_bus_ids(),
        }
    }

    fn eval(&self, builder: &mut LB) {
        match self {
            Self::Core => CoreAir.lookup_eval(builder),
            Self::Chiplets => ChipletsAir.lookup_eval(builder),
            Self::EidosCompression => EidosCompressionAir.lookup_eval(builder),
            Self::And8Lookup => And8LookupAir.lookup_eval(builder),
        }
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        match self {
            Self::Core => CoreAir.lookup_eval_boundary(boundary),
            Self::Chiplets => ChipletsAir.lookup_eval_boundary(boundary),
            Self::EidosCompression => EidosCompressionAir.lookup_eval_boundary(boundary),
            Self::And8Lookup => And8LookupAir.lookup_eval_boundary(boundary),
        }
    }
}
