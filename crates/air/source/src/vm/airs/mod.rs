//! Authored VM AIR contracts and canonical instance dispatch.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, ReductionError, native},
    lookup::{
        BoundaryBuilder, Challenges, LookupAir, build_logup_aux_trace_with_preprocessed,
        native as native_lookup,
    },
};
use p3_field::Algebra;

use crate::vm::{
    constraints::{
        eidos_compression::lookup::EidosCompressionLookupBuilder,
        lookup::{
            and8_lookup_air::And8LookupBuilder,
            chiplet_air::{ChipletLookupBuilder, NativeChipletLookupBuilder},
            main_air::{MainLookupBuilder, NativeMainLookupBuilder},
        },
    },
    inputs::{AUX_KERNEL_DIGESTS, NUM_PUBLIC_VALUES},
    trace,
};

mod and8_lookup;
mod boundary;
mod chiplets;
mod core_air;
mod eidos_compression;

pub use and8_lookup::And8LookupAir;
pub use chiplets::ChipletsAir;
pub use core_air::CoreAir;
pub use eidos_compression::EidosCompressionAir;

// MIDEN AIR BUILDER
// ================================================================================================

/// Convenience super-trait that pins `LiftedAirBuilder` to the Miden base field.
///
/// Constraint functions use `AB: MidenAirBuilder` instead of the longer
/// `LiftedAirBuilder<F = Felt>` bound.
pub trait MidenAirBuilder: LiftedAirBuilder<F = Felt> {}
impl<T: LiftedAirBuilder<F = Felt>> MidenAirBuilder for T {}

/// Assertion sink over Miden expressions for helpers with separate immutable inputs.
pub trait NativeMidenAirBuilder: miden_stark::air::native::LiftedAirBuilder<F = Felt> {}
impl<T: miden_stark::air::native::LiftedAirBuilder<F = Felt>> NativeMidenAirBuilder for T {}

/// Combined LogUp width used by constraint test harnesses: 4 core columns, 4 chiplet
/// columns, and the byte-pair table column. Standalone Eidos compression tests size their aux
/// matrix from the AIR directly.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 9;

// MIDEN AIR
// ================================================================================================

/// AIR instance identifier for the Miden multi-AIR statement.
///
/// [`MultiAir::Air`](miden_stark::air::MultiAir) is a single associated type, so every
/// instance in the multi-AIR proof must have the same type. This enum identifies which concrete
/// AIR logic to dispatch to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MidenAir {
    Core,
    Chiplets,
    EidosCompression,
    And8Lookup,
}

macro_rules! with_source {
    ($self:ident, |$air:ident| $body:expr) => {
        match $self {
            MidenAir::Core => {
                let $air = &CoreAir;
                $body
            },
            MidenAir::Chiplets => {
                let $air = &ChipletsAir;
                $body
            },
            MidenAir::EidosCompression => {
                let $air = &EidosCompressionAir;
                $body
            },
            MidenAir::And8Lookup => {
                let $air = &And8LookupAir;
                $body
            },
        }
    };
}

impl native::LiftedAir for MidenAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        with_source!(self, |air| native::LiftedAir::spec(air))
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        with_source!(self, |air| native::LiftedAir::build_preprocessed_trace(air))
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        with_source!(self, |air| native::LiftedAir::eval(air, frame, inputs, sink));
    }
}

impl<EF: ExtensionField<Felt>> native::ProverAir<EF> for MidenAir {
    type Error = crate::shared::WitnessError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, EF>,
    ) -> Result<native::AuxTrace<EF>, Self::Error> {
        with_source!(self, |air| native::ProverAir::build_aux_trace(air, inputs)
            .map_err(Into::into))
    }
}

impl<LB: NativeMainLookupBuilder + NativeChipletLookupBuilder> native_lookup::LookupAir<LB>
    for MidenAir
{
    fn column_shape(&self) -> &[usize] {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::column_shape(air))
    }

    fn max_message_width(&self) -> usize {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::max_message_width(air))
    }

    fn num_bus_ids(&self) -> usize {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::num_bus_ids(air))
    }

    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::eval(air, frame, builder));
    }

    fn eval_boundary<B: BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::eval_boundary(air, boundary));
    }
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
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

    fn log_preprocessed_height(&self) -> Option<u8> {
        match self {
            Self::And8Lookup => Some(trace::and8_lookup::LOG_AND8_LOOKUP_TRACE_HEIGHT),
            Self::Core | Self::Chiplets | Self::EidosCompression => None,
        }
    }

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
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let (aux, sums) = if *self == Self::EidosCompression {
            let aux =
                <EidosCompressionAir as miden_stark::air::native::ProverAir<EF>>::build_aux_trace(
                    &EidosCompressionAir,
                    miden_stark::air::native::AuxTraceInputs {
                        main,
                        preprocessed,
                        public_values: air_inputs,
                        statement: aux_inputs,
                        challenges,
                    },
                )
                .expect("valid Eidos compression auxiliary inputs");
            (aux.columns, aux.exports)
        } else {
            build_logup_aux_trace_with_preprocessed(self, main, preprocessed, challenges)
        };
        debug_assert_eq!(
            sums.len(),
            1,
            "build_logup_aux_trace returns one normalized LogUp sum per AIR"
        );
        (aux, sums)
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        ConstraintDegrees::from_air::<Felt, EF, _>(self)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
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
