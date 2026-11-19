//! Authored VM AIR contracts and canonical instance dispatch.

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{self, ReductionError},
    lookup::{self, BoundaryBuilder, Challenges},
};

use crate::vm::{
    constraints::lookup::{
        chiplet_air::NativeChipletLookupBuilder, main_air::NativeMainLookupBuilder,
    },
    inputs::AUX_KERNEL_DIGESTS,
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

/// Assertion sink over Miden expressions for helpers with separate immutable inputs.
pub trait NativeMidenAirBuilder: miden_stark::air::LiftedAirBuilder<F = Felt> {}
impl<T: miden_stark::air::LiftedAirBuilder<F = Felt>> NativeMidenAirBuilder for T {}

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
    ($self:ident, | $air:ident | $body:expr) => {
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

impl air::LiftedAir for MidenAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        with_source!(self, |air| air::LiftedAir::spec(air))
    }

    fn eval<B: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, B>,
        inputs: air::Inputs<'_, B>,
        sink: &mut B,
    ) {
        with_source!(self, |air| air::LiftedAir::eval(air, frame, inputs, sink));
    }
}

impl<LB: NativeMainLookupBuilder + NativeChipletLookupBuilder> lookup::LookupAir<LB> for MidenAir {
    fn column_shape(&self) -> &[usize] {
        with_source!(self, |air| lookup::LookupAir::<LB>::column_shape(air))
    }

    fn max_message_width(&self) -> usize {
        with_source!(self, |air| lookup::LookupAir::<LB>::max_message_width(air))
    }

    fn num_bus_ids(&self) -> usize {
        with_source!(self, |air| lookup::LookupAir::<LB>::num_bus_ids(air))
    }

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        with_source!(self, |air| lookup::LookupAir::<LB>::eval(air, frame, builder));
    }

    fn eval_boundary<B: BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        with_source!(self, |air| lookup::LookupAir::<LB>::eval_boundary(air, boundary));
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
