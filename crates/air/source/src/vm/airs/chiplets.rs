//! Authored Chiplets AIR constraints and lookup bindings.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use miden_core::{Felt, WORD_SIZE, field::ExtensionField};
use miden_stark::{
    air::{self, ReductionError},
    lookup::{self, BoundaryBuilder, Challenges},
};

use super::boundary::ReduceBoundaryBuilder;
use crate::vm::{
    constraints::{self, columns::ChipletCols, lookup::chiplet_air::NativeChipletLookupBuilder},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// CHIPLETS AIR
// ================================================================================================

/// Chiplets trace AIR.
///
/// Enforces the chiplet selector hierarchy, chiplet transition constraints, and
/// chiplet-side LogUp buses.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    pub(in crate::vm) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    /// LogUp boundary correction for the chiplets trace.
    ///
    /// The boundary input slice contains the kernel-procedure digests; these statement values
    /// close the kernel-ROM bus.
    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
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

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }
}

impl air::LiftedAir for ChipletsAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: constraints::columns::NUM_CHIPLETS_COLS,
            aux_width: constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len(),
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(self.periodic_columns()),
        }
    }

    fn eval<B: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, B>,
        inputs: air::Inputs<'_, B>,
        sink: &mut B,
    ) {
        let local: &ChipletCols<B::Expr> = frame.main.current.borrow();
        let next: &ChipletCols<B::Expr> = frame.main.next.borrow();
        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(frame, sink, local, next);
        constraints::enforce_chiplets(frame, sink, local, next, &selectors);
        lookup::eval_lookup(self, frame, inputs, sink);
    }
}

impl<LB: NativeChipletLookupBuilder> lookup::LookupAir<LB> for ChipletsAir {
    fn column_shape(&self) -> &[usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(frame, builder);
    }
    fn eval_boundary<B: BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

impl<EF: ExtensionField<Felt>> air::ProverAir<EF> for ChipletsAir {
    type Error = lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, EF>,
    ) -> Result<air::AuxTrace<EF>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::QuadFelt;
    use miden_stark::air;

    use super::ChipletsAir;

    #[test]
    fn ordinary_constraints_precede_lookup_assertions() {
        let captured = air::capture_with::<_, QuadFelt>(&ChipletsAir).unwrap();
        let layout = captured.descriptor.analysis().layout();
        assert!(layout.base_indices().iter().copied().eq(0..172));
        assert!(layout.ext_indices().iter().copied().eq(172..177));
    }
}
