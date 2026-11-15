//! Authored Eidos compression AIR constraints and lookup bindings.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use miden_core::{Felt, field::ExtensionField};
use miden_stark::{
    air::{ReductionError, native},
    lookup::{BoundaryBuilder, Challenges, native as native_lookup},
};

use super::MidenAirBuilder;
use crate::vm::{
    constraints::eidos_compression::{
        EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS,
        constraints::{
            enforce_footer_rows, enforce_fused_rows, enforce_inactive_footer_input_aux,
            enforce_inactive_footer_output_aux,
        },
        layout::{AUX_COLS, AUX_REGISTER_COL},
        lookup::{
            EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionLookupBuilder,
            emit_lookup_columns,
        },
        periodic::get_periodic_column_values,
        selectors::EidosCompressionSelectors,
    },
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// EIDOS COMPRESSION AIR
// ================================================================================================

/// Standalone Eidos compression AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct EidosCompressionAir;

impl EidosCompressionAir {
    pub(super) fn width(self) -> usize {
        NUM_EIDOS_COMPRESSION_COLS
    }

    pub(in crate::vm) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }

    pub(super) fn aux_width(self) -> usize {
        AUX_COLS
    }

    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
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

    pub(super) fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        native::migration::eval_source(&self, builder);
    }

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }

    pub(super) fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    pub(super) fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    pub(super) fn lookup_eval<LB: EidosCompressionLookupBuilder>(self, builder: &mut LB) {
        native::migration::eval_lookup(&self, builder, 0);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}

impl native::LiftedAir for EidosCompressionAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_EIDOS_COMPRESSION_COLS,
            aux_width: AUX_COLS,
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(get_periodic_column_values()),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;
        let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
        enforce_fused_rows(frame, builder, local, next, &selectors);
        enforce_footer_rows(frame, builder, local, next, &selectors);
        enforce_inactive_footer_input_aux(frame, builder, &selectors);
        enforce_inactive_footer_output_aux(frame, builder, local, &selectors);
        crate::shared::eidos::enforce_register_constraints(
            frame,
            inputs,
            builder,
            AUX_REGISTER_COL,
        );
        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl<EF: ExtensionField<Felt>> native::ProverAir<EF> for EidosCompressionAir {
    type Error = crate::shared::eidos::EidosWitnessError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, EF>,
    ) -> Result<native::AuxTrace<EF>, Self::Error> {
        crate::shared::eidos::build_aux_trace(self, inputs, AUX_REGISTER_COL)
    }
}

impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB>
    for EidosCompressionAir
{
    fn column_shape(&self) -> &[usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let local: &EidosCompressionCols<_> = frame.main.current.borrow();
        let next: &EidosCompressionCols<_> = frame.main.next.borrow();
        let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
        emit_lookup_columns(builder, local, next, &selectors);
    }
}
