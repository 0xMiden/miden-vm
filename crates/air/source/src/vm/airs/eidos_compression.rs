//! Authored Eidos compression AIR constraints and lookup bindings.

use alloc::borrow::Cow;
use core::borrow::Borrow;

use miden_core::{Felt, field::ExtensionField};
use miden_stark::{
    air::{self, ReductionError},
    lookup::{self, Challenges},
};

use crate::vm::{
    constraints::eidos_compression::{
        EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS,
        constraints::{
            enforce_footer_rows, enforce_fused_rows, enforce_inactive_footer_input_aux,
            enforce_inactive_footer_output_aux,
        },
        layout::{AUX_COLS, AUX_REGISTER_COL},
        lookup::{EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, emit_lookup_columns},
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

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }
}

impl air::LiftedAir for EidosCompressionAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_EIDOS_COMPRESSION_COLS,
            aux_width: AUX_COLS,
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(get_periodic_column_values()),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
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
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for EidosCompressionAir {
    fn column_shape(&self) -> &[usize] {
        &EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let local: &EidosCompressionCols<_> = frame.main.current.borrow();
        let next: &EidosCompressionCols<_> = frame.main.next.borrow();
        let selectors = EidosCompressionSelectors::new(frame.periodic, 0);
        emit_lookup_columns(builder, local, next, &selectors);
    }
}
