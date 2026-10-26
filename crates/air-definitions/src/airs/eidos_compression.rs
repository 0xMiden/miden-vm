//! VM Eidos compression constraints and lookup wiring.

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{Felt, field::ExtensionField};
use miden_lifted_air::{ReductionError, WindowAccess};

use super::{MidenAir, MidenAirBuilder};
use crate::{
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{BoundaryBuilder, Challenges, ConstraintLookupBuilder},
    shared::eidos_compression::{
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

    pub(crate) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        get_periodic_column_values()
    }

    pub(super) fn aux_width(self) -> usize {
        EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len()
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
        let main = builder.main();
        let local: &EidosCompressionCols<_> = main.current_slice().borrow();
        let next: &EidosCompressionCols<_> = main.next_slice().borrow();
        let periodic_values: Vec<LB::Expr> =
            builder.periodic_values().iter().map(|value| (*value).into()).collect();
        let selectors = EidosCompressionSelectors::new(&periodic_values, 0);

        emit_lookup_columns(builder, local, next, &selectors);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}
