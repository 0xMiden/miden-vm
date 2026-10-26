//! Byte-pair lookup table constraints and preprocessed trace.

use core::borrow::Borrow;

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_lifted_air::{ReductionError, WindowAccess};

use super::{MidenAir, MidenAirBuilder};
use crate::{
    constraints::{
        self, and8_lookup, and8_lookup::columns::And8LookupCols,
        lookup::and8_lookup_air::And8LookupBuilder,
    },
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{BoundaryBuilder, Challenges, ConstraintLookupBuilder},
};

// BYTE-PAIR LOOKUP AIR
// ================================================================================================

/// Standalone byte-AND and range lookup-table AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct And8LookupAir;

impl And8LookupAir {
    pub(super) fn width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_COLS
    }

    pub(super) fn preprocessed_trace(self) -> RowMajorMatrix<Felt> {
        and8_lookup::preprocessed_trace()
    }

    pub(super) fn preprocessed_width(self) -> usize {
        and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS
    }

    pub(super) fn aux_width(self) -> usize {
        constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len()
    }

    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
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

    pub(super) fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::And8Lookup);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }

    pub(super) fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    pub(super) fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    pub(super) fn lookup_eval<LB: And8LookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &And8LookupCols<_> = main.current_slice().borrow();
        constraints::lookup::and8_lookup_air::emit_and8_lookup_columns(builder, local);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder>(self, _boundary: &mut B) {}
}
