//! Authored byte-pair lookup AIR constraints and lookup bindings.

use alloc::borrow::Cow;

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{self, ReductionError},
    lookup::{self, Challenges},
};

use crate::vm::{
    constraints::{self, and8_lookup},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// BYTE-PAIR LOOKUP AIR
// ================================================================================================

/// Standalone byte-AND and range lookup-table AIR.
#[derive(Copy, Clone, Debug, Default)]
pub struct And8LookupAir;

impl And8LookupAir {
    pub(super) fn preprocessed_trace(self) -> RowMajorMatrix<Felt> {
        and8_lookup::preprocessed_trace()
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

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }
}

impl air::LiftedAir for And8LookupAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: and8_lookup::columns::NUM_AND8_LOOKUP_COLS,
            aux_width: constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len(),
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: Some(air::PreprocessedSpec {
                width: and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS,
                log_height: and8_lookup::columns::LOG_AND8_LOOKUP_TRACE_HEIGHT,
            }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed_trace())
    }

    fn eval<B: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, B>,
        inputs: air::Inputs<'_, B>,
        sink: &mut B,
    ) {
        lookup::eval_lookup(self, frame, inputs, sink);
    }
}

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for And8LookupAir {
    fn column_shape(&self) -> &[usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        constraints::lookup::and8_lookup_air::emit_and8_lookup_columns(frame, builder);
    }
}

impl<EF: ExtensionField<Felt>> air::ProverAir<EF> for And8LookupAir {
    type Error = lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, EF>,
    ) -> Result<air::AuxTrace<EF>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}
