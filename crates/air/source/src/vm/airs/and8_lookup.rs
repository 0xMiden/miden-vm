//! Authored byte-pair lookup AIR constraints and lookup bindings.

use alloc::borrow::Cow;

use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{ReductionError, native},
    lookup::{Challenges, native as native_lookup},
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

impl native::LiftedAir for And8LookupAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: and8_lookup::columns::NUM_AND8_LOOKUP_COLS,
            aux_width: constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len(),
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: Some(native::PreprocessedSpec {
                width: and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS,
                log_height: and8_lookup::columns::LOG_AND8_LOOKUP_TRACE_HEIGHT,
            }),
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(self.preprocessed_trace())
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        native_lookup::eval_lookup(self, frame, inputs, sink);
    }
}

impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB> for And8LookupAir {
    fn column_shape(&self) -> &[usize] {
        &constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        constraints::lookup::and8_lookup_air::emit_and8_lookup_columns(frame, builder);
    }
}

impl<EF: ExtensionField<Felt>> native::ProverAir<EF> for And8LookupAir {
    type Error = native_lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, EF>,
    ) -> Result<native::AuxTrace<EF>, Self::Error> {
        native_lookup::build_logup_aux_trace(self, inputs)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{air::native, lookup::native::LookupError};

    use super::And8LookupAir;

    #[test]
    fn native_table_capture_declares_fixed_shape_without_building_the_table() {
        // Capture allocates two symbolic rows in each declared namespace, independent of the
        // fixed matrix height. Its factory is exclusively the explicit setup capability.
        let captured = native::capture_with::<_, QuadFelt>(&And8LookupAir).unwrap();
        let spec = captured.descriptor.spec();
        assert_eq!(spec.main_width, 7);
        assert_eq!(spec.aux_width, 4);
        assert_eq!(spec.num_public_values, 0);
        assert_eq!(spec.num_challenges, 2);
        assert_eq!(spec.num_exports, 1);
        assert_eq!(spec.preprocessed, Some(native::PreprocessedSpec { width: 5, log_height: 16 }));
        assert!(spec.periodic_columns.is_empty());
        assert_eq!(captured.descriptor.analysis().counts().base, 0);
        assert_eq!(captured.descriptor.analysis().counts().ext, 5);
        #[cfg(feature = "std")]
        miden_stark::lookup::native::validate_native(&And8LookupAir, spec).unwrap();
    }

    #[test]
    fn native_table_witness_requires_the_supplied_fixed_cache() {
        let main = RowMajorMatrix::new(vec![Felt::ZERO; 2 * 7], 7);
        let wrong_height = RowMajorMatrix::new(vec![Felt::ZERO; 2 * 5], 5);
        let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
        // Neither missing data nor a short supplied matrix triggers a factory fallback. Setup
        // must supply the declared log16 table matching the full multiplicity trace height.
        for preprocessed in [None, Some(&wrong_height)] {
            let result = native::ProverAir::build_aux_trace(
                &And8LookupAir,
                native::AuxTraceInputs {
                    main: &main,
                    preprocessed,
                    public_values: &[],
                    statement: &[],
                    challenges: &challenges,
                },
            );
            assert!(matches!(result, Err(LookupError::PreprocessedShape)));
        }
    }
}
