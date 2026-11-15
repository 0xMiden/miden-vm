//! Authored Chiplets AIR constraints and lookup bindings.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use miden_core::{Felt, WORD_SIZE, field::ExtensionField};
use miden_stark::{
    air::{ReductionError, native},
    lookup::{BoundaryBuilder, Challenges, native as native_lookup},
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

impl native::LiftedAir for ChipletsAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: constraints::columns::NUM_CHIPLETS_COLS,
            aux_width: constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len(),
            num_public_values: 0,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Owned(self.periodic_columns()),
        }
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        let local: &ChipletCols<B::Expr> = frame.main.current.borrow();
        let next: &ChipletCols<B::Expr> = frame.main.next.borrow();
        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(frame, sink, local, next);
        constraints::enforce_chiplets(frame, sink, local, next, &selectors);
        native_lookup::eval_lookup(self, frame, inputs, sink);
    }
}

impl<LB: NativeChipletLookupBuilder> native_lookup::LookupAir<LB> for ChipletsAir {
    fn column_shape(&self) -> &[usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }
    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }
    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }
    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(frame, builder);
    }
    fn eval_boundary<B: BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

impl<EF: ExtensionField<Felt>> native::ProverAir<EF> for ChipletsAir {
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
    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{
        air::native,
        lookup::{Challenges, accumulate_slow, native as native_lookup},
    };

    use super::ChipletsAir;
    use crate::vm::constraints::columns::NUM_CHIPLETS_COLS;

    #[test]
    fn complete_native_chiplets_capture_preserves_ordinary_then_lookup_order() {
        let captured = native::capture_with::<_, QuadFelt>(&ChipletsAir).unwrap();
        let spec = captured.descriptor.spec();
        assert_eq!(spec.main_width, NUM_CHIPLETS_COLS);
        assert_eq!(spec.aux_width, 4);
        assert_eq!(spec.num_public_values, 0);
        assert_eq!(spec.num_challenges, 2);
        assert_eq!(spec.num_exports, 1);
        assert!(spec.preprocessed.is_none());
        assert_eq!(spec.periodic_columns.len(), 8);
        assert!(spec.periodic_columns.iter().all(|column| column.len() == 8));
        let counts = captured.descriptor.analysis().counts();
        assert_eq!(counts.base, 172);
        assert_eq!(counts.ext, 5);
        assert!(
            captured.assertions[..counts.base]
                .iter()
                .all(|value| matches!(value, native::Assertion::Base(_)))
        );
        assert!(
            captured.assertions[counts.base..]
                .iter()
                .all(|value| matches!(value, native::Assertion::Extension(_)))
        );
        #[cfg(feature = "std")]
        miden_stark::lookup::native::validate_native(&ChipletsAir, spec).unwrap();
    }

    #[test]
    fn native_chiplet_witness_matches_slow_fractions_and_exports() {
        let main = RowMajorMatrix::new(
            (0..8)
                .flat_map(|row| {
                    let mut values = [Felt::ZERO; NUM_CHIPLETS_COLS];
                    values[23] = Felt::from_usize(row + 1);
                    values
                })
                .collect(),
            NUM_CHIPLETS_COLS,
        );
        let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
        let native = native::ProverAir::build_aux_trace(
            &ChipletsAir,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        let spec = native::LiftedAir::spec(&ChipletsAir);
        let encoding = Challenges::new(
            challenges[0],
            challenges[1],
            crate::vm::logup::MIDEN_MAX_MESSAGE_WIDTH,
            crate::vm::logup::BusId::COUNT,
        );
        let fractions = native_lookup::build_lookup_fractions(
            &ChipletsAir,
            &main,
            None,
            &spec.periodic_columns,
            &encoding,
        );
        let (expected, sigma) = accumulate_slow(&fractions);
        for (row, values) in native.columns.values.chunks_exact(expected.len()).enumerate() {
            for (column, value) in values.iter().enumerate() {
                assert_eq!(*value, expected[column][row]);
            }
        }
        assert_eq!(native.exports, [sigma]);
    }
}
