//! Authored Core AIR constraints and lookup bindings.

use alloc::{borrow::Cow, vec::Vec};
use core::borrow::Borrow;

use miden_core::{Felt, WORD_SIZE, field::ExtensionField};
use miden_stark::{
    air::{ReductionError, native},
    lookup::{BoundaryBuilder, Challenges, LookupAir, native as native_lookup},
};

use super::{MidenAirBuilder, boundary::ReduceBoundaryBuilder};
use crate::vm::{
    constraints::{
        self,
        columns::CoreCols,
        lookup::main_air::{MainLookupAir, MainLookupBuilder, NativeMainLookupBuilder},
    },
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// CORE AIR
// ================================================================================================

/// Core trace AIR.
///
/// Enforces the system, decoder, stack, and range-check constraints.
#[derive(Copy, Clone, Debug, Default)]
pub struct CoreAir;

impl CoreAir {
    pub(super) fn width(self) -> usize {
        constraints::columns::NUM_CORE_COLS
    }

    pub(super) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        Vec::new()
    }

    pub(super) fn aux_width(self) -> usize {
        constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the core trace: the running sum of every
    /// boundary interaction reduced to its denominator contribution. The single var-len slice
    /// carries `[program_hash (4) | deferred_root (4)]`, the statement inputs the core
    /// boundary cancels against the block-hash and log-deferred buses.
    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "CoreAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if boundary_inputs[0].len() != 2 * WORD_SIZE {
            return Err(format!(
                "CoreAir expects {} boundary felts (program hash + deferred root), got {}",
                2 * WORD_SIZE,
                boundary_inputs[0].len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            var_len_public_inputs: boundary_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_core_boundary(&mut reducer);
        reducer.finalize()
    }

    pub(super) fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        native::migration::eval_source(&self, builder);
    }

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::main_air::MAIN_COLUMN_SHAPE
    }

    pub(super) fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    pub(super) fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    pub(super) fn lookup_eval<LB: MainLookupBuilder>(self, builder: &mut LB) {
        MainLookupAir.eval(builder);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_core_boundary(boundary);
    }
}

impl native::LiftedAir for CoreAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: constraints::columns::NUM_CORE_COLS,
            aux_width: constraints::lookup::main_air::MAIN_COLUMN_SHAPE.len(),
            num_public_values: crate::vm::inputs::NUM_PUBLIC_VALUES,
            num_challenges: crate::vm::trace::AUX_TRACE_RAND_CHALLENGES,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        let local: &CoreCols<B::Expr> = frame.main.current.borrow();
        let next: &CoreCols<B::Expr> = frame.main.next.borrow();
        let op_flags =
            constraints::op_flags::OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        constraints::enforce_core(frame, sink, local, next, &op_flags);
        constraints::public_inputs::enforce_main(frame, inputs, sink, local);
        native_lookup::eval_lookup(self, frame, inputs, sink);
    }
}

impl<LB: NativeMainLookupBuilder> native_lookup::LookupAir<LB> for CoreAir {
    fn column_shape(&self) -> &[usize] {
        &constraints::lookup::main_air::MAIN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        native_lookup::LookupAir::eval(&MainLookupAir, frame, builder);
    }

    fn eval_boundary<B: BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_core_boundary(boundary);
    }
}

impl<EF: ExtensionField<Felt>> native::ProverAir<EF> for CoreAir {
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
        operations::opcodes,
        utils::RowMajorMatrix,
    };
    use miden_stark::air::{LiftedAir as LegacyAir, native};

    use super::CoreAir;
    use crate::vm::{
        MidenAir,
        constraints::{columns::NUM_CORE_COLS, op_flags::generate_test_row},
        inputs::NUM_PUBLIC_VALUES,
    };

    #[test]
    fn complete_native_core_capture_keeps_lookup_after_all_base_assertions() {
        let captured = native::capture_with::<_, QuadFelt>(&CoreAir).unwrap();
        let spec = captured.descriptor.spec();
        assert_eq!(spec.main_width, NUM_CORE_COLS);
        assert_eq!(spec.aux_width, 4);
        assert_eq!(spec.num_public_values, NUM_PUBLIC_VALUES);
        assert_eq!(spec.num_challenges, 2);
        assert_eq!(spec.num_exports, 1);
        assert!(spec.preprocessed.is_none());
        assert!(spec.periodic_columns.is_empty());
        let counts = captured.descriptor.analysis().counts();
        // Column0 owns the cyclic accumulator and first-row anchor. Each later column owns
        // one fraction relation, so four columns contribute five extension-class assertions.
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

        use native::symbolic::{AuxInput, BaseLeaf, ExtLeaf, RowOffset, SymbolicExpr};
        let native::Assertion::Extension(SymbolicExpr::Mul { x: acc, y: first, .. }) =
            &captured.assertions[counts.base]
        else {
            panic!("the first lookup assertion must remain its accumulator anchor");
        };
        assert!(matches!(
            acc.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Input(AuxInput::Trace {
                offset: RowOffset::Current,
                index: 0
            }))
        ));
        assert!(matches!(
            first.as_ref(),
            SymbolicExpr::Leaf(ExtLeaf::Base(SymbolicExpr::Leaf(BaseLeaf::IsFirstRow)))
        ));

        #[cfg(feature = "std")]
        miden_stark::lookup::native::validate_native(&CoreAir, spec).unwrap();
    }

    #[test]
    fn native_and_legacy_core_witnesses_preserve_values_and_normalized_export() {
        let mut current = generate_test_row(opcodes::PUSH.into());
        let mut next = generate_test_row(opcodes::END.into());
        current.system.clk = Felt::from_u32(19);
        next.system.clk = Felt::from_u32(41);
        let main = RowMajorMatrix::new(
            current.as_slice().iter().chain(next.as_slice()).copied().collect(),
            NUM_CORE_COLS,
        );
        let public = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
        let native = native::ProverAir::build_aux_trace(
            &CoreAir,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &public,
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap();
        let (legacy, exports) =
            <MidenAir as LegacyAir<Felt, QuadFelt>>::build_aux_trace_with_preprocessed(
                &MidenAir::Core,
                &main,
                None,
                &public,
                &[],
                &challenges,
            );
        assert_eq!(native.columns.values, legacy.values);
        assert_eq!(native.exports, exports);
    }
}
