//! Compiled coverage of input namespaces and ordered assertion emission.

use std::borrow::Cow;

use miden_core::Felt;
use miden_stark::air::{
    AirSpec, Frame, Inputs, LiftedAir, LiftedAirBuilder, PreprocessedSpec,
};
use p3_field::{Dup, PrimeCharacteristicRing};

#[derive(Clone, Copy, Debug)]
pub struct AllInputs;

impl LiftedAir for AllInputs {
    type F = Felt;

    fn spec(&self) -> AirSpec<'_, Felt> {
        AirSpec {
            main_width: 2,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 1,
            num_exports: 1,
            preprocessed: Some(PreprocessedSpec { width: 1, log_height: 2 }),
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::ZERO]]),
        }
    }

    fn eval<B: LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        sink: &mut B,
    ) {
        let main = frame.main.current[0].dup();
        let next = frame.main.next[0].dup();
        let periodic = frame.periodic[0].dup();
        sink.when(frame.first_row()).assert_eq(main.dup(), inputs.public(0));
        sink.assert_zero_ext(
            frame.aux.current[0].dup() + inputs.challenge(0) - inputs.export(0)
                + frame.preprocessed.current[0].dup(),
        );
        // Zero gates still emit, including repeated roots in the global sequence.
        sink.when(B::Expr::ZERO).assert_zero(next.dup());
        sink.when(B::Expr::ZERO).assert_zero(next.dup());
        sink.when(frame.transition()).assert_eq(next, main);
        let fixed: B::ExtExpr = (frame.preprocessed.next[0].dup() + periodic.dup()).into();
        sink.when(frame.last_row()).assert_zero_ext(frame.aux.next[0].dup() - fixed);
        sink.when(frame.last_row()).assert_eq(frame.main.current[1].dup(), periodic);
    }
}

pub fn generate() -> String {
    use miden_constraint_compiler::{
        backend::rust_eval::{AirEvaluator, emit_native_optimized_module},
        ir::capture_program_native_with_descriptor,
    };
    let (program, descriptor) =
        capture_program_native_with_descriptor(&AllInputs).expect("capture current-input fixture");
    emit_native_optimized_module(
        "// Generated current input and emission fixture.\n",
        &[AirEvaluator {
            name: "all_inputs",
            air_label: "AllInputs",
            program: &program,
            descriptor: &descriptor,
        }],
    )
}
