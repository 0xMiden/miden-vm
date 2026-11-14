//! Execute emitted rich operations with scalar and packed expression carriers.
use miden_constraint_compiler::{
    ir::capture_program_native_with_descriptor,
    testing::{
        assert_concrete_evaluation, assert_concrete_evaluations_equal, assert_program_lowering,
    },
};
use miden_core::Felt;
use miden_stark::air::{
    AirDescriptor, AirKernel, DirectKernel, Frame, Inputs, LiftedAirBuilder, UniformInputs,
};
use p3_field::Algebra;

#[path = "../build/symbolic_fixture.rs"]
mod fixture;
mod generated {
    include!(concat!(env!("OUT_DIR"), "/symbolic_operations_fixture.rs"));
}
struct Kernel(AirDescriptor<Felt>);
impl AirKernel for Kernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = [E; generated::OPERATIONS_PREPARED_TERMS];
    fn descriptor(&self) -> &AirDescriptor<Felt> {
        &self.0
    }
    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E> {
        generated::precompute_operations(inputs)
    }
    fn eval_row<B: LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        terms: &Self::Prepared<B::Expr, B::ExtExpr>,
        sink: &mut B,
    ) {
        generated::eval_operations(frame, inputs, sink, terms);
    }
}
#[test]
fn rich_operations_match_lowered_scalar_and_packed_execution() {
    let (program, descriptor) =
        capture_program_native_with_descriptor(&fixture::OperationFixture).unwrap();
    let kernel = Kernel(descriptor);
    let source = DirectKernel::new(fixture::OperationFixture).unwrap();
    for seed in [0, 0x243f6a8885a308d3, 0x13198a2e03707344, u64::MAX] {
        assert_concrete_evaluations_equal(&source, &kernel, seed);
        assert_program_lowering(&program, seed);
        assert_concrete_evaluation(&kernel, program.graph(), program.constraints(), seed);
    }
    let emitted = fixture::generate();
    assert_eq!(emitted, fixture::generate(), "generation is deterministic");
    for method in [
        "AB::Expr::dot_product::<2>",
        "<AB::Expr as Algebra<Felt>>::mixed_dot_product::<2>",
        "<AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<2>",
        "AB::ExtExpr::dot_product::<2>",
        "<AB::ExtExpr as Algebra<AB::Expr>>::batched_linear_combination",
    ] {
        assert!(emitted.contains(method), "missing {method}: {emitted}");
    }
    assert!(!emitted.contains("<AB::ExtExpr as Algebra<Felt>>"));
    assert!(
        !emitted.contains("::quadratic_extension_square("),
        "the quadratic helper must use its default scalar expansion"
    );
}
