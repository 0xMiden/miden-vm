//! Compiled coverage for rich operations that production constraints do not all use yet.
use miden_core::Felt;
use miden_stark::air::{AirSpec, Frame, Inputs, LiftedAir, LiftedAirBuilder};
use p3_field::{Algebra, Dup, PrimeCharacteristicRing};

#[derive(Debug)]
pub struct OperationFixture;
impl LiftedAir for OperationFixture {
    type F = Felt;
    fn spec(&self) -> AirSpec<'_, Felt> {
        AirSpec {
            main_width: 2,
            aux_width: 2,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: std::borrow::Cow::Borrowed(&[]),
        }
    }
    fn eval<B: LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        sink: &mut B,
    ) {
        let x = frame.main.current[0].dup();
        let y = frame.main.current[1].dup();
        sink.assert_zero(x.square());
        sink.assert_zero(x.cube());
        sink.assert_zero(x.exp_u64(7));
        sink.assert_zero(x.exp_const_u64::<11>());
        sink.assert_zero(x.exp_power_of_2(3));
        sink.assert_zero(x.double());
        sink.assert_zero(x.halve());
        sink.assert_zero(x.mul_2exp_u64(13));
        sink.assert_zero(x.div_2exp_u64(9));
        sink.assert_zero(x.bool_check());
        let values = [x.dup(), y.dup()];
        sink.assert_zero(B::Expr::sum_array::<2>(&values));
        sink.assert_zero(values.iter().map(Dup::dup).product::<B::Expr>());
        sink.assert_zero(B::Expr::dot_product(&values, &values));
        sink.assert_zero(<B::Expr as Algebra<Felt>>::mixed_dot_product(
            &values,
            &[Felt::from_u64(3), Felt::from_u64(5)],
        ));
        let a = frame.aux.current[0].dup();
        let b = frame.aux.current[1].dup();
        let ext = [a.dup(), b.dup()];
        sink.assert_zero_ext(<B::ExtExpr as Algebra<B::Expr>>::mixed_dot_product(&ext, &values));
        let long_values: [B::ExtExpr; 17] = core::array::from_fn(|_| a.dup());
        let long_coeffs: [B::Expr; 17] = core::array::from_fn(|_| y.dup());
        sink.assert_zero_ext(<B::ExtExpr as Algebra<B::Expr>>::batched_linear_combination(
            &long_values,
            &long_coeffs,
        ));
        // Exercise Plonky3's default scalar expansion without a dedicated quadratic node.
        let [c0, c1] = <B::ExtExpr as Algebra<B::Expr>>::quadratic_extension_square(&ext, x.dup());
        sink.assert_zero_ext(c0.dup() + c1.dup());
        sink.assert_zero_ext(c0 * y.dup());
        sink.assert_zero_ext(c1 * x);
        let challenges = [inputs.challenge(0), inputs.challenge(1)];
        let [p0, p1] = <B::ExtExpr as Algebra<B::Expr>>::quadratic_extension_square(
            &challenges,
            B::Expr::from_u64(7),
        );
        sink.assert_zero_ext(p0.dup() * y);
        sink.assert_zero_ext(p1 + p0);
    }
}

pub fn generate() -> String {
    use miden_constraint_compiler::{
        backend::rust_eval::{AirEvaluator, emit_native_optimized_module},
        ir::capture_program_native_with_descriptor,
    };
    let (program, descriptor) = capture_program_native_with_descriptor(&OperationFixture)
        .expect("capture rich-operation fixture");
    emit_native_optimized_module(
        "// Generated rich-operation execution fixture.\n",
        &[AirEvaluator {
            name: "operations",
            air_label: "Operations",
            program: &program,
            descriptor: &descriptor,
        }],
    )
}
