use miden_core::{Felt, Word};
use miden_precompiles::{CurveId, CurvePrecompile};

use crate::helpers::{
    TRUNCATE_STACK_TO_OUTPUT_PROC, assert_deferred_state_round_trips, expect_precompile_trap,
    read_stack_felts, run_precompile_program,
};

#[derive(Clone, Copy)]
struct CurveCase {
    module: &'static str,
    scalar_module: &'static str,
    curve: CurveId,
}

fn supported_curves() -> [CurveCase; 1] {
    [CurveCase {
        module: "secp256k1",
        scalar_module: "k1_scalar",
        curve: CurveId::Secp256k1,
    }]
}

#[test]
fn supported_curves_satisfy_public_contract() {
    for curve in supported_curves() {
        assert_constant_digests(curve);
        assert_arithmetic_assertions(curve.module);
        assert_scalar_mul_wrappers(curve);
        assert_eval_generator(curve);
        assert_identity_assertions_have_expected_polarity(curve.module);
    }
}

fn assert_arithmetic_assertions(module: &str) {
    run_curve_program(
        module,
        &format!(
            "
            exec.{module}::push_generator
            exec.{module}::push_identity
            exec.{module}::add
            exec.{module}::push_generator
            exec.{module}::assert_eq

            exec.{module}::push_generator
            exec.{module}::push_generator
            exec.{module}::sub
            exec.{module}::push_identity
            exec.{module}::assert_eq

            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::push_generator
            exec.{module}::push_generator
            exec.{module}::add
            exec.{module}::assert_eq
            ",
        ),
        "curve arithmetic assertions",
    );
}

fn assert_scalar_mul_wrappers(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    let source = format!(
        "
        use miden::precompiles::math::curve::{module}
        use miden::precompiles::math::field::{scalar_module}
        begin
            exec.{scalar_module}::push_zero_digest
            exec.{module}::push_generator
            exec.{module}::mul_scalar
            exec.{module}::push_identity
            exec.{module}::assert_eq

            exec.{scalar_module}::push_one_digest
            exec.{module}::mul_scalar_generator
            exec.{module}::push_generator
            exec.{module}::assert_eq

            exec.{scalar_module}::push_two_digest
            exec.{module}::push_generator
            exec.{module}::mul_scalar
            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::assert_eq
        end
        ",
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} curve scalar multiplication wrappers must succeed: {err:?}");
    });
}

fn assert_eval_generator(curve: CurveCase) {
    let generator = CurvePrecompile::generator_node(curve.curve);
    let (x_digest, y_digest) = generator.payload().as_join().unwrap();
    let source = format!(
        "
        {TRUNCATE_STACK_TO_OUTPUT_PROC}

        use miden::precompiles::math::curve::{module}
        begin
            exec.{module}::push_generator
            exec.{module}::eval
            exec.truncate_stack_to_output
        end
        ",
        module = curve.module,
    );
    let output = run_precompile_program(&source).expect("curve eval must succeed");

    assert_stack_words(&read_stack_felts(&output, 12), &[generator.digest(), x_digest, y_digest]);
    assert_deferred_state_round_trips(&output);
}

fn assert_identity_assertions_have_expected_polarity(module: &str) {
    run_curve_program(
        module,
        &format!(
            "
            exec.{module}::push_identity
            exec.{module}::assert_identity

            exec.{module}::push_generator
            exec.{module}::assert_not_identity

            exec.{module}::push_generator
            exec.{module}::push_generator
            exec.{module}::assert_eq_digest
            ",
        ),
        "curve identity assertions",
    );

    expect_curve_trap(
        module,
        &format!("exec.{module}::push_generator\nexec.{module}::assert_identity"),
    );
    expect_curve_trap(
        module,
        &format!("exec.{module}::push_identity\nexec.{module}::assert_not_identity"),
    );
}

fn assert_constant_digests(curve: CurveCase) {
    let identity = CurvePrecompile::identity_node(curve.curve);
    let generator = CurvePrecompile::generator_node(curve.curve);
    let source = format!(
        "
        {TRUNCATE_STACK_TO_OUTPUT_PROC}

        use miden::precompiles::math::curve::{module}
        begin
            exec.{module}::push_identity
            exec.{module}::push_generator
            exec.truncate_stack_to_output
        end
        ",
        module = curve.module,
    );
    let output = run_precompile_program(&source).expect("curve constants must push digests");

    assert_stack_words(&read_stack_felts(&output, 8), &[generator.digest(), identity.digest()]);
    assert_deferred_state_round_trips(&output);
}

fn run_curve_program(module: &str, body: &str, label: &str) {
    let source = format!(
        "
        use miden::precompiles::math::curve::{module}
        begin
            {body}
        end
        "
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} {label} must succeed: {err:?}");
    });
}

fn expect_curve_trap(module: &str, body: &str) {
    let source = format!(
        "
        use miden::precompiles::math::curve::{module}
        begin
            {body}
        end
        "
    );
    expect_precompile_trap(&source);
}

fn assert_stack_words(actual: &[Felt], expected: &[Word]) {
    let expected: Vec<Felt> =
        expected.iter().flat_map(|word| word.as_elements().iter().copied()).collect();
    assert_eq!(actual, expected.as_slice());
}
