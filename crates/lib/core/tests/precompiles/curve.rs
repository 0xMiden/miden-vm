use miden_core::{Felt, Word};
use miden_precompiles::{CurveId, CurvePrecompile};

use super::helpers::{
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
        assert_zero_scalar_mul_evaluates_to_identity(curve);
        assert_eval_generator(curve);
        assert_predicates_have_expected_polarity(curve.module);
        assert_identity_assertions_have_expected_polarity(curve.module);
        assert_msm2_zero_scalar_expression_term(curve);
        assert_msm2_all_zero_scalar_terms(curve);
        assert_msm2_duplicate_base(curve);
        assert_msm2_structurally_different_equal_bases(curve);
        assert_msm2_rejects_identity_base(curve);
        assert_msm_mem_multi_term_with_zero_scalar_and_duplicate_base(curve);
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
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
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

fn assert_zero_scalar_mul_evaluates_to_identity(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            exec.{scalar_module}::push_zero_digest
            exec.{module}::push_generator
            exec.{module}::mul_scalar
            exec.{module}::push_identity
            exec.{module}::assert_eq
        end
        ",
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} zero-scalar multiplication must evaluate to the identity: {err:?}");
    });
}

/// Builds an `msm2` call from four snippets, each pushing the digest named in `msm2`'s own
/// `Input:` comment (`POINT0`, `SCALAR0`, `POINT1`, `SCALAR1`), and reorders them so `POINT0`
/// ends up on top as `msm2` expects.
fn msm2_call(point0: &str, scalar0: &str, point1: &str, scalar1: &str, module: &str) -> String {
    format!(
        "
        {scalar1}
        {point1}
        {scalar0}
        {point0}
        exec.{module}::msm2
        "
    )
}

fn assert_msm2_zero_scalar_expression_term(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    // `1 - 1`: a scalar EXPRESSION that evaluates to zero, distinct from the literal
    // `push_zero_digest` VALUE already covered by `assert_zero_scalar_mul_evaluates_to_identity`.
    let zero_scalar_expr = format!(
        "exec.{scalar_module}::push_one_digest exec.{scalar_module}::push_one_digest exec.{scalar_module}::sub"
    );
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            {msm2}
            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::assert_eq
        end
        ",
        msm2 = msm2_call(
            &format!("exec.{module}::push_generator"),
            &zero_scalar_expr,
            &format!("exec.{module}::push_generator"),
            &format!("exec.{scalar_module}::push_two_digest"),
            module,
        ),
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} msm2 with a zero-scalar expression term must succeed: {err:?}");
    });
}

fn assert_msm2_all_zero_scalar_terms(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    let zero_scalar_expr = format!(
        "exec.{scalar_module}::push_one_digest exec.{scalar_module}::push_one_digest exec.{scalar_module}::sub"
    );
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            {msm2}
            exec.{module}::push_identity
            exec.{module}::assert_eq
        end
        ",
        msm2 = msm2_call(
            &format!("exec.{module}::push_generator"),
            &format!("exec.{scalar_module}::push_zero_digest"),
            &format!("exec.{module}::push_generator"),
            &zero_scalar_expr,
            module,
        ),
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} msm2 with every scalar zero must evaluate to the identity: {err:?}");
    });
}

fn assert_msm2_duplicate_base(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            {msm2}
            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::push_generator
            exec.{module}::add
            exec.{module}::assert_eq
        end
        ",
        msm2 = msm2_call(
            &format!("exec.{module}::push_generator"),
            &format!("exec.{scalar_module}::push_two_digest"),
            &format!("exec.{module}::push_generator"),
            &format!("exec.{scalar_module}::push_one_digest"),
            module,
        ),
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!("{module} msm2 with a duplicate canonical base must combine scalars: {err:?}");
    });
}

fn assert_msm2_structurally_different_equal_bases(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    // `G + O`: an ADD-expression digest that is structurally different from the plain
    // `push_generator` constant but canonically evaluates to the same point.
    let generator_via_add_identity =
        format!("exec.{module}::push_generator exec.{module}::push_identity exec.{module}::add");
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            {msm2}
            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::assert_eq
        end
        ",
        msm2 = msm2_call(
            &format!("exec.{module}::push_generator"),
            &format!("exec.{scalar_module}::push_one_digest"),
            &generator_via_add_identity,
            &format!("exec.{scalar_module}::push_one_digest"),
            module,
        ),
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!(
            "{module} msm2 with structurally different but canonically equal bases must combine scalars: {err:?}"
        );
    });
}

fn assert_msm2_rejects_identity_base(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;

    let literal_identity = format!("exec.{module}::push_identity");
    let identity_via_expression =
        format!("exec.{module}::push_generator exec.{module}::push_generator exec.{module}::sub");
    let nonzero_scalar = format!("exec.{scalar_module}::push_one_digest");
    let other_point = format!("exec.{module}::push_generator");

    for identity_base in [literal_identity, identity_via_expression] {
        let source = format!(
            "
            use miden::core::precompiles::curves::{module}
            use miden::core::precompiles::fields::{scalar_module}
            begin
                {msm2}
            end
            ",
            msm2 =
                msm2_call(&identity_base, &nonzero_scalar, &other_point, &nonzero_scalar, module),
        );
        expect_precompile_trap(&source);
    }
}

fn assert_msm_mem_multi_term_with_zero_scalar_and_duplicate_base(curve: CurveCase) {
    let module = curve.module;
    let scalar_module = curve.scalar_module;
    let ptr: u32 = 1000;
    let stage = |addr: u32, push: &str| format!("{push}\nmem_storew_le.{addr}\ndropw");

    // A 3-pair PairList over `msm_mem`: `G` appears twice (a duplicate canonical base) and the
    // middle pair carries a zero scalar. Expected sum: `1*G + 0*G + 2*G = 3*G`.
    let source = format!(
        "
        use miden::core::precompiles::curves::{module}
        use miden::core::precompiles::fields::{scalar_module}
        begin
            {pair0_point}
            {pair0_scalar}
            {pair1_point}
            {pair1_scalar}
            {pair2_point}
            {pair2_scalar}

            push.3 push.{ptr}
            exec.{module}::msm_mem

            exec.{module}::push_generator
            exec.{module}::double
            exec.{module}::push_generator
            exec.{module}::add
            exec.{module}::assert_eq
        end
        ",
        pair0_point = stage(ptr, &format!("exec.{module}::push_generator")),
        pair0_scalar = stage(ptr + 4, &format!("exec.{scalar_module}::push_one_digest")),
        pair1_point = stage(ptr + 8, &format!("exec.{module}::push_generator")),
        pair1_scalar = stage(ptr + 12, &format!("exec.{scalar_module}::push_zero_digest")),
        pair2_point = stage(ptr + 16, &format!("exec.{module}::push_generator")),
        pair2_scalar = stage(ptr + 20, &format!("exec.{scalar_module}::push_two_digest")),
    );
    run_precompile_program(&source).unwrap_or_else(|err| {
        panic!(
            "{module} msm_mem with a zero-scalar term and a duplicate base across 3 pairs must succeed: {err:?}"
        );
    });
}

fn assert_eval_generator(curve: CurveCase) {
    let generator = CurvePrecompile::generator_node(curve.curve);
    let (x_digest, y_digest) = generator.payload().as_join().unwrap();
    let source = format!(
        "
        {TRUNCATE_STACK_TO_OUTPUT_PROC}

        use miden::core::precompiles::curves::{module}
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

fn assert_predicates_have_expected_polarity(module: &str) {
    run_curve_program(
        module,
        &format!(
            "
            exec.{module}::push_generator
            exec.{module}::push_generator
            exec.{module}::is_eq
            assert

            exec.{module}::push_identity
            exec.{module}::push_generator
            exec.{module}::is_eq
            assertz

            exec.{module}::push_generator
            exec.{module}::push_generator
            exec.{module}::is_eq_digest
            assert

            exec.{module}::push_identity
            exec.{module}::push_generator
            exec.{module}::is_eq_digest
            assertz

            exec.{module}::push_identity
            exec.{module}::is_identity
            assert

            exec.{module}::push_generator
            exec.{module}::is_identity
            assertz
            ",
        ),
        "curve predicate polarity",
    );
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

        use miden::core::precompiles::curves::{module}
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
        use miden::core::precompiles::curves::{module}
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
        use miden::core::precompiles::curves::{module}
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
