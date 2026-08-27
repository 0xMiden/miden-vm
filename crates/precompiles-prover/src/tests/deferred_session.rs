use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::{
        DeferredState, MAX_PRECOMPILE_ROOTS, Node, PrecompileRegistry, PrecompileWitness,
        TRUE_DIGEST,
    },
};
use miden_precompiles::{
    CurveId, CurvePoint, CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile,
};

use crate::{
    DEFAULT_MAX_DEFERRED_EXPANSION_WORK, MAX_DEFERRED_TRANSLATION_DEPTH,
    deferred::{
        DeferredSession, DeferredSessionError, session_from_deferred_state,
        session_from_deferred_state_with_budget,
    },
    hash::keccak::sponge::trace::keccak_oracle,
};

fn state() -> DeferredState {
    DeferredState::new(Arc::new(miden_precompiles::registry()))
        .expect("precompile init must succeed")
}

fn shared_and_state(depth: u32) -> DeferredState {
    let mut state = DeferredState::new(Arc::new(PrecompileRegistry::new()))
        .expect("empty registry must initialize");
    for _ in 0..depth {
        let root = state.root();
        state.log_statement(root).expect("current root must log as a true statement");
    }
    state
}

fn linear_and_state(depth: u32) -> DeferredState {
    let mut state = DeferredState::new(Arc::new(PrecompileRegistry::new()))
        .expect("empty registry must initialize");
    for _ in 0..depth {
        state.log_statement(TRUE_DIGEST).expect("TRUE must log as a true statement");
    }
    state
}

fn shared_uint_state(depth: u32) -> DeferredState {
    let mut state = state();
    let value = UintPrecompile::value_node(UintDomain::U256, limbs(1));
    let mut value = state.register(value).expect("value must register");
    for _ in 0..depth {
        let sum = Node::join(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), value, value)
            .expect("tag is uint-owned");
        value = state.register(sum).expect("sum must register");
    }
    let eq = Node::join(UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID), value, value)
        .expect("tag is uint-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");
    state
}

fn linear_uint_state(depth: u32) -> DeferredState {
    let mut state = state();
    let one = UintPrecompile::value_node(UintDomain::U256, limbs(1));
    let one = state.register(one).expect("value must register");
    let mut value = one;
    for _ in 0..depth {
        let sum = Node::join(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), value, one)
            .expect("tag is uint-owned");
        value = state.register(sum).expect("sum must register");
    }
    let eq = Node::join(UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID), value, value)
        .expect("tag is uint-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");
    state
}

fn keccak_state(input: &[u8]) -> DeferredState {
    let registry =
        Arc::new(PrecompileRegistry::new().with_precompile(Keccak256Precompile::default()));
    let mut state = DeferredState::new(registry).expect("Keccak registry must initialize");
    let input_digest = state
        .register(Node::chunks_from_bytes(input))
        .expect("input chunks must register");
    let expected = vec![keccak_oracle(input).to_u32s().map(Felt::from_u32)];
    let expected_digest = state
        .register(Node::chunks(expected).expect("digest chunks are nonempty"))
        .expect("expected digest must register");
    let assertion = state
        .register(Keccak256Precompile::assert_node(
            input.len().try_into().expect("test input length fits u32"),
            input_digest,
            expected_digest,
        ))
        .expect("matching Keccak assertion must register");
    state.log_statement(assertion).expect("matching assertion must log");
    state
}

#[test]
fn deferred_session_truthy_expansion_budget_has_an_exact_boundary() {
    let state = shared_and_state(5);

    session_from_deferred_state_with_budget(&state, 63)
        .expect("a depth-five shared AND has exactly 63 truthy occurrences");
    assert!(matches!(
        session_from_deferred_state_with_budget(&state, 62),
        Err(DeferredSessionError::TranslationBudgetExceeded { max: 62 })
    ));
}

#[test]
fn deferred_session_expansion_budget_includes_shared_uint_dependencies() {
    let state = shared_uint_state(5);

    session_from_deferred_state_with_budget(&state, 129)
        .expect("the shared uint expression has exactly 129 translation occurrences");
    assert!(matches!(
        session_from_deferred_state_with_budget(&state, 128),
        Err(DeferredSessionError::TranslationBudgetExceeded { max: 128 })
    ));
}

#[test]
fn deferred_session_expansion_budget_charges_keccak_input_chunks() {
    let state = keccak_state(&[42; 64]);

    session_from_deferred_state_with_budget(&state, 5)
        .expect("the root, TRUE leaf, assertion, and two input chunks cost five units");
    assert!(matches!(
        session_from_deferred_state_with_budget(&state, 4),
        Err(DeferredSessionError::TranslationBudgetExceeded { max: 4 })
    ));
}

#[test]
fn deferred_session_accepts_supported_merged_root_depth() {
    let witnesses = (0..MAX_PRECOMPILE_ROOTS)
        .map(|_| {
            PrecompileWitness::new(linear_and_state(1))
                .expect("one logged statement must form a witness")
        })
        .collect();
    let merged = PrecompileWitness::merge(witnesses).expect("root count is supported");

    session_from_deferred_state(merged.state()).expect("supported root merges must lower");
}

#[test]
fn deferred_session_rejects_translation_depth_above_the_safe_limit() {
    session_from_deferred_state(&linear_uint_state(MAX_DEFERRED_TRANSLATION_DEPTH as u32 - 2))
        .expect("the exact translation depth limit must be accepted");
    assert!(matches!(
        session_from_deferred_state(&linear_uint_state(MAX_DEFERRED_TRANSLATION_DEPTH as u32 - 1)),
        Err(DeferredSessionError::TranslationDepthExceeded { max: MAX_DEFERRED_TRANSLATION_DEPTH })
    ));
}

#[test]
fn deferred_session_truthy_expansion_count_rejects_overflow() {
    let state = shared_and_state(usize::BITS);

    assert!(matches!(
        session_from_deferred_state_with_budget(&state, usize::MAX),
        Err(DeferredSessionError::TranslationCountOverflow)
    ));
}

#[test]
fn deferred_session_rejects_truthy_expansion_above_the_default_budget() {
    let depth = DEFAULT_MAX_DEFERRED_EXPANSION_WORK.ilog2();
    let state = shared_and_state(depth);

    assert!(matches!(
        session_from_deferred_state(&state),
        Err(DeferredSessionError::TranslationBudgetExceeded {
            max: DEFAULT_MAX_DEFERRED_EXPANSION_WORK,
        })
    ));
}

fn limbs(value: u32) -> [u32; 8] {
    let mut limbs = [0; 8];
    limbs[0] = value;
    limbs
}

#[test]
fn deferred_session_lowers_uint_equality_assertion() {
    let mut state = state();
    let one = UintPrecompile::value_node(UintDomain::U256, limbs(1));
    let two = UintPrecompile::value_node(UintDomain::U256, limbs(2));
    let three = UintPrecompile::value_node(UintDomain::U256, limbs(3));

    state.register(one.clone()).expect("one must register");
    state.register(two.clone()).expect("two must register");
    state.register(three.clone()).expect("three must register");

    let sum =
        Node::join(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), one.digest(), two.digest())
            .expect("tag is uint-owned");
    let sum = state.register(sum).expect("sum must register");
    let eq = Node::join(UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID), three.digest(), sum)
        .expect("tag is uint-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");

    session_from_deferred_state(&state).expect("uint equality should lower into a session");
}

#[test]
fn deferred_session_lowers_curve_equality_assertion() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let identity = CurvePrecompile::identity_node(curve);

    state.register(identity.clone()).expect("identity must register");
    state.register(generator.clone()).expect("generator must register");

    let sum = Node::join(
        CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID),
        identity.digest(),
        generator.digest(),
    )
    .expect("tag is curve-owned");
    let sum = state.register(sum).expect("sum must register");
    let eq =
        Node::join(CurvePrecompile::op_tag(CurvePrecompile::EQ_OP_ID), generator.digest(), sum)
            .expect("tag is curve-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");

    session_from_deferred_state(&state).expect("curve equality should lower into a session");
}

fn register_curve_equality(state: &mut DeferredState, lhs: Node, rhs: Node) {
    let lhs = state.register(lhs).expect("lhs must register");
    let rhs = state.register(rhs).expect("rhs must register");
    let eq = Node::join(CurvePrecompile::op_tag(CurvePrecompile::EQ_OP_ID), lhs, rhs)
        .expect("tag is curve-owned");
    let eq = state.register(eq).expect("equality must register");
    state.log_statement(eq).expect("equality must log");
}

fn curve_msm_node(pairs: Vec<(Node, Node)>) -> Node {
    let pairs = pairs.into_iter().map(|(point, scalar)| (point.digest(), scalar.digest()));
    let pairs = pairs.collect::<Vec<_>>();
    Node::try_pair_list(CurvePrecompile::msm_tag(), pairs).expect("tag is curve-owned")
}

#[test]
fn deferred_session_lowers_nested_one_term_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");

    let inner = curve_msm_node(vec![(generator.clone(), one.clone())]);
    state.register(inner.clone()).expect("inner MSM must register");
    let outer = curve_msm_node(vec![(inner, one)]);
    state.register(outer.clone()).expect("outer MSM must register");
    register_curve_equality(&mut state, outer, generator);

    let DeferredSession { session, root } =
        session_from_deferred_state(&state).expect("nested MSM claims should lower");
    session.finish(root).check();
}

#[test]
fn deferred_session_reuses_identical_msm_claim_in_trace() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator, one)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    let DeferredSession { session, root } =
        session_from_deferred_state(&state).expect("repeated MSM claim should lower");
    session.finish(root).check();
}

fn register_affine_curve_value(
    state: &mut DeferredState,
    curve: CurveId,
    point: CurvePoint,
) -> Node {
    let CurvePoint::Affine { x, y } = point else {
        panic!("expected affine point");
    };
    let x = UintPrecompile::value_node(curve.base_domain(), x);
    let y = UintPrecompile::value_node(curve.base_domain(), y);
    state.register(x.clone()).expect("x coordinate must register");
    state.register(y.clone()).expect("y coordinate must register");
    let point = CurvePrecompile::affine_node_from_digests(curve, x.digest(), y.digest());
    state.register(point.clone()).expect("point must register");
    point
}

#[test]
fn deferred_session_inputs_reject_zero_scalar_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero)]);
    assert!(state.register(msm).is_err(), "zero-scalar MSM must be rejected");
}

#[test]
fn deferred_session_inputs_reject_duplicate_base_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(generator.clone()).expect("generator must register");
    state.register(two.clone()).expect("scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator.clone(), two), (generator, three)]);
    assert!(state.register(msm).is_err(), "duplicate-base MSM must be rejected");
}

#[test]
fn deferred_session_inputs_reject_identity_base_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let identity = CurvePrecompile::identity_node(curve);
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(17));
    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    state.register(identity.clone()).expect("identity must register");
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");
    state.register(two.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(identity, one), (generator, two)]);
    assert!(state.register(msm).is_err(), "identity-base MSM must be rejected");
}

#[test]
fn deferred_session_lowers_large_msm_without_panicking() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(one.clone()).expect("scalar must register");

    let pairs = (1..=17)
        .map(|scalar| {
            let point = curve
                .mul_scalar(curve.generator(), limbs(scalar))
                .expect("generator multiple must be valid");
            (register_affine_curve_value(&mut state, curve, point), one.clone())
        })
        .collect::<Vec<_>>();
    let msm = curve_msm_node(pairs);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("large MSM should lower");
}
