use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::deferred::{DeferredState, Node, TRUE_DIGEST};
use miden_precompiles::{CurveId, CurvePoint, CurvePrecompile, UintDomain, UintPrecompile};

use crate::{
    deferred::{DeferredSession, session_from_deferred_state},
    math::{U256, from_hex, to_limbs32},
};

fn state() -> DeferredState {
    DeferredState::new(Arc::new(miden_precompiles::registry()))
        .expect("precompile init must succeed")
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
fn deferred_session_lowers_zero_scalar_msm() {
    // 0·P = 𝒪: a single zero-scalar term registers and lowers to a session
    // whose resolved value is the point at infinity.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("zero-scalar MSM should lower");
}

#[test]
fn deferred_session_lowers_duplicate_base_msm() {
    // a·P + b·P = (a + b)·P: two terms naming the same generator lower
    // (via the term-preserving fallback path) into one session.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(generator.clone()).expect("generator must register");
    state.register(two.clone()).expect("scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator.clone(), two), (generator, three)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("duplicate-base MSM should lower");
}

#[test]
fn deferred_session_lowers_mixed_zero_and_nonzero_msm() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two_g = register_affine_curve_value(
        &mut state,
        curve,
        curve
            .mul_scalar(curve.generator(), limbs(2))
            .expect("valid scalar multiplication"),
    );
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator, zero), (two_g, three)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("mixed zero/nonzero MSM should lower");
}

#[test]
fn deferred_session_lowers_all_zero_msm_with_multiple_terms() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let two_g = register_affine_curve_value(
        &mut state,
        curve,
        curve
            .mul_scalar(curve.generator(), limbs(2))
            .expect("valid scalar multiplication"),
    );
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero.clone()), (two_g, zero)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("all-zero MSM should lower");
}

#[test]
fn deferred_session_lowers_repeated_base_coefficients_that_cancel() {
    // A repeated base whose scalars sum to the curve order mod n cancels to
    // the identity: k·P + (n − k)·P = n·P = 𝒪.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let k = limbs(7);
    let order = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let n_minus_k = to_limbs32(order - U256::from(7u64));
    let k_node = UintPrecompile::value_node(curve.scalar_domain(), k);
    let n_minus_k_node = UintPrecompile::value_node(curve.scalar_domain(), n_minus_k);
    state.register(generator.clone()).expect("generator must register");
    state.register(k_node.clone()).expect("scalar must register");
    state.register(n_minus_k_node.clone()).expect("scalar must register");

    let msm = curve_msm_node(vec![(generator.clone(), k_node), (generator, n_minus_k_node)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("cancelling repeated-base MSM should lower");
}

#[test]
fn deferred_session_lowers_structurally_different_nodes_at_the_same_canonical_point() {
    // `G` and `identity + G` are structurally different DAG nodes that both
    // evaluate to the generator — the same repeated-canonical-base path as
    // `deferred_session_lowers_duplicate_base_msm`, reached structurally.
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let identity = CurvePrecompile::identity_node(curve);
    state.register(generator.clone()).expect("generator must register");
    state.register(identity.clone()).expect("identity must register");
    let generator_via_add = Node::join(
        CurvePrecompile::op_tag(CurvePrecompile::ADD_OP_ID),
        identity.digest(),
        generator.digest(),
    )
    .expect("tag is curve-owned");
    let generator_via_add =
        state.register(generator_via_add).expect("identity + generator must register");

    let two = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
    let three = UintPrecompile::value_node(curve.scalar_domain(), limbs(3));
    state.register(two.clone()).expect("scalar must register");
    state.register(three.clone()).expect("scalar must register");

    let pairs = vec![(generator.digest(), two.digest()), (generator_via_add, three.digest())];
    let msm = Node::try_pair_list(CurvePrecompile::msm_tag(), pairs).expect("tag is curve-owned");
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state)
        .expect("MSM over structurally different same-point nodes should lower");
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

fn run_on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(f)
        .expect("thread spawn must succeed")
        .join()
        .expect("thread must not panic");
}

#[test]
fn translate_truthy_deep_and_spine_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = DeferredState::default();
        for _ in 0..512 {
            state.log_statement(TRUE_DIGEST).unwrap();
        }
        session_from_deferred_state(&state)
            .expect("deep AND spine must lower without stack overflow");
    });
}

#[test]
fn translate_uint_deep_add_chain_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
        state.register(one.clone()).expect("scalar leaf must register");
        let mut current = one.clone();
        for _ in 0..512 {
            let next = Node::join(
                UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID),
                current.digest(),
                one.digest(),
            )
            .expect("add node must construct");
            state.register(next.clone()).expect("add node must register");
            current = next;
        }
        let generator = CurvePrecompile::generator_node(curve);
        state.register(generator.clone()).expect("generator must register");
        let msm = curve_msm_node(vec![(generator, current)]);
        state.register(msm.clone()).expect("MSM must register");
        register_curve_equality(&mut state, msm.clone(), msm);
        session_from_deferred_state(&state)
            .expect("deep uint add chain must lower without stack overflow");
    });
}

#[test]
fn translate_ec_deep_nested_msm_does_not_stackoverflow() {
    run_on_small_stack(|| {
        let mut state = state();
        let curve = CurveId::Secp256k1;
        let scalar2 = UintPrecompile::value_node(curve.scalar_domain(), limbs(2));
        state.register(scalar2.clone()).expect("scalar must register");
        let generator = CurvePrecompile::generator_node(curve);
        state.register(generator.clone()).expect("generator must register");
        let mut current = curve_msm_node(vec![(generator, scalar2.clone())]);
        state.register(current.clone()).expect("first MSM must register");
        for _ in 1..512 {
            let next = curve_msm_node(vec![(current.clone(), scalar2.clone())]);
            state.register(next.clone()).expect("nested MSM must register");
            current = next;
        }
        register_curve_equality(&mut state, current.clone(), current);
        session_from_deferred_state(&state)
            .expect("deep nested MSM must lower without stack overflow");
    });
}
