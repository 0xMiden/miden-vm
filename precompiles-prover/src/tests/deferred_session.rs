use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::deferred::{DeferredState, Node};
use miden_precompiles::{CurveId, CurvePrecompile, UintDomain, UintPrecompile};

use crate::deferred::{DeferredSessionError, session_from_deferred_state};

fn state() -> DeferredState {
    DeferredState::new(Arc::new(miden_precompiles::registry()), usize::MAX)
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
fn deferred_session_rejects_all_zero_msm_without_panicking() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let zero = UintPrecompile::value_node(curve.scalar_domain(), limbs(0));
    state.register(generator.clone()).expect("generator must register");
    state.register(zero.clone()).expect("zero scalar must register");

    let msm = curve_msm_node(vec![(generator, zero)]);
    register_curve_equality(&mut state, msm.clone(), msm);

    let err = match session_from_deferred_state(&state) {
        Ok(_) => panic!("zero-scalar MSM must be rejected"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        DeferredSessionError::UnsupportedMsmAllZeroScalars { .. }
    ));
}

#[test]
fn deferred_session_lowers_duplicate_base_msm_without_panicking() {
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
fn deferred_session_lowers_large_msm_without_panicking() {
    let mut state = state();
    let curve = CurveId::Secp256k1;
    let generator = CurvePrecompile::generator_node(curve);
    let one = UintPrecompile::value_node(curve.scalar_domain(), limbs(1));
    state.register(generator.clone()).expect("generator must register");
    state.register(one.clone()).expect("scalar must register");

    let pairs = (0..17).map(|_| (generator.clone(), one.clone())).collect::<Vec<_>>();
    let msm = curve_msm_node(pairs);
    register_curve_equality(&mut state, msm.clone(), msm);

    session_from_deferred_state(&state).expect("large MSM should lower");
}
