use miden_core::{Felt, deferred::Node};
use miden_precompiles::{UintDomain, UintPrecompile};

use super::check_local_inputs;
use crate::{
    math::{U256, from_limbs32, to_limbs32},
    session::Session,
    transcript::eval::{
        COL_H_BEGIN, COL_IS_FIELD_TAG, COL_IS_PINNED, COL_IS_UINT_LEAF, COL_PIN_PTR, COL_PTR,
        NUM_MAIN_COLS, TranscriptEvalAir,
    },
};

const TEST_DOMAIN: UintDomain = UintDomain::K1Scalar;

#[test]
fn uint_add_mul_is_balances_session_stack() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);

    let a = session.uint_leaf(U256::from(3u64), bound);
    let b = session.uint_leaf(U256::from(4u64), bound);
    let sum = session.uint_add(&a, &b);
    let product = session.uint_mul(&sum, &b);
    let expected = session.uint_leaf(U256::from(28u64), bound);
    let claim = session.uint_is(&product, &expected);

    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    traces.check();
}

#[test]
fn pinned_uint_can_become_the_session_root() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let claim = session.pin_uint(2, U256::from(42u64), bound);

    let traces = session.finish(claim);
    traces.check();
}

#[test]
fn pin_domain_allows_modulus_minus_one_value() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let value = session.uint_leaf(from_limbs32(&TEST_DOMAIN.minus_one()), bound);
    let claim = session.uint_is(&value, &value);

    let traces = session.finish(claim);
    traces.check();
}

#[test]
#[should_panic]
fn pin_domain_rejects_modulus_value() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let _ = session.uint_leaf(from_limbs32(&TEST_DOMAIN.encoded_modulus()), bound);
}

#[test]
#[should_panic(expected = "pinned uint claims are root-only")]
fn pinned_uint_cannot_be_a_non_root_claim() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let _claim = session.pin_uint(2, U256::from(42u64), bound);
    let root = session.zero();

    let _ = session.finish(root);
}

#[test]
#[should_panic]
fn eval_air_rejects_non_first_pinned_uint_leaf() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let a = session.uint_leaf(U256::from(3u64), bound);
    let b = session.uint_leaf(U256::from(3u64), bound);
    let root = session.uint_is(&a, &b);

    let traces = session.finish(root);
    let mut eval = traces.eval_main().clone();
    let row = eval
        .values
        .chunks_exact(NUM_MAIN_COLS)
        .enumerate()
        .skip(1)
        .find_map(|(row, cols)| (cols[COL_IS_UINT_LEAF] == Felt::ONE).then_some(row))
        .expect("uint leaf row exists");
    let offset = row * NUM_MAIN_COLS;
    eval.values[offset + COL_IS_PINNED] = Felt::ONE;
    eval.values[offset + COL_PIN_PTR] = eval.values[offset + COL_PTR];

    check_local_inputs(TranscriptEvalAir, &eval, traces.air_inputs());
}

#[test]
#[should_panic]
fn eval_air_rejects_unpinned_uint_leaf_as_root() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let claim = session.pin_uint(2, U256::from(42u64), bound);

    let traces = session.finish(claim);
    let mut eval = traces.eval_main().clone();
    eval.values[COL_IS_PINNED] = Felt::ZERO;
    eval.values[COL_PIN_PTR] = Felt::ZERO;

    check_local_inputs(TranscriptEvalAir, &eval, traces.air_inputs());
}

#[test]
#[should_panic]
fn eval_air_rejects_field_tag_for_wrong_uint_domain() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let a = session.uint_leaf(U256::from(3u64), bound);
    let b = session.uint_leaf(U256::from(3u64), bound);
    let root = session.uint_is(&a, &b);

    let traces = session.finish(root);
    let mut eval = traces.eval_main().clone();
    let row = eval
        .values
        .chunks_exact(NUM_MAIN_COLS)
        .enumerate()
        .find_map(|(row, cols)| (cols[COL_IS_FIELD_TAG] == Felt::ONE).then_some(row))
        .expect("field-domain row exists");
    let offset = row * NUM_MAIN_COLS;
    eval.values[offset + COL_H_BEGIN + 2] = UintDomain::K1Base.id();

    check_local_inputs(TranscriptEvalAir, &eval, traces.air_inputs());
}

#[test]
fn equal_modulus_domains_do_not_share_uint_op_nodes() {
    let mut session = Session::new();
    let bound = from_limbs32(&TEST_DOMAIN.minus_one());
    let bound_a = session.pin_modulus(1, bound);
    let bound_b = session.pin_modulus(2, bound);

    let a0 = session.uint_leaf(U256::from(3u64), bound_a);
    let a1 = session.uint_leaf(U256::from(4u64), bound_a);
    let sum_a = session.uint_add(&a0, &a1);
    let expected_a = session.uint_leaf(U256::from(7u64), bound_a);
    let claim_a = session.uint_is(&sum_a, &expected_a);

    let b0 = session.uint_leaf(U256::from(3u64), bound_b);
    let b1 = session.uint_leaf(U256::from(4u64), bound_b);
    let sum_b = session.uint_add(&b0, &b1);
    let expected_b = session.uint_leaf(U256::from(7u64), bound_b);
    let claim_b = session.uint_is(&sum_b, &expected_b);

    let root = session.assert_and_fold([claim_a, claim_b]);
    let traces = session.finish(root);
    traces.check();
}

#[test]
fn uint_leaf_hash_matches_canonical_value_node() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let value = U256::from(42u64);

    let node = session.uint_leaf(value, bound);
    let expected = UintPrecompile::value_node(TEST_DOMAIN, to_limbs32(value));

    assert_eq!(node.hash(), expected.digest().into());
}

#[test]
fn uint_op_hashes_match_canonical_join_nodes() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let lhs_value = U256::from(3u64);
    let rhs_value = U256::from(4u64);

    let lhs = session.uint_leaf(lhs_value, bound);
    let rhs = session.uint_leaf(rhs_value, bound);
    let sum = session.uint_add(&lhs, &rhs);
    let claim = session.uint_is(&sum, &sum);

    let lhs_node = UintPrecompile::value_node(TEST_DOMAIN, to_limbs32(lhs_value));
    let rhs_node = UintPrecompile::value_node(TEST_DOMAIN, to_limbs32(rhs_value));
    let canonical_sum = Node::join(
        UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID),
        lhs_node.digest(),
        rhs_node.digest(),
    )
    .expect("uint add tag is precompile-owned");
    let canonical_claim = Node::join(
        UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID),
        canonical_sum.digest(),
        canonical_sum.digest(),
    )
    .expect("uint eq tag is precompile-owned");

    assert_eq!(sum.hash(), canonical_sum.digest().into());
    assert_eq!(claim.hash(), canonical_claim.digest().into());
}

#[test]
#[should_panic(expected = "stray field-element value node")]
fn unconsumed_uint_value_is_rejected_by_session_finish() {
    let mut session = Session::new();
    let bound = session.pin_domain(1, TEST_DOMAIN);
    let _dead = session.uint_leaf(U256::from(3u64), bound);
    let root = session.zero();

    let _ = session.finish(root);
}
