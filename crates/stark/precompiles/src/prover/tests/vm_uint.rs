//! Focused tests for VM uint Eidos frames.

use miden_core::{Felt, utils::Matrix};
use miden_precompiles::{UintDomain, UintPrecompile};

use crate::prover::{
    math::U256,
    session::Session,
    transcript::{
        eidos::{EidosDigest, trace::EidosRequires},
        eval::{
            COL_BOUND_PTR, COL_FRAME_PARAM1, COL_IS_UINT_LEAF, COL_IS_UINT_OP, COL_OUT_MULT,
            COL_PTR, COL_UINT_VALUE_BOUND_PTR, NUM_MAIN_COLS as EVAL_NUM_MAIN_COLS,
        },
        nodes::UintOpId,
    },
};

fn limbs(value: u32) -> [u32; 8] {
    let mut limbs = [0; 8];
    limbs[0] = value;
    limbs
}

fn value_words(limbs: [u32; 8]) -> ([Felt; 4], [Felt; 4]) {
    (
        core::array::from_fn(|i| Felt::from(limbs[i])),
        core::array::from_fn(|i| Felt::from(limbs[4 + i])),
    )
}

#[test]
fn uint_value_hash_matches_vm_node_and_eq_op_context() {
    let domain = UintDomain::U256;
    let value_limbs = limbs(0x1234_5678);
    let (lo, hi) = value_words(value_limbs);
    let value_node = UintPrecompile::value_node(domain, value_limbs);

    let actual_value = EidosRequires::digest_of(UintPrecompile::value_frame(domain), &[(lo, hi)]);
    assert_eq!(actual_value, EidosDigest::from(value_node.digest()));

    assert_eq!(
        UintPrecompile::op_frame(UintOpId::Is as u64).as_word().into_elements(),
        [
            UintPrecompile::domain().as_felt(),
            Felt::new(UintPrecompile::EQ_OP_ID).expect("uint EQ op id must fit in a felt"),
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
}

#[test]
fn uint_value_at_fixed_store_pointer_commits_bound_and_shares_uses() {
    let mut session = Session::new();
    let root0 = session.zero();
    assert_eq!(root0.hash(), EidosDigest::default());

    let domain = UintDomain::U256;
    let bound_ptr = domain.bound_ptr();

    let value = session.uint_leaf(U256::MAX, bound_ptr);
    assert_eq!(value.ptr.addr(), bound_ptr);
    let eq = session.uint_is(&value, &value);
    let root = session.assert_and(root0, eq);

    let traces = session.finish(root);
    let eval = crate::prover::tests::transcript_eval_main(&traces);
    let row_value = |row: usize, col: usize| eval.values[row * EVAL_NUM_MAIN_COLS + col];

    let value_row = (0..eval.height())
        .find(|&row| {
            row_value(row, COL_IS_UINT_LEAF) == Felt::ONE
                && row_value(row, COL_PTR) == Felt::from(bound_ptr)
        })
        .expect("expected VM uint value row for explicit ptr");
    assert_eq!(row_value(value_row, COL_UINT_VALUE_BOUND_PTR), Felt::from(bound_ptr));
    assert_eq!(row_value(value_row, COL_OUT_MULT), Felt::from_u32(2));

    let op_row = (0..eval.height())
        .find(|&row| row_value(row, COL_IS_UINT_OP) == Felt::ONE)
        .expect("expected VM uint Is op row");
    assert_eq!(row_value(op_row, COL_FRAME_PARAM1), Felt::ZERO);
    assert_eq!(row_value(op_row, COL_BOUND_PTR), Felt::from(bound_ptr));

    traces.check();
}
