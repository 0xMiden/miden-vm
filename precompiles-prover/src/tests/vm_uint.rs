//! Focused tests for VM uint caps.

use miden_core::Felt;
use miden_precompiles::{UintDomain, UintPrecompile};
use p3_matrix::Matrix;

use crate::{
    math::U256,
    session::Session,
    transcript::{
        eval::{
            COL_BOUND_PTR, COL_CAP_PARAM_B, COL_IS_PINNED, COL_IS_UINT_LEAF, COL_IS_UINT_OP,
            COL_PTR, NUM_MAIN_COLS as EVAL_NUM_MAIN_COLS,
        },
        nodes::UintOpId,
        poseidon2::{P2Cap, P2Digest, trace::Poseidon2Requires},
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
fn uint_value_hash_matches_vm_node_and_eq_op_cap() {
    let domain = UintDomain::U256;
    let value_limbs = limbs(0x1234_5678);
    let (lo, hi) = value_words(value_limbs);
    let value_node = UintPrecompile::value_node(domain, value_limbs);

    let actual_value =
        Poseidon2Requires::digest_of(P2Cap::uint_value(domain.bound_ptr()), &[(lo, hi)]);
    assert_eq!(actual_value, P2Digest::from(value_node.digest()));

    assert_eq!(
        P2Cap::uint_op(UintOpId::Is).as_array(),
        [
            UintPrecompile::id(),
            Felt::new(UintPrecompile::EQ_OP_ID).expect("uint EQ op id must fit in a felt"),
            Felt::ZERO,
            Felt::ZERO,
        ],
    );
}

#[test]
fn pin_claim_rows_commit_pin_ptr_but_vm_uint_rows_commit_bound_ptr() {
    const PIN_PTR: u32 = 1000;

    let mut session = Session::new();
    let root0 = session.zero();
    assert_eq!(root0.hash(), P2Digest::default());

    let domain = UintDomain::U256;
    let bound_ptr = domain.bound_ptr();

    let pinned_value = U256::from(9u8);
    let pin_claim = session.pin_uint(PIN_PTR, pinned_value, bound_ptr);
    let pinned_value_node = session.uint_leaf(pinned_value, bound_ptr);
    assert_eq!(pinned_value_node.ptr.addr(), PIN_PTR);
    assert_ne!(pin_claim.hash(), pinned_value_node.hash());

    let eq = session.uint_is(&pinned_value_node, &pinned_value_node);
    let root1 = session.assert_and(root0, pin_claim);
    let root = session.assert_and(root1, eq);

    let traces = session.finish(root);
    let eval = traces.mains()[7];
    let row_value = |row: usize, col: usize| eval.values[row * EVAL_NUM_MAIN_COLS + col];

    let pin_row = (0..eval.height())
        .find(|&row| {
            row_value(row, COL_IS_UINT_LEAF) == Felt::ONE
                && row_value(row, COL_IS_PINNED) == Felt::ONE
                && row_value(row, COL_PTR) == Felt::from(PIN_PTR)
        })
        .expect("expected pin row for explicit ptr");
    assert_eq!(row_value(pin_row, COL_CAP_PARAM_B), Felt::from(PIN_PTR));

    let value_row = (0..eval.height())
        .find(|&row| {
            row_value(row, COL_IS_UINT_LEAF) == Felt::ONE
                && row_value(row, COL_IS_PINNED) == Felt::ZERO
                && row_value(row, COL_PTR) == Felt::from(PIN_PTR)
        })
        .expect("expected VM uint value row for explicit ptr");
    assert_eq!(row_value(value_row, COL_CAP_PARAM_B), Felt::from(bound_ptr));

    let op_row = (0..eval.height())
        .find(|&row| row_value(row, COL_IS_UINT_OP) == Felt::ONE)
        .expect("expected VM uint Is op row");
    assert_eq!(row_value(op_row, COL_CAP_PARAM_B), Felt::ZERO);
    assert_eq!(row_value(op_row, COL_BOUND_PTR), Felt::from(bound_ptr));

    traces.check();
}
