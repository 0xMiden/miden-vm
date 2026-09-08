//! Transcript eval corruption, shared-assertion demand, and root accounting.

use std::vec::Vec;

use miden_core::{
    Felt,
    utils::{Matrix, RowMajorMatrix},
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    session::Session,
    transcript::{
        eval::{
            COL_ACT, COL_H_BEGIN, COL_IS_PINNED, COL_IS_ZERO, COL_OUT_MULT, COL_PIN_CLAIM_PIN_PTR,
            NUM_MAIN_COLS, TranscriptEvalAir,
            trace::{TranscriptEvalRequires, Truthy, generate_trace},
        },
        poseidon2::{P2Digest, trace::Poseidon2Requires},
    },
    uint::trace::{UintPtr, UintStoreRequires},
};

#[test]
fn shared_assertions_balance_actual_operand_uses() {
    use miden_precompiles::{K1_BASE_BOUND_PTR, K1_GROUP_PTR};

    use crate::{
        hash::{chunk, keccak::node},
        math::U256,
    };

    let mut session = Session::new();
    let (_, keccak) = session.keccak(b"shared assertion");
    let (_, same_keccak) = session.keccak(b"shared assertion");
    let value = session.uint_leaf(U256::from(5u32), K1_BASE_BOUND_PTR);
    let equal = session.uint_is(&value, &value);
    let point = session.ec_pai(K1_GROUP_PTR);
    let point_equal = session.ec_is(&point, &point);
    let zero = session.zero();

    let shared = session.assert_and(equal, keccak);
    let repeated = session.assert_and(shared, shared);
    let with_child = session.assert_and(repeated, keccak);
    let with_alias = session.assert_and(with_child, same_keccak);
    let repeated_point = session.assert_and(point_equal, point_equal);
    let repeated_zero = session.assert_and(zero, zero);
    // The shared node occurs as both a constituent root and an internal child.
    let root = session.assert_and_fold([with_alias, repeated_point, repeated_zero, shared]);
    let traces = session.finish(root);
    let mains = traces.mains();
    let eval = mains[4];
    let multiplicity = |hash: P2Digest| {
        eval.values
            .as_chunks::<NUM_MAIN_COLS>()
            .0
            .iter()
            .filter(|row| row[COL_ACT] == Felt::ONE)
            .filter(|row| row[COL_H_BEGIN..COL_H_BEGIN + 4] == hash.as_array())
            .map(|row| row[COL_OUT_MULT])
            .sum::<Felt>()
    };
    assert_eq!(multiplicity(root.hash()), Felt::ZERO);
    assert_eq!(multiplicity(shared.hash()), Felt::from(3u32));
    assert_eq!(multiplicity(equal.hash()), Felt::ONE);
    assert_eq!(multiplicity(value.hash()), Felt::from(2u32));
    assert_eq!(multiplicity(point_equal.hash()), Felt::from(2u32));
    assert_eq!(multiplicity(zero.hash()), Felt::from(3u32));
    // Two computation requests, three binding uses, one Keccak provider row.
    assert_eq!(mains[0].values[chunk::NUM_MAIN_COLS + node::COL_OUT_MULT], Felt::from(3u32));
    let node_rows = mains[0]
        .values
        .chunks_exact(mains[0].width)
        .filter(|row| row[chunk::NUM_MAIN_COLS + node::COL_ACT] == Felt::ONE)
        .count();
    assert_eq!(node_rows, 1);

    traces.check();
}

#[test]
#[should_panic(expected = "stray unasserted claims")]
fn unused_internal_assertion_is_rejected() {
    let mut session = Session::new();
    let zero = session.zero();
    let _unused = session.assert_and(zero, zero);
    let root = session.zero();
    session.finish(root);
}

#[test]
#[should_panic(expected = "stray unasserted claims")]
fn unused_keccak_alias_is_rejected() {
    let mut session = Session::new();
    let (_, used) = session.keccak(b"same computation");
    let _unused = session.keccak(b"same computation");
    let root = session.assert_and(used, used);
    session.finish(root);
}

#[test]
#[should_panic(expected = "root has parents")]
fn final_root_with_parent_is_rejected() {
    let mut req = TranscriptEvalRequires::new();
    let mut p2 = Poseidon2Requires::new();
    let zero = req.zero();
    let root = req.record_and(zero, zero, &mut p2);
    let _parent = req.record_and(root, root, &mut p2);
    generate_trace(req, root);
}

#[test]
#[should_panic(expected = "root must be a recorded node")]
fn external_assertion_cannot_bind_the_final_root() {
    let mut session = Session::new();
    let (_, root) = session.keccak(b"bare external root");
    assert!(!session.is_recorded_truth(root));
    session.finish(root);
}

fn random_hash(rng: &mut impl Rng) -> P2Digest {
    P2Digest(core::array::from_fn(|_| Felt::new(rng.random()).unwrap()))
}

fn fold_one(
    requires: &mut TranscriptEvalRequires,
    p2: &mut Poseidon2Requires,
    a: Truthy,
    b: Truthy,
) -> Truthy {
    requires.record_and(a, b, p2)
}

fn build_eval_trace(rng: &mut impl Rng, k: usize) -> (RowMajorMatrix<Felt>, P2Digest) {
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();
    let handles = (0..k).map(|_| req.issue(random_hash(rng))).collect::<Vec<_>>();
    let mut acc = req.zero();
    for handle in handles {
        acc = fold_one(&mut req, &mut p2, acc, handle);
    }
    let public_root = acc.hash();
    (generate_trace(req, acc), public_root)
}

fn check_corrupted(
    seed: u64,
    k: usize,
    corrupt_trace: impl FnOnce(&mut RowMajorMatrix<Felt>),
    corrupt_public_root: impl FnOnce(&mut P2Digest),
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut main, mut public_root) = build_eval_trace(&mut rng, k);
    corrupt_trace(&mut main);
    corrupt_public_root(&mut public_root);
    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_act() {
    check_corrupted(0xc0, 1, |main| main.values[COL_ACT] = Felt::from(2u8), |_| {});
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_non_binary_is_zero() {
    check_corrupted(0xc1, 3, |main| main.values[COL_IS_ZERO] = Felt::from(2u8), |_| {});
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_zero_leaf_h_not_zero() {
    check_corrupted(
        0xc2,
        3,
        |main| main.values[3 * NUM_MAIN_COLS + COL_H_BEGIN] += Felt::ONE,
        |_| {},
    );
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_first_row_root_pin() {
    check_corrupted(0xc3, 3, |_| {}, |root| root.0[0] += Felt::ONE);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_empty_root_not_zero() {
    check_corrupted(0xc4, 0, |_| {}, |root| root.0[2] = Felt::from(7u8));
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_out_mult_on_padding() {
    check_corrupted(
        0xc5,
        2,
        |main| main.values[3 * NUM_MAIN_COLS + COL_OUT_MULT] = Felt::ONE,
        |_| {},
    );
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_act_sticky_down() {
    check_corrupted(0xc6, 2, |main| main.values[COL_ACT] = Felt::ZERO, |_| {});
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_pinned_leaf_cap_slot_mismatch() {
    let mut rng = StdRng::seed_from_u64(0xf0_f6_3d);
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();

    let zero = req.zero();
    let value = core::array::from_fn(|_| rng.random());
    let mut scratch = UintStoreRequires::new();
    let pinned =
        req.pin_uint(UintPtr::from_addr(7), UintPtr::from_addr(7), value, &mut scratch, &mut p2);
    let root = fold_one(&mut req, &mut p2, zero, pinned);
    let public_root = root.hash();
    let mut main = generate_trace(req, root);

    let pin_row = (0..main.height())
        .find(|&r| main.values[r * NUM_MAIN_COLS + COL_IS_PINNED] == Felt::ONE)
        .expect("trace has a pinned leaf row");
    main.values[pin_row * NUM_MAIN_COLS + COL_PIN_CLAIM_PIN_PTR] += Felt::ONE;

    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}
