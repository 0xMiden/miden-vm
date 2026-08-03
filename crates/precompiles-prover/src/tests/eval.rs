//! Corruption tests for the transcript eval chiplet.

use std::vec::Vec;

use miden_core::{
    Felt,
    utils::{Matrix, RowMajorMatrix},
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
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
