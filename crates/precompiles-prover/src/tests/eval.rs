//! Corruption tests for the transcript eval chiplet.

use std::vec::Vec;

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_precompiles_air::hash::{
    chunk_node::NODE_COL_OFFSET, keccak::node::COL_OUT_MULT as KECCAK_OUT_MULT,
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::Session,
    tests::bus_balance::session_stack_residual,
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
fn shared_truthy_claims_balance_and_reject_wrong_multiplicities() {
    let mut session = Session::new();
    // Separate registrations of one Keccak input must also accumulate uses on one provider.
    let (_, first) = session.keccak(b"shared claim");
    let (_, second) = session.keccak(b"shared claim");
    let pair = session.assert_and(first, first);
    let left = session.assert_and(pair, first);
    let right = session.assert_and(second, second);
    let branch = session.assert_and(left, right);
    let root = session.assert_and(branch, pair);
    let traces = session.finish(root);
    traces.check();
    let mains = traces.mains();
    assert_eq!(mains[0].values[NODE_COL_OFFSET + KECCAK_OUT_MULT], Felt::from_u32(5));

    let mut rng = StdRng::seed_from_u64(3787);
    let alpha = QuadFelt::new([rng.random::<Felt>(), rng.random::<Felt>()]);
    let beta = QuadFelt::new([rng.random::<Felt>(), rng.random::<Felt>()]);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    assert!(session_stack_residual(&mains, &[], &challenges).is_empty());
    let shared_and = mains[4]
        .values
        .as_chunks::<NUM_MAIN_COLS>()
        .0
        .iter()
        .position(|row| row[COL_OUT_MULT] == Felt::from_u32(2))
        .unwrap();
    for (chip, offset) in [
        (0, NODE_COL_OFFSET + KECCAK_OUT_MULT),
        (4, shared_and * NUM_MAIN_COLS + COL_OUT_MULT),
    ] {
        for delta in [Felt::ONE, -Felt::ONE] {
            let mut corrupted = mains[chip].clone();
            corrupted.values[offset] += delta;
            assert!(!session_stack_residual(&mains, &[(chip, &corrupted)], &challenges).is_empty());
        }
    }
}

#[test]
#[should_panic(expected = "stray unasserted claims")]
fn unused_truthy_claim_is_rejected_even_when_its_hash_is_used() {
    let mut session = Session::new();
    let _unused = session.zero();
    let used = session.zero();
    let root = session.assert_and(used, used);
    session.finish(root);
}

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
#[should_panic(expected = "stray unasserted Keccak claim")]
fn unused_keccak_alias_is_rejected() {
    let mut session = Session::new();
    let (_, used) = session.keccak(b"same computation");
    let _unused = session.keccak(b"same computation");
    let root = session.assert_and(used, used);
    session.finish(root);
}

#[test]
#[should_panic(expected = "root must be an unconsumed recorded truthy claim")]
fn final_root_with_parent_is_rejected() {
    let mut req = TranscriptEvalRequires::new();
    let mut p2 = Poseidon2Requires::new();
    let zero = req.zero();
    let root = req.record_and(zero, zero, &mut p2);
    let _parent = req.record_and(root, root, &mut p2);
    generate_trace(req, root);
}

#[test]
#[should_panic(expected = "stray unasserted Keccak claim")]
fn external_assertion_cannot_bind_the_final_root() {
    let mut session = Session::new();
    let (_, root) = session.keccak(b"bare external root");
    assert!(!session.is_recorded_truth(root));
    session.finish(root);
}

fn random_hash(rng: &mut impl Rng) -> P2Digest {
    P2Digest(core::array::from_fn(|_| rng.random::<Felt>()))
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
