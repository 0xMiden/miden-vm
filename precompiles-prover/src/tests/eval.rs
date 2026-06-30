//! Tests for the transcript eval chiplet (MVP tag-0 tree).
//!
//! Layout / [`LiftedAir`] smoke checks + trace-driven constraint checks
//! across `K = 0, 1, 2, 3, 7` (empty, single, mid-trace pad, exact pow2,
//! larger), plus the tree-specific shape: root at row 0 (first-row pin),
//! `ZERO_HASH` leaf, `out_mult`. Negatives confirm `check_constraints`
//! catches `act` binarity / sticky-down, the `is_zero` h-pin, the
//! first-row root pin, and the `out_mult` padding pin.
//!
//! Standalone (no Poseidon2 / KeccakNode chips), so the test validates
//! the eval chip's local constraints + its internal σ recurrence, not
//! cross-chiplet bus balance — that's the full-stack integration test.

use miden_core::{Felt, deferred::Tag, field::QuadFelt};
use miden_lifted_air::{BaseAir, LiftedAir};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    ec::trace::EcStoreRequires,
    logup::{NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    transcript::{
        eval::{
            COL_ACT, COL_CAP_PARAM_B, COL_H_BEGIN, COL_IS_PINNED, COL_IS_ZERO, COL_OUT_MULT,
            NUM_AUX_COLS, NUM_HASH, NUM_MAIN_COLS, NUM_PUBLIC_VALUES as EVAL_NUM_PUBLIC_VALUES,
            PUBLIC_ROOT_BEGIN, TranscriptEvalAir,
            trace::{TranscriptEvalRequires, Truthy, generate_trace, transcript_node_hash},
        },
        poseidon2::{P2Cap, P2Digest, trace::Poseidon2Requires},
    },
    uint::trace::{UintPtr, UintStoreRequires},
};

// HELPERS
// ================================================================================================

fn random_hash(rng: &mut impl Rng) -> P2Digest {
    P2Digest(core::array::from_fn(|_| Felt::new(rng.random()).unwrap()))
}

/// One AND fold (the standalone-test equivalent of
/// `Session::assert_and`) — the requires drives `p2` itself.
fn fold_one(
    requires: &mut TranscriptEvalRequires,
    p2: &mut Poseidon2Requires,
    a: Truthy,
    b: Truthy,
) -> Truthy {
    requires.record_and(a, b, p2)
}

/// Lay a transient uint leaf — the standalone-test stand-in for the
/// session pulling a uint's two 4×32 halves over `UintVal` and hashing
/// them. Bare-chiplet harness: the handles are forged and the `UintVal`
/// demand lands in a discarded scratch store (these tests judge the
/// eval chip alone).
fn lay_uint_leaf(
    req: &mut TranscriptEvalRequires,
    p2: &mut Poseidon2Requires,
    ptr: u32,
    bound_ptr: u32,
    value: [u32; 8],
) {
    let mut scratch = UintStoreRequires::new();
    req.uint_leaf(UintPtr::forged(ptr), UintPtr::forged(bound_ptr), value, &mut scratch, p2);
}

/// `K` random keccak-style claims left-folded from a `ZERO_HASH` base
/// (mirrors `Session::assert_and_fold`; `p2` supplies each AND hash).
/// Returns the laid main trace and its `public_root`.
fn build_eval_trace(rng: &mut impl Rng, k: usize) -> (RowMajorMatrix<Felt>, P2Digest) {
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();
    let handles: Vec<Truthy> = (0..k).map(|_| req.issue(random_hash(rng))).collect();
    let mut acc = req.zero();
    for h in handles {
        acc = fold_one(&mut req, &mut p2, acc, h);
    }
    let public_root = acc.hash();
    (generate_trace(req, acc, &EcStoreRequires::new()), public_root)
}

fn check_with_k(seed: u64, k: usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    let (main, public_root) = build_eval_trace(&mut rng, k);
    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

/// Same as [`check_with_k`] but applies a corruption to the trace and/or
/// the public root before checking.
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
fn uint_leaf_constraints_hold() {
    // ZERO_HASH root + two transient uint leaves. Exercises the eval chip's
    // one-hot node type + ptr / bound_ptr handling and its σ recurrence; the
    // pinned→True fork + cross-chiplet UintVal / Binding / Poseidon2 balance
    // are the integration test's job.
    let mut rng = StdRng::seed_from_u64(0x0157_1eaf);
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();

    let root = req.zero();
    let public_root = root.hash();
    let v1: [u32; 8] = core::array::from_fn(|_| rng.random());
    let v2: [u32; 8] = core::array::from_fn(|_| rng.random());
    lay_uint_leaf(&mut req, &mut p2, 7, 3, v1);
    lay_uint_leaf(&mut req, &mut p2, 9, 3, v2);

    let main = generate_trace(req, root, &EcStoreRequires::new());
    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

// LAYOUT / STRUCTURAL
// ================================================================================================

#[test]
fn main_column_layout_matches_declared_width() {
    // Layout is a contiguous partition by construction (each COL_* is
    // `prev + 1`); the load-bearing invariant is that the AIR's declared
    // width matches NUM_MAIN_COLS.
    assert_eq!(<TranscriptEvalAir as BaseAir<Felt>>::width(&TranscriptEvalAir), NUM_MAIN_COLS,);
}

#[test]
fn public_values_layout_is_transcript_root() {
    // 0.26 shares one `air_inputs` slice across all AIRs. For eval that slice
    // *is* the 4-felt transcript root: it begins at index 0 and spans the
    // whole shared count — no `inv_n` prefix as in the old σ/n layout.
    assert_eq!(PUBLIC_ROOT_BEGIN, 0);
    assert_eq!(EVAL_NUM_PUBLIC_VALUES, NUM_HASH);
    // Eval declares exactly the shared count: it neither extends nor shrinks
    // the common `air_inputs`.
    assert_eq!(EVAL_NUM_PUBLIC_VALUES, NUM_PUBLIC_VALUES);
    assert_eq!(
        <TranscriptEvalAir as BaseAir<Felt>>::num_public_values(&TranscriptEvalAir),
        EVAL_NUM_PUBLIC_VALUES,
    );
}

#[test]
fn lifted_air_validates_and_layout_matches_spec() {
    let air = TranscriptEvalAir;
    let layout = <TranscriptEvalAir as LiftedAir<Felt, QuadFelt>>::air_layout(&air);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, EVAL_NUM_PUBLIC_VALUES);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, NUM_SIGMA_VALUES);
    assert_eq!(layout.num_periodic_columns, 0);
}

#[test]
fn log_quotient_degree_matches_design_target() {
    // The uint-leaf seam keeps the one-hot node-type gates degree-1, so the
    // deg-2 `−out_mult` provide still tops col 0 at constraint deg 5 →
    // log_quotient_degree 2, unchanged from the AND-only chip.
    let air = TranscriptEvalAir;
    assert_eq!(crate::tests::log_quotient_degree(&air), 2);
}

// BUILDER
// ================================================================================================

#[test]
fn build_with_zero_root_yields_zero_hash() {
    // A lone ZERO_HASH leaf as root: one real row, public_root = 0. The trace
    // pads to the 0.26 two-row minimum (`TraceHeightTooSmall` below that).
    let mut req = TranscriptEvalRequires::new();
    let root = req.zero();
    let public_root = root.hash();
    let main = generate_trace(req, root, &EcStoreRequires::new());
    assert_eq!(public_root, P2Digest::default());
    assert_eq!(main.height(), 2);
}

#[test]
fn build_root_matches_left_leaning_chain() {
    // assert_and_fold from zero must equal the left-leaning chain:
    // (((0 ⋄ a) ⋄ b) ⋄ c), where x ⋄ y = Hash(x, y, cap).
    let a = P2Digest([Felt::from(1u32); 4]);
    let b = P2Digest([Felt::from(2u32); 4]);
    let c = P2Digest([Felt::from(3u32); 4]);

    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();
    let (ha, hb, hc) = (req.issue(a), req.issue(b), req.issue(c));
    let mut acc = req.zero();
    for h in [ha, hb, hc] {
        acc = fold_one(&mut req, &mut p2, acc, h);
    }
    let public_root = acc.hash();
    let main = generate_trace(req, acc, &EcStoreRequires::new());

    let t1 = transcript_node_hash(P2Digest::default(), a);
    let t2 = transcript_node_hash(t1, b);
    let t3 = transcript_node_hash(t2, c);
    assert_eq!(public_root, t3);

    // Root sits at row 0 (first-row pin), its h = public_root.
    let row0_h: [Felt; NUM_HASH] = core::array::from_fn(|i| main.values[COL_H_BEGIN + i]);
    assert_eq!(row0_h, t3.as_array());
}

#[test]
fn transcript_node_hash_uses_vm_and_cap() {
    let lhs = P2Digest([Felt::from(11u32); 4]);
    let rhs = P2Digest([Felt::from(22u32); 4]);
    let expected = Poseidon2Requires::digest_of(
        P2Cap(Tag::AND.as_word()),
        &[(lhs.as_array(), rhs.as_array())],
    );

    assert_eq!(transcript_node_hash(lhs, rhs), expected);
}

#[test]
fn each_fold_defers_one_perm_seq_id_to_p2() {
    let mut p2 = Poseidon2Requires::new();
    let prefill = P2Cap::chunk();
    let _ = p2.require_one_shot(prefill, [Felt::ONE; 4], [Felt::ONE; 4]);
    let cycles_before = p2.total_cycles();

    let mut req = TranscriptEvalRequires::new();
    let h1 = req.issue(P2Digest([Felt::from(7u8); 4]));
    let h2 = req.issue(P2Digest([Felt::from(8u8); 4]));
    let mut acc = req.zero();
    acc = fold_one(&mut req, &mut p2, acc, h1);
    acc = fold_one(&mut req, &mut p2, acc, h2);
    let _ = generate_trace(req, acc, &EcStoreRequires::new());

    // Two folds ⇒ two fresh p2 cycles past the prefill.
    assert_eq!(p2.total_cycles(), cycles_before + 2);
}

#[test]
fn zero_leaves_merge_into_one_row() {
    // Two sub-folds, each from its own zero leaf: AND(AND(0, k1), AND(0, k2)).
    // The two zero leaves share one is_zero row at out_mult 2.
    let mut rng = StdRng::seed_from_u64(0x2e_07);
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();
    let k1 = req.issue(random_hash(&mut rng));
    let k2 = req.issue(random_hash(&mut rng));
    let t1 = {
        let z = req.zero();
        fold_one(&mut req, &mut p2, z, k1)
    };
    let t2 = {
        let z = req.zero();
        fold_one(&mut req, &mut p2, z, k2)
    };
    let root = fold_one(&mut req, &mut p2, t1, t2);
    let public_root = root.hash();
    let main = generate_trace(req, root, &EcStoreRequires::new());

    // Exactly one is_zero row, carrying out_mult 2.
    let zero_rows: Vec<usize> = (0..main.height())
        .filter(|&r| main.values[r * NUM_MAIN_COLS + COL_IS_ZERO] == Felt::ONE)
        .collect();
    assert_eq!(zero_rows.len(), 1, "two zero leaves merge into one row");
    assert_eq!(main.values[zero_rows[0] * NUM_MAIN_COLS + COL_OUT_MULT], Felt::from(2u8),);

    // The merged trace still validates.
    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

#[test]
#[should_panic(expected = "stray unasserted")]
fn build_panics_on_stray_claim() {
    // A claim issued but never folded leaves its provider's out_mult with
    // no eval consume — a latent bus imbalance, caught here.
    let mut req = TranscriptEvalRequires::new();
    let _stray = req.issue(P2Digest([Felt::from(9u8); 4]));
    let root = req.zero();
    let _ = generate_trace(req, root, &EcStoreRequires::new());
}

#[test]
#[should_panic(expected = "must be a recorded node")]
fn build_panics_on_raw_keccak_root() {
    // A raw issued handle has no eval row, so it can't be pinned at row 0.
    let mut req = TranscriptEvalRequires::new();
    let h = req.issue(P2Digest([Felt::from(5u8); 4]));
    let _ = generate_trace(req, h, &EcStoreRequires::new());
}

// CONSTRAINT TESTS
// ================================================================================================

#[test]
fn constraints_hold_on_empty_transcript() {
    // K = 0: single ZERO_HASH-leaf root, public_root = 0.
    check_with_k(0x00, 0);
}

#[test]
fn constraints_hold_on_single_assertion() {
    // K = 1: root T_1 at row 0, ZERO_HASH leaf at row 1.
    check_with_k(0x01, 1);
}

#[test]
fn constraints_hold_with_padding() {
    // K = 2: 3 active rows (root, T_1, zero leaf), 1 padding row.
    check_with_k(0x02, 2);
}

#[test]
fn constraints_hold_on_exact_power_of_two() {
    // K = 3: 4 active rows, no padding.
    check_with_k(0x03, 3);
}

#[test]
fn constraints_hold_on_larger_tree() {
    // K = 7: 8 active rows, no padding.
    check_with_k(0x07, 7);
}

// NEGATIVE TESTS
// ================================================================================================

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
    // K = 3: ZERO_HASH leaf at row 3. Bumping its h breaks `is_zero·h = 0`.
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
    // Bump the public root; row 0's h no longer matches it.
    check_corrupted(0xc3, 3, |_| {}, |root| root.0[0] += Felt::ONE);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_empty_root_not_zero() {
    // K = 0: row 0 is a ZERO_HASH leaf (h = 0), so a non-zero public root
    // fails the first-row pin.
    check_corrupted(0xc4, 0, |_| {}, |root| root.0[2] = Felt::from(7u8));
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_out_mult_on_padding() {
    // K = 2: row 3 is padding. Setting its out_mult breaks `(1−act)·out_mult = 0`.
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
    // K = 2: flip row 0 inactive, leaving row 1 active — the 0→1 transition
    // violates sticky-down.
    check_corrupted(0xc6, 2, |main| main.values[COL_ACT] = Felt::ZERO, |_| {});
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_pinned_leaf_cap_slot_mismatch() {
    // A pinned uint leaf whose cap slot 2 (`pin_ptr`) is forged away from the ptr
    // its UintVal consume dereferences must be rejected.
    let mut rng = StdRng::seed_from_u64(0xf0_f6_3d);
    let mut p2 = Poseidon2Requires::new();
    let mut req = TranscriptEvalRequires::new();

    let zero = req.zero();
    let value: [u32; 8] = core::array::from_fn(|_| rng.random());
    let mut scratch = UintStoreRequires::new();
    let pinned = req.pin_uint(UintPtr::forged(7), UintPtr::forged(7), value, &mut scratch, &mut p2);
    let root = fold_one(&mut req, &mut p2, zero, pinned);
    let public_root = root.hash();
    let mut main = generate_trace(req, root, &EcStoreRequires::new());

    let pin_row = (0..main.height())
        .find(|&r| main.values[r * NUM_MAIN_COLS + COL_IS_PINNED] == Felt::ONE)
        .expect("trace has a pinned leaf row");
    main.values[pin_row * NUM_MAIN_COLS + COL_CAP_PARAM_B] += Felt::ONE;

    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}
