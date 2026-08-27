//! Layout, lookup, and corruption tests for the transcript eval chiplet.

use std::{vec, vec::Vec};

use miden_air::lookup::{
    LookupAir, LookupMessage,
    debug::{DebugTraceBuilder, ValidateLayout, ValidateLookupAir, collect_column_oracle_folds},
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, ConstraintDegrees, LiftedAir};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    ec::EcPointMsg,
    logup::{Challenges, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::assert_same_rational_fold,
    transcript::{
        eidos::{EidosDigest, trace::EidosRequires},
        eval::{
            COL_A_PTR, COL_ACT, COL_B_PTR, COL_BOUND_PTR, COL_EC_CREATE_GROUP_PTR,
            COL_EC_CREATE_POINT_PTR, COL_EC_CREATE_X_PTR, COL_EC_CREATE_Y_PTR, COL_H_BEGIN,
            COL_IS_EC_CREATE, COL_IS_EC_PAI, COL_IS_MUL, COL_IS_PINNED, COL_IS_UINT_LEAF,
            COL_IS_UINT_OP, COL_IS_ZERO, COL_LHS_BEGIN, COL_OUT_MULT, COL_PIN_CLAIM_PIN_PTR,
            COL_PTR, COL_RHS_BEGIN, DIGEST_WIDTH, NUM_MAIN_COLS, TranscriptEvalAir,
            trace::{TranscriptEvalRequires, Truthy, generate_trace},
        },
    },
    uint::{
        UintValMsg,
        mul::UintMulMsg,
        trace::{UintPtr, UintStoreRequires},
    },
};

const TYPED_RELATION_COL: usize = 3;

#[test]
fn shape_and_degree_match_design() {
    let air = TranscriptEvalAir;

    assert_eq!(air.width(), 39);
    assert_eq!(air.aux_width(), 12);
    assert_eq!(
        <TranscriptEvalAir as LookupAir<DebugTraceBuilder<'_>>>::column_shape(&air),
        &[1, 2, 2, 1, 1, 2, 1, 2, 1, 1, 2, 2]
    );
    assert_eq!(
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air),
        ConstraintDegrees { base: 3, ext: 3 }
    );
    assert_eq!(crate::tests::log_quotient_degree(&air), 1);

    ValidateLookupAir::validate(
        &air,
        ValidateLayout {
            preprocessed_width: air.preprocessed_width(),
            trace_width: air.width(),
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: air.periodic_columns().len(),
            permutation_width: air.aux_width(),
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: NUM_SIGMA_VALUES,
        },
    )
    .unwrap_or_else(|err| panic!("TranscriptEvalAir lookup validation failed: {err}"));
}

fn typed_relation_fold(row: Vec<Felt>, challenges: &Challenges<QuadFelt>) -> (QuadFelt, QuadFelt) {
    let air = TranscriptEvalAir;
    let main = RowMajorMatrix::new(row, NUM_MAIN_COLS);
    let periodic = air.periodic_columns();
    let public_values = [Felt::ZERO; NUM_PUBLIC_VALUES];
    let folds = collect_column_oracle_folds(&air, &main, &periodic, &public_values, challenges);
    folds[0][TYPED_RELATION_COL]
}

#[test]
fn typed_relation_column_preserves_each_selected_message() {
    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let mut payload = vec![Felt::ZERO; NUM_MAIN_COLS];
    payload[COL_PTR] = Felt::from(11u8);
    payload[COL_BOUND_PTR] = Felt::from(12u8);
    payload[COL_A_PTR] = Felt::from(13u8);
    payload[COL_B_PTR] = Felt::from(14u8);
    payload[COL_EC_CREATE_GROUP_PTR] = Felt::from(15u8);
    for i in 0..DIGEST_WIDTH {
        payload[COL_LHS_BEGIN + i] = Felt::from((20 + i) as u8);
        payload[COL_RHS_BEGIN + i] = Felt::from((30 + i) as u8);
    }

    let assert_selected = |row: Vec<Felt>, denominator: QuadFelt, context: &str| {
        assert_same_rational_fold(
            typed_relation_fold(row, &challenges),
            (QuadFelt::ONE, denominator),
            context,
        );
    };

    let mut uint_leaf = payload.clone();
    uint_leaf[COL_IS_UINT_LEAF] = Felt::ONE;
    let uint_leaf_denominator = UintValMsg {
        ptr: uint_leaf[COL_PTR],
        bound_ptr: uint_leaf[COL_BOUND_PTR],
        limbs: core::array::from_fn(|i| {
            if i < DIGEST_WIDTH {
                uint_leaf[COL_LHS_BEGIN + i]
            } else {
                uint_leaf[COL_RHS_BEGIN + i - DIGEST_WIDTH]
            }
        }),
    }
    .encode(&challenges);
    assert_selected(uint_leaf, uint_leaf_denominator, "UintVal branch");

    let mut uint_mul = payload.clone();
    uint_mul[COL_IS_MUL] = Felt::ONE;
    let uint_mul_denominator = UintMulMsg {
        kappa_a: Felt::ONE,
        kappa_c: Felt::ZERO,
        a_ptr: uint_mul[COL_A_PTR],
        b_ptr: uint_mul[COL_B_PTR],
        c_ptr: uint_mul[COL_BOUND_PTR],
        r_ptr: uint_mul[COL_PTR],
        bound_ptr: uint_mul[COL_BOUND_PTR],
        is_sub: Felt::ZERO,
    }
    .encode(&challenges);
    assert_selected(uint_mul, uint_mul_denominator, "UintMul branch");

    for (is_pai, context) in [(false, "finite EcPoint branch"), (true, "PAI EcPoint branch")] {
        let mut ec_point = payload.clone();
        ec_point[if is_pai { COL_IS_EC_PAI } else { COL_IS_EC_CREATE }] = Felt::ONE;
        if is_pai {
            ec_point[COL_EC_CREATE_X_PTR] = Felt::ZERO;
            ec_point[COL_EC_CREATE_Y_PTR] = Felt::ZERO;
        }
        let denominator = EcPointMsg {
            point_ptr: ec_point[COL_EC_CREATE_POINT_PTR],
            group_ptr: ec_point[COL_EC_CREATE_GROUP_PTR],
            x_ptr: ec_point[COL_EC_CREATE_X_PTR],
            y_ptr: ec_point[COL_EC_CREATE_Y_PTR],
            is_pai: if is_pai { Felt::ONE } else { Felt::ZERO },
        }
        .encode(&challenges);
        assert_selected(ec_point, denominator, context);
    }

    assert_same_rational_fold(
        typed_relation_fold(payload, &challenges),
        (QuadFelt::ZERO, QuadFelt::ONE),
        "inactive rows must contribute the rational zero",
    );
}

fn random_hash(rng: &mut impl Rng) -> EidosDigest {
    EidosDigest(core::array::from_fn(|_| Felt::new(rng.random()).unwrap()))
}

fn fold_one(
    requires: &mut TranscriptEvalRequires,
    eidos: &mut EidosRequires,
    a: Truthy,
    b: Truthy,
) -> Truthy {
    requires.record_and(a, b, eidos)
}

fn build_eval_trace(rng: &mut impl Rng, k: usize) -> (RowMajorMatrix<Felt>, EidosDigest) {
    let mut eidos = EidosRequires::new();
    let mut req = TranscriptEvalRequires::new();
    let handles = (0..k).map(|_| req.issue(random_hash(rng))).collect::<Vec<_>>();
    let mut acc = req.zero();
    for handle in handles {
        acc = fold_one(&mut req, &mut eidos, acc, handle);
    }
    let public_root = acc.hash();
    (generate_trace(req, acc), public_root)
}

fn check_corrupted(
    seed: u64,
    k: usize,
    corrupt_trace: impl FnOnce(&mut RowMajorMatrix<Felt>),
    corrupt_public_root: impl FnOnce(&mut EidosDigest),
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut main, mut public_root) = build_eval_trace(&mut rng, k);
    corrupt_trace(&mut main);
    corrupt_public_root(&mut public_root);
    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

fn build_pinned_uint_trace(seed: u64) -> (RowMajorMatrix<Felt>, EidosDigest, usize) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut eidos = EidosRequires::new();
    let mut req = TranscriptEvalRequires::new();

    let zero = req.zero();
    let value = core::array::from_fn(|_| rng.random());
    let mut scratch = UintStoreRequires::new();
    let pinned =
        req.pin_uint(UintPtr::from_addr(7), UintPtr::from_addr(7), value, &mut scratch, &mut eidos);
    let root = fold_one(&mut req, &mut eidos, zero, pinned);
    let public_root = root.hash();
    let main = generate_trace(req, root);
    let pin_row = (0..main.height())
        .find(|&r| main.values[r * NUM_MAIN_COLS + COL_IS_PINNED] == Felt::ONE)
        .expect("trace has a pinned leaf row");

    (main, public_root, pin_row)
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
fn corruption_pinned_leaf_chain_context_slot_mismatch() {
    let (mut main, public_root, pin_row) = build_pinned_uint_trace(0xf0_f6_3d);
    main.values[pin_row * NUM_MAIN_COLS + COL_PIN_CLAIM_PIN_PTR] += Felt::ONE;

    crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
}

#[test]
fn packed_relation_selectors_fail_closed_on_overlap() {
    let (mut main, public_root, pin_row) = build_pinned_uint_trace(0x1412_0bad);
    assert_eq!(main.values[pin_row * NUM_MAIN_COLS + COL_IS_UINT_LEAF], Felt::ONE);
    assert_eq!(main.values[pin_row * NUM_MAIN_COLS + COL_IS_UINT_OP], Felt::ZERO);
    assert_eq!(main.values[pin_row * NUM_MAIN_COLS + COL_IS_MUL], Felt::ZERO);

    main.values[pin_row * NUM_MAIN_COLS + COL_IS_UINT_OP] = Felt::ONE;
    main.values[pin_row * NUM_MAIN_COLS + COL_IS_MUL] = Felt::ONE;

    let rejected = std::panic::catch_unwind(|| {
        crate::tests::check_local_inputs(TranscriptEvalAir, &main, public_root.as_array().to_vec());
    })
    .is_err();
    assert!(rejected, "overlapping packed-relation selectors must be rejected");
}
