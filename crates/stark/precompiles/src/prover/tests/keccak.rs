//! Integration tests for the Keccak-round miniVM chiplet.
//!
//! Drives the production [`generate_trace`] against a reference Keccak-f[1600]
//! implementation, reading the lane outputs back from the trace, and runs
//! `check_constraints` on the resulting AIR/witness pair.

use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_stark::{
    air::{BaseAir, ConstraintDegrees, LiftedAir},
    lookup::{
        LookupFractions, build_lookup_fractions,
        debug::{ValidateLayout, ValidateLookupAir},
    },
};
use proptest::prelude::*;

use crate::prover::{
    hash::keccak::{
        reference::{KECCAK_RC, keccak_f1600, keccak_round},
        round::{
            A_BYTES_RANGE, B_BYTES_RANGE, COL_ACT, KeccakRoundAir, NUM_AUX_COLS, NUM_LANES,
            NUM_MAIN_COLS, NUM_ROUNDS, PERM_CYCLE, R_BYTES_RANGE, ROT_MASK_XOR_RANGE, ROUND_PERIOD,
            RoundRequires, generate_trace, lane_base,
            program::{self, SLOT_D_ROL_BEGIN},
        },
    },
    logup::{Challenges, NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{ChipletAir, Session},
    tests::{bus_balance::session_stack_residual, lookup_column_folds},
};

fn lookup_challenges() -> Challenges<QuadFelt> {
    Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    )
}

fn fractions_at(
    fractions: &LookupFractions<Felt, QuadFelt>,
    row: usize,
    column: usize,
) -> &[(Felt, QuadFelt)] {
    let count_idx = row * fractions.num_columns() + column;
    let start = fractions.counts()[..count_idx].iter().sum::<usize>();
    let end = start + fractions.counts()[count_idx];
    &fractions.fractions()[start..end]
}

// TESTS
// ================================================================================================

/// The round ledger for `states`: the production generator seeds each permutation from its
/// round-0 state and derives the later rounds itself, so the remaining entries are unused.
fn round_requires(states: &[[u64; 25]]) -> RoundRequires {
    let mut requires = RoundRequires::new();
    for state in states {
        for round in 0..NUM_ROUNDS {
            requires.require_round(if round == 0 { *state } else { [0u64; 25] });
        }
    }
    requires
}

/// Builds the production round trace for `states`, with the cycle's byte lookups in a scratch
/// ledger: these fixtures check row-local constraints and read lane values, not bus balance.
fn trace_for(states: &[[u64; 25]]) -> RowMajorMatrix<Felt> {
    generate_trace(round_requires(states), &mut BytePairLutRequires::new())
}

/// Reads the 25 output lanes of `perm` after `round` from `main`.
///
/// Every lane's output is the `x` operand of its producer row: the iota row for lane 0, and the
/// chi-XOR rows for the rest. The rows of a permutation start at its offset in the lane that
/// holds it, and each round takes `ROUND_PERIOD` rows.
fn trace_lanes(
    main: &RowMajorMatrix<Felt>,
    num_perms: usize,
    perm: usize,
    round: usize,
) -> [u64; 25] {
    let perms_per_lane = num_perms.max(1).div_ceil(NUM_LANES);
    let lane = perm / perms_per_lane;
    let perm_rows = (perm % perms_per_lane) * PERM_CYCLE;
    let width = main.width();
    let read = |slot: usize| -> u64 {
        let row = perm_rows + round * ROUND_PERIOD + slot;
        let start = row * width + lane_base(lane) + R_BYTES_RANGE.start;
        main.values[start..start + 8]
            .iter()
            .enumerate()
            .fold(0u64, |value, (i, byte)| value | (byte.as_canonical_u64() << (8 * i)))
    };

    let mut lanes = [0u64; 25];
    lanes[0] = read(program::SLOT_IOTA);
    for (idx, lane_value) in lanes.iter_mut().enumerate().skip(1) {
        *lane_value = read(program::SLOT_CHI_XOR_BEGIN + idx - 1);
    }
    lanes
}

#[test]
fn chiplet_one_round_matches_reference_zero_input() {
    let state = [0u64; 25];
    let mut expected = state;
    keccak_round(&mut expected, KECCAK_RC[0]);
    let main = trace_for(&[state]);
    let got = trace_lanes(&main, 1, 0, 0);
    for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
        assert_eq!(g, e, "lane {i} (x={}, y={})", i % 5, i / 5);
    }
}

/// Run `n` rounds via chiplet by reading the per-round outputs and
/// feeding them back as the next round's inputs. Compares against the
/// reference round by round.
#[test]
fn chiplet_two_rounds_match_reference_zero_input() {
    let state = [0u64; 25];
    let main = trace_for(&[state]);
    let mut expected = state;
    for (r, &rc) in KECCAK_RC.iter().enumerate().take(2) {
        keccak_round(&mut expected, rc);
        let got = trace_lanes(&main, 1, 0, r);
        for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
            assert_eq!(g, e, "round {r}, lane {i} (x={}, y={})", i % 5, i / 5);
        }
    }
}

/// Trace the chiplet through N rounds in one shot and compare with the
/// N-round reference.
#[test]
fn chiplet_full_permutation_matches_reference_zero_input_internal() {
    let state = [0u64; 25];
    let mut expected = state;
    for &rc in KECCAK_RC.iter().take(NUM_ROUNDS) {
        keccak_round(&mut expected, rc);
    }
    let main = trace_for(&[state]);
    let got = trace_lanes(&main, 1, 0, NUM_ROUNDS - 1);
    assert_eq!(got, expected);
}

#[test]
fn extract_output_matches_reference_keccak_zero_input() {
    let state = [0u64; 25];
    let expected = keccak_f1600(state);
    let main = trace_for(&[state]);
    let got = trace_lanes(&main, 1, 0, NUM_ROUNDS - 1);
    assert_eq!(got, expected, "all-zero input");
}

#[test]
fn extract_output_matches_reference_keccak_canonical_test_vectors() {
    // A handful of arbitrary patterns.
    let mut state = [0u64; 25];
    for (i, lane) in state.iter_mut().enumerate() {
        *lane = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    let expected = keccak_f1600(state);
    let main = trace_for(&[state]);
    let got = trace_lanes(&main, 1, 0, NUM_ROUNDS - 1);
    assert_eq!(got, expected, "patterned input");
}

#[test]
fn keccak_round_constraints_hold_on_canonical_input() {
    let state = [0u64; 25];

    let main = trace_for(&[state]);
    assert_eq!(main.height(), PERM_CYCLE.next_power_of_two());

    crate::prover::tests::check_local(KeccakRoundAir, &main);
}

#[test]
fn keccak_round_shape_and_degree_match_design() {
    let air = KeccakRoundAir;

    assert_eq!(air.width(), 56);
    assert_eq!(air.aux_width(), 8);
    assert_eq!(crate::prover::tests::lookup_column_shape(&air), &[3, 4, 4, 2, 3, 4, 4, 2],);
    assert_eq!(
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air),
        ConstraintDegrees { base: 2, ext: 5 }
    );
    assert_eq!(crate::prover::tests::log_quotient_degree(&air), 2);

    let layout = ValidateLayout {
        preprocessed_width: air.preprocessed_width(),
        trace_width: air.width(),
        num_public_values: 0,
        num_periodic_columns: air.periodic_columns().len(),
        permutation_width: NUM_AUX_COLS,
        num_permutation_challenges: NUM_RANDOMNESS,
        num_permutation_values: NUM_LOGUP_VALUES,
    };
    ValidateLookupAir::validate(&air, layout)
        .unwrap_or_else(|err| panic!("KeccakRoundAir lookup validation failed: {err}"));
}

#[test]
fn pure_rol_raw_b_affects_every_byte_and_lane() {
    let states = [[0x0123_4567_89ab_cdef; 25], [0xfedc_ba98_7654_3210; 25]];
    let main = trace_for(&states);
    let row = SLOT_D_ROL_BEGIN;
    let air = KeccakRoundAir;
    let one_row = RowMajorMatrix::new(
        main.values[row * NUM_MAIN_COLS..(row + 1) * NUM_MAIN_COLS].to_vec(),
        NUM_MAIN_COLS,
    );
    let periodic_columns = air.periodic_columns();
    let periodic: Vec<Vec<Felt>> =
        periodic_columns.iter().map(|column| vec![column[row % column.len()]]).collect();
    let challenges = lookup_challenges();
    let baseline = build_lookup_fractions(&air, &one_row, None, &periodic, &challenges);
    let baseline_folds = lookup_column_folds(&baseline);

    for lane in 0..NUM_LANES {
        let lane_base = lane_base(lane);
        assert_eq!(one_row.values[lane_base + COL_ACT], Felt::ONE);

        for byte in 0..B_BYTES_RANGE.len() {
            let cell = lane_base + B_BYTES_RANGE.start + byte;
            assert_eq!(one_row.values[cell], Felt::ZERO);

            let mut attacked = one_row.clone();
            attacked.values[cell] = Felt::ONE;
            let attacked_fractions =
                build_lookup_fractions(&air, &attacked, None, &periodic, &challenges);
            let attacked_folds = lookup_column_folds(&attacked_fractions);
            let target_col = lane * (NUM_AUX_COLS / NUM_LANES) + 1 + byte / 4;
            let source_col = lane * (NUM_AUX_COLS / NUM_LANES);

            for col in 0..NUM_AUX_COLS {
                let attacked_fold = attacked_folds[0][col];
                let baseline_fold = baseline_folds[0][col];
                if col == target_col {
                    let (attacked_v, attacked_u) = attacked_fold;
                    let (baseline_v, baseline_u) = baseline_fold;
                    assert_ne!(attacked_v * baseline_u, baseline_v * attacked_u);
                } else {
                    assert_eq!(attacked_fold, baseline_fold);
                    if col == source_col {
                        // `src_b` has zero multiplicity on a pure-ROL row, so the
                        // production collector omits it; the destination and `src_a`
                        // fractions remain unchanged in this column.
                        assert_eq!(
                            fractions_at(&attacked_fractions, 0, col),
                            fractions_at(&baseline, 0, col),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn pure_rol_nonzero_b_unbalances_the_full_chiplet_stack() {
    let mut session = Session::new();
    let (_, claim) = session.keccak(b"KeccakRound raw-b binding");
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    let mains = traces.mains();
    let challenges = lookup_challenges();
    let round_idx = ChipletAir::all()
        .into_iter()
        .position(|air| air == ChipletAir::KECCAK_ROUND)
        .expect("KeccakRound is present in the chiplet stack");

    let honest = session_stack_residual(&mains, &[], &challenges);
    assert!(honest.is_empty(), "honest session must balance: {honest:#?}");

    let mut attacked = mains[round_idx].clone();
    let cell = SLOT_D_ROL_BEGIN * NUM_MAIN_COLS + B_BYTES_RANGE.start;
    assert_eq!(attacked.values[cell], Felt::ZERO);
    attacked.values[cell] = Felt::ONE;
    let residual = session_stack_residual(&mains, &[(round_idx, &attacked)], &challenges);

    assert!(
        !residual.is_empty(),
        "a forged pure-ROL operand must leave a lookup residual: {residual:#?}"
    );
}

// NEGATIVE TESTS — confirm `check_constraints` catches deliberate corruption.
// ================================================================================================

/// On the first pure-ROL row, forge the otherwise valid byte lookup `Xor(0, 1, 1)` and update the
/// split-byte XOR to preserve its masked-byte lookup. The local `x = a`
/// passthrough constraint must be the remaining reason this trace is rejected.
#[test]
#[should_panic(expected = "constraint not satisfied")]
fn pure_rol_passthrough_rejects_bpl_valid_nonzero_b() {
    let mut main = trace_for(&[[0u64; 25]]);
    let row_start = SLOT_D_ROL_BEGIN * NUM_MAIN_COLS;

    for col in [A_BYTES_RANGE.start, B_BYTES_RANGE.start, R_BYTES_RANGE.start] {
        assert_eq!(main.values[row_start + col], Felt::ZERO);
    }

    main.values[row_start + B_BYTES_RANGE.start] = Felt::ONE;
    main.values[row_start + R_BYTES_RANGE.start] = Felt::ONE;
    main.values[row_start + ROT_MASK_XOR_RANGE.start] = Felt::from(128u8);

    crate::prover::tests::check_local(KeccakRoundAir, &main);
}

#[test]
fn corruption_rotation_mask_unbalances_the_full_chiplet_stack() {
    let mut session = Session::new();
    let (_, claim) = session.keccak(&[0xa5; 200]);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    traces.check();
    let mains = traces.mains();
    let challenges = lookup_challenges();
    let round_idx = ChipletAir::all()
        .into_iter()
        .position(|air| air == ChipletAir::KECCAK_ROUND)
        .unwrap();
    assert!(session_stack_residual(&mains, &[], &challenges).is_empty());
    for lane in 0..NUM_LANES {
        for half in 0..2 {
            let mut attacked = mains[round_idx].clone();
            let cell = SLOT_D_ROL_BEGIN * NUM_MAIN_COLS
                + lane_base(lane)
                + ROT_MASK_XOR_RANGE.start
                + half;
            attacked.values[cell] += Felt::ONE;
            assert!(
                !session_stack_residual(&mains, &[(round_idx, &attacked)], &challenges).is_empty(),
                "a corrupted split-byte XOR must leave a lookup residual"
            );
        }
    }
}

#[test]
fn packed_passthrough_aliases_preserve_memory_but_fail_canonical_byte_checks() {
    let mut session = Session::new();
    let (_, claim) = session.keccak(&[0x5a; 200]);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    traces.check();
    let mains = traces.mains();
    let challenges = lookup_challenges();
    let index = ChipletAir::all()
        .into_iter()
        .position(|air| air == ChipletAir::KECCAK_ROUND)
        .unwrap();
    let honest = mains[index];
    assert!(session_stack_residual(&mains, &[], &challenges).is_empty());
    for lane in 0..NUM_LANES {
        for half in 0..2 {
            let mut forged = honest.clone();
            let row = SLOT_D_ROL_BEGIN * NUM_MAIN_COLS + lane_base(lane);
            // ROL(1) selects byte 3 of each half. Altering bytes 0 and 1 together preserves
            // source/destination words, carries, mask lookups and the packed passthrough tie.
            for bytes in [A_BYTES_RANGE, R_BYTES_RANGE] {
                let start = row + bytes.start;
                let expected = crate::prover::utils::halves_le::<Felt, _>(
                    &honest.values[start..start + 8],
                    256,
                );
                forged.values[start + 4 * half] += Felt::from_u16(256);
                forged.values[start + 4 * half + 1] -= Felt::ONE;
                assert_eq!(
                    crate::prover::utils::halves_le::<Felt, _>(
                        &forged.values[start..start + 8],
                        256
                    ),
                    expected,
                );
            }
            crate::prover::tests::check_local(KeccakRoundAir, &forged);
            assert!(!session_stack_residual(&mains, &[(index, &forged)], &challenges).is_empty());
        }
    }
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(4))]

    /// The chiplet's output, read back from its production trace, must agree with the reference
    /// permutation for arbitrary lane values. Capped at 4 cases because each case generates and
    /// reads back a full 3200-row trace; uniform lanes shrink toward zero on failure.
    #[test]
    fn trace_output_matches_reference_keccak_random_input(state in any::<[u64; 25]>()) {
        let expected = keccak_f1600(state);
        let main = trace_for(&[state]);
        let got = trace_lanes(&main, 1, 0, NUM_ROUNDS - 1);
        prop_assert_eq!(got, expected);
    }
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(16))]

    /// Round constraints must hold for arbitrary lane values. Capped at 16 cases because each
    /// case generates and checks a full trace (~0.5s); still 16x the coverage of the seeded
    /// single draw it replaces, with shrinking.
    #[test]
    fn keccak_round_constraints_hold_on_random_input(state in any::<[u64; 25]>()) {
        let main = trace_for(&[state]);

        crate::prover::tests::check_local(KeccakRoundAir, &main);
    }
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(8))]

    /// Stack 3 independent perms of arbitrary states in one trace and verify both per-perm
    /// output correctness (read back from the trace) and constraint satisfaction. With
    /// NUM_LANES=2, the 3 perms split into a busiest lane of `⌈3/2⌉ = 2` perms, so the height
    /// is `2 * 3200 = 6400` padded to `8192`. Capped at 8 cases: each case generates and
    /// checks a 3-perm trace.
    #[test]
    fn keccak_round_multi_perm_oracle_and_constraints(states in prop::collection::vec(any::<[u64; 25]>(), 3)) {
        use crate::prover::hash::keccak::round::NUM_LANES;
        let states: [[u64; 25]; 3] = states.try_into().expect("exactly 3 states");

        let expected: Vec<[u64; 25]> = states.iter().map(|s| keccak_f1600(*s)).collect();
        let main = trace_for(&states);
        let got: Vec<[u64; 25]> =
            (0..states.len()).map(|perm| trace_lanes(&main, states.len(), perm, NUM_ROUNDS - 1)).collect();
        prop_assert_eq!(got, expected);
        prop_assert_eq!(
            main.height(),
            (states.len().div_ceil(NUM_LANES) * PERM_CYCLE).next_power_of_two()
        );

        crate::prover::tests::check_local(KeccakRoundAir, &main);
    }
}

#[test]
fn keccak_round_constraints_hold_on_extreme_input() {
    let all_ones = [u64::MAX; 25];
    let mut alternating = [0u64; 25];
    for (i, lane) in alternating.iter_mut().enumerate() {
        *lane = if i % 2 == 0 { 0 } else { u64::MAX };
    }

    // Oracle agreement for the extreme states: constraints alone cannot catch a self-consistent
    // but wrong permutation result for these exact inputs.
    let main = trace_for(&[all_ones, alternating]);
    for (perm, state) in [all_ones, alternating].into_iter().enumerate() {
        let expected = keccak_f1600(state);
        let got = trace_lanes(&main, 2, perm, NUM_ROUNDS - 1);
        assert_eq!(got, expected);
    }

    crate::prover::tests::check_local(KeccakRoundAir, &main);
}
