//! Integration tests for the Keccak-round miniVM chiplet.
//!
//! Drives [`generate_trace`] + [`extract_output`] against a reference
//! Keccak-f[1600] implementation, and runs `check_constraints` on the
//! resulting AIR/witness pair.

use std::{vec, vec::Vec};

use miden_air::lookup::debug::{
    ValidateLayout, ValidateLookupAir, trace::collect_column_oracle_folds,
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, ConstraintDegrees, LiftedAir};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    hash::keccak::{
        reference::{KECCAK_RC, keccak_f1600, keccak_round},
        round::{
            A_BYTES_RANGE, B_BYTES_RANGE, COL_ACT, KeccakRoundAir, NUM_AUX_COLS, NUM_LANES,
            NUM_MAIN_COLS, NUM_ROUNDS, PERM_CYCLE, R_BYTES_RANGE, ROT_LIMBS_RANGE, extract_output,
            extract_outputs, generate_trace_from_states, lane_base, program::SLOT_D_ROL_BEGIN,
        },
    },
    logup::{Challenges, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{ChipletAir, Session},
    tests::bus_balance::session_stack_residual,
};

fn lookup_challenges() -> Challenges<QuadFelt> {
    Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    )
}

// TESTS
// ================================================================================================

/// Run a single Keccak round through the chiplet simulator and read
/// back the state after that one round.
fn chiplet_one_round(state: [u64; 25], rc: u64) -> [u64; 25] {
    // Pad RCs with zeros for the remaining 23 rounds; the chiplet still
    // computes them but we only read out round 0's outputs.
    let mut rcs = [0u64; NUM_ROUNDS];
    rcs[0] = rc;

    extract_output_one_round(&state, &rcs)
}

/// Extract state after exactly one round by running the chiplet
/// simulation and reading lane outputs at slots 103..128 of round 0.
/// Sponge inputs use natural row-major addressing: `state[i]` at
/// addr `i`.
fn extract_output_one_round(state: &[u64; 25], rcs: &[u64; NUM_ROUNDS]) -> [u64; 25] {
    use crate::hash::keccak::round::{
        IP_BOUNDARY, ROUND_PERIOD,
        program::{SLOT_CHI_XOR_BEGIN, SLOT_IOTA},
        slots,
    };

    let program = slots();
    // Size memory to cover the highest seeded address: the last RC
    // (RC[NUM_ROUNDS − 1]) sits at IP `IP_BOUNDARY + (NUM_ROUNDS − 1)·ROUND_PERIOD`.
    let mut memory = vec![0u64; IP_BOUNDARY as usize + NUM_ROUNDS * ROUND_PERIOD];
    for (idx, &lane) in state.iter().enumerate() {
        memory[idx] = lane;
    }
    for r in 0..NUM_ROUNDS {
        memory[(IP_BOUNDARY + (r * ROUND_PERIOD) as u64) as usize] = rcs[r];
    }

    // Step one full round.
    for row in 0..ROUND_PERIOD {
        let slot = row;
        let ip = IP_BOUNDARY + row as u64;
        let spec = program[slot];
        let reads_a = !matches!(spec.op, crate::hash::keccak::round::Op::Nop);
        let reads_b = matches!(
            spec.op,
            crate::hash::keccak::round::Op::Xor
                | crate::hash::keccak::round::Op::Andnot
                | crate::hash::keccak::round::Op::XorRol(_)
        );
        let a = if reads_a {
            memory[ip.wrapping_sub(spec.back_a) as usize]
        } else {
            0
        };
        let b = if reads_b {
            memory[ip.wrapping_sub(spec.back_b) as usize]
        } else {
            0
        };
        let (_, c) = simulate_for_debug(spec.op, a, b);
        if spec.dst_mult > 0 {
            memory[ip as usize] = c;
        }
    }

    let mut out = [0u64; 25];
    for (idx, value) in out.iter_mut().enumerate() {
        let slot = if idx == 0 {
            SLOT_IOTA
        } else {
            SLOT_CHI_XOR_BEGIN + (idx - 1)
        };
        *value = memory[(IP_BOUNDARY + slot as u64) as usize];
    }
    out
}

fn simulate_for_debug(op: crate::hash::keccak::round::Op, a: u64, b: u64) -> (u64, u64) {
    use crate::hash::keccak::round::Op;
    let r = match op {
        Op::Nop | Op::Rol(_) => a,
        Op::Xor | Op::XorRol(_) => a ^ b,
        Op::Andnot => (!a) & b,
    };
    let c = match op {
        Op::Nop | Op::Xor | Op::Andnot => r,
        Op::Rol(s) | Op::XorRol(s) => r.rotate_left(s),
    };
    (r, c)
}

#[test]
fn chiplet_one_round_matches_reference_zero_input() {
    let state = [0u64; 25];
    let mut expected = state;
    keccak_round(&mut expected, KECCAK_RC[0]);
    let got = chiplet_one_round(state, KECCAK_RC[0]);
    for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
        assert_eq!(g, e, "lane {i} (x={}, y={})", i % 5, i / 5);
    }
}

/// Run `n` rounds via chiplet by reading the per-round outputs and
/// feeding them back as the next round's inputs. Compares against the
/// reference round by round.
#[test]
fn chiplet_two_rounds_match_reference_zero_input() {
    let mut state = [0u64; 25];
    let mut expected = state;
    for (r, &rc) in KECCAK_RC.iter().enumerate().take(2) {
        let prev = state;
        keccak_round(&mut expected, rc);
        let got = chiplet_one_round(prev, rc);
        for (i, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
            assert_eq!(g, e, "round {r}, lane {i} (x={}, y={})", i % 5, i / 5);
        }
        state = got;
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
    let got = extract_output(&state, &KECCAK_RC);
    assert_eq!(got, expected);
}

#[test]
fn extract_output_matches_reference_keccak_zero_input() {
    let state = [0u64; 25];
    let expected = keccak_f1600(state);
    let got = extract_output(&state, &KECCAK_RC);
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
    let got = extract_output(&state, &KECCAK_RC);
    assert_eq!(got, expected, "patterned input");
}

#[test]
fn extract_output_matches_reference_keccak_random_input() {
    let mut rng = StdRng::seed_from_u64(0xcaca0);
    for trial in 0..3 {
        let mut state = [0u64; 25];
        for lane in state.iter_mut() {
            *lane = rng.random();
        }
        let expected = keccak_f1600(state);
        let got = extract_output(&state, &KECCAK_RC);
        assert_eq!(got, expected, "trial {trial}");
    }
}

#[test]
fn keccak_round_constraints_hold_on_canonical_input() {
    let state = [0u64; 25];

    let main = generate_trace_from_states(&[state], &KECCAK_RC);
    assert_eq!(main.height(), PERM_CYCLE.next_power_of_two());

    crate::tests::check_local(KeccakRoundAir, &main);
}

#[test]
fn keccak_round_constraints_hold_on_random_input() {
    let mut rng = StdRng::seed_from_u64(0xc037f);
    let mut state = [0u64; 25];
    for lane in state.iter_mut() {
        *lane = rng.random();
    }

    let main = generate_trace_from_states(&[state], &KECCAK_RC);

    crate::tests::check_local(KeccakRoundAir, &main);
}

#[test]
fn keccak_round_shape_and_degree_match_design() {
    let air = KeccakRoundAir;

    assert_eq!(air.width(), 68);
    assert_eq!(air.aux_width(), 12);
    assert_eq!(crate::tests::lookup_column_shape(&air), &[1, 2, 4, 4, 4, 4, 1, 2, 4, 4, 4, 4],);
    assert_eq!(
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air),
        ConstraintDegrees { base: 4, ext: 5 }
    );
    assert_eq!(crate::tests::log_quotient_degree(&air), 2);

    let layout = ValidateLayout {
        preprocessed_width: air.preprocessed_width(),
        trace_width: air.width(),
        num_public_values: NUM_PUBLIC_VALUES,
        num_periodic_columns: air.periodic_columns().len(),
        permutation_width: NUM_AUX_COLS,
        num_permutation_challenges: NUM_RANDOMNESS,
        num_permutation_values: NUM_LOGUP_VALUES,
    };
    ValidateLookupAir::validate(&air, layout)
        .unwrap_or_else(|err| panic!("KeccakRoundAir lookup validation failed: {err}"));
}

#[test]
fn pure_rol_raw_b_is_load_bearing_in_every_byte_and_lane() {
    let states = [[0x0123_4567_89ab_cdef; 25], [0xfedc_ba98_7654_3210; 25]];
    let main = generate_trace_from_states(&states, &KECCAK_RC);
    let row = SLOT_D_ROL_BEGIN;
    let air = KeccakRoundAir;
    let one_row = RowMajorMatrix::new(
        main.values[row * NUM_MAIN_COLS..(row + 1) * NUM_MAIN_COLS].to_vec(),
        NUM_MAIN_COLS,
    );
    let periodic: Vec<Vec<Felt>> = air
        .periodic_columns()
        .into_iter()
        .map(|column| vec![column[row % column.len()]])
        .collect();
    let public_values = [Felt::ZERO; NUM_PUBLIC_VALUES];
    let challenges = lookup_challenges();
    let baseline =
        collect_column_oracle_folds(&air, &one_row, &periodic, &public_values, &challenges);

    for lane in 0..NUM_LANES {
        let lane_base = lane_base(lane);
        assert_eq!(one_row.values[lane_base + COL_ACT], Felt::ONE);

        for byte in 0..B_BYTES_RANGE.len() {
            let cell = lane_base + B_BYTES_RANGE.start + byte;
            assert_eq!(one_row.values[cell], Felt::ZERO);

            let mut attacked = one_row.clone();
            attacked.values[cell] = Felt::ONE;
            let attacked_folds = collect_column_oracle_folds(
                &air,
                &attacked,
                &periodic,
                &public_values,
                &challenges,
            );
            let target_col = lane * (NUM_AUX_COLS / NUM_LANES) + 2 + byte / 4;
            let source_col = lane * (NUM_AUX_COLS / NUM_LANES) + 1;

            for col in 0..NUM_AUX_COLS {
                if col == target_col {
                    let (attacked_v, attacked_u) = attacked_folds[0][col];
                    let (baseline_v, baseline_u) = baseline[0][col];
                    assert_ne!(attacked_v * baseline_u, baseline_v * attacked_u);
                } else if col == source_col {
                    // `src_b` has zero multiplicity on a pure-ROL row, so changing its
                    // denominator must not change the represented rational sum.
                    let (attacked_v, attacked_u) = attacked_folds[0][col];
                    let (baseline_v, baseline_u) = baseline[0][col];
                    assert_eq!(attacked_v * baseline_u, baseline_v * attacked_u);
                } else {
                    assert_eq!(attacked_folds[0][col], baseline[0][col]);
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
        .position(|air| air == ChipletAir::KeccakRound)
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

/// Stack 3 independent perms in one trace and verify both per-perm
/// output correctness (via `extract_outputs`) and constraint
/// satisfaction. With NUM_LANES=2, the 3 perms split into a busiest lane of
/// `⌈3/2⌉ = 2` perms, so the height is `2 * 3200 = 6400` padded to `8192`.
#[test]
fn keccak_round_multi_perm_oracle_and_constraints() {
    use crate::hash::keccak::round::NUM_LANES;
    let mut rng = StdRng::seed_from_u64(0xc0ffee);
    let mut states = [[0u64; 25]; 3];
    for state in states.iter_mut() {
        for lane in state.iter_mut() {
            *lane = rng.random();
        }
    }

    let expected: Vec<[u64; 25]> = states.iter().map(|s| keccak_f1600(*s)).collect();
    let got = extract_outputs(&states, &KECCAK_RC);
    assert_eq!(got, expected, "per-perm oracle agreement");

    let main = generate_trace_from_states(&states, &KECCAK_RC);
    assert_eq!(
        main.height(),
        (states.len().div_ceil(NUM_LANES) * PERM_CYCLE).next_power_of_two()
    );

    crate::tests::check_local(KeccakRoundAir, &main);
}

// NEGATIVE TESTS — confirm `check_constraints` catches deliberate corruption.
// ================================================================================================

/// On the first pure-ROL row, forge the otherwise valid byte lookup `Xor(0, 1, 1)` and update the
/// first rotation limb to preserve the rotation-decomposition identity. The local `r = a`
/// passthrough constraint must be the remaining reason this trace is rejected.
#[test]
#[should_panic(expected = "constraint not satisfied")]
fn pure_rol_passthrough_rejects_bpl_valid_nonzero_b() {
    let mut main = generate_trace_from_states(&[[0u64; 25]], &KECCAK_RC);
    let row_start = SLOT_D_ROL_BEGIN * NUM_MAIN_COLS;

    for col in [
        A_BYTES_RANGE.start,
        B_BYTES_RANGE.start,
        R_BYTES_RANGE.start,
        ROT_LIMBS_RANGE.start,
    ] {
        assert_eq!(main.values[row_start + col], Felt::ZERO);
    }

    main.values[row_start + B_BYTES_RANGE.start] = Felt::ONE;
    main.values[row_start + R_BYTES_RANGE.start] = Felt::ONE;
    main.values[row_start + ROT_LIMBS_RANGE.start] = Felt::from(2u8);

    crate::tests::check_local(KeccakRoundAir, &main);
}

/// Corrupting a `rot_limbs` cell on an active ROL row must now be
/// rejected by the rotation limb-decomposition binding constraint:
/// without it, `rot_limbs` was only Range16-range-checked, and the
/// value `memory_provide_c` reconstructs from it (written to the
/// Memory64 bus as this row's rotated result) could be driven to any
/// value the prover chose. `SLOT_D_ROL_BEGIN` (round 0, lane 0) is an
/// active `Op::Rol` row, so `is_rol = act = 1` there.
#[test]
#[should_panic(expected = "constraint not satisfied")]
fn corruption_rot_limb_breaks_rotation_decomposition_binding() {
    let state = [0u64; 25];
    let mut main = generate_trace_from_states(&[state], &KECCAK_RC);
    let row = SLOT_D_ROL_BEGIN;
    let col = ROT_LIMBS_RANGE.start;
    main.values[row * NUM_MAIN_COLS + col] += Felt::from(1u8);
    crate::tests::check_local(KeccakRoundAir, &main);
}
