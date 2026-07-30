//! Integration tests for the Keccak-round miniVM chiplet.
//!
//! Drives [`generate_trace`] + [`extract_output`] against a reference
//! Keccak-f[1600] implementation, and runs `check_constraints` on the
//! resulting AIR/witness pair.

use std::{vec, vec::Vec};

use miden_core::{Felt, utils::Matrix};
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::hash::keccak::{
    reference::{KECCAK_RC, keccak_f1600, keccak_round},
    round::{
        KeccakRoundAir, NUM_MAIN_COLS, NUM_ROUNDS, PERM_CYCLE, ROT_LIMBS_RANGE, extract_output,
        extract_outputs, generate_trace_from_states, program::SLOT_D_ROL_BEGIN,
    },
};

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
