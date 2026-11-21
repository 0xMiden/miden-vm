use alloc::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::LiftedAir;

use super::{
    algebra::{footer_cv_word, footer_message_word},
    constraints_tests::fingerprint_evaluations,
    fingerprint::fill_aux_register,
    layout::*,
    schedule::fused_step_at,
    trace::{TraceMode, generate_felt_trace_block, write_full_felt_footer_cv},
};
use crate::vm::MidenAir;

fn sample(mode: TraceMode) -> [[Felt; NUM_COLS]; BLOCK_PERIOD] {
    generate_felt_trace_block(
        core::array::from_fn(|i| 0x1020_3040 + 0x1133 * i as u32),
        core::array::from_fn(|i| 0x6070_8090 + 0x2211 * i as u32),
        mode,
    )
    .rows
}

fn matrix(rows: &[[Felt; NUM_COLS]]) -> RowMajorMatrix<Felt> {
    RowMajorMatrix::new(rows.iter().flatten().copied().collect(), NUM_COLS)
}

fn evaluations(rows: &[[Felt; NUM_COLS]], rho: QuadFelt) -> Vec<[QuadFelt; 2]> {
    let main = matrix(rows);
    let mut aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; rows.len() * AUX_COLS], AUX_COLS);
    fill_aux_register(&main, &mut aux, AUX_REGISTER_COL, rho);
    fingerprint_evaluations(rows, &aux, rho)
}

// Independent direct equation: form each A-addition residual before assigning its power.
// This uses neither the telescoped recurrence nor its precomputed message weights.
fn direct_polynomial(rows: &[[Felt; NUM_COLS]], rho: QuadFelt) -> QuadFelt {
    let cv: [Felt; 8] = core::array::from_fn(|i| footer_cv_word(|c| rows[31][c], i));
    let block: [Felt; 16] =
        core::array::from_fn(|i| footer_message_word(|c| rows[28 + i / 4][c], i % 4));
    let mut previous_a = core::array::from_fn::<_, 4, _>(|g| cv[g]);
    let mut sum = QuadFelt::ZERO;
    for (t, row) in rows.iter().take(FUSED_G_ROWS).enumerate() {
        let step = fused_step_at(t).unwrap();
        for g in 0..NUM_G {
            let a: Felt = (0..4)
                .map(|b| row[g_ac_byte_slot_col(g, b, 1)] * Felt::from_u64(1 << (8 * b)))
                .sum();
            let b: Felt = (0..4)
                .map(|b| row[g_bd_rot_slot_col(g, b, 0)] * Felt::from_u64(1 << (8 * b)))
                .sum();
            let residual = a + Felt::from_u64(1 << 32) * row[g_k3_col(g)]
                - previous_a[g]
                - b
                - block[step.message_indices[g]];
            sum += rho.exp_u64((4 * (28 - t) + g) as u64) * residual;
            if t == 0 {
                sum += rho.exp_u64((116 + g) as u64) * (b - cv[g + 4]);
            }
            previous_a[g] = a;
        }
    }
    sum
}

#[test]
fn recurrence_matches_direct_residual_polynomial_on_every_main_coordinate() {
    // At each tested challenge, both maps are affine in the main trace. Equality on zero and
    // every coordinate basis vector therefore establishes equality for all main witnesses,
    // including invalid ones.
    for rho in [
        QuadFelt::ZERO,
        QuadFelt::ONE,
        QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)]),
    ] {
        let mut rows = vec![[Felt::ZERO; NUM_COLS]; BLOCK_PERIOD];
        for coordinate in 0..=BLOCK_PERIOD * NUM_COLS {
            if coordinate > 0 {
                rows[(coordinate - 1) / NUM_COLS][(coordinate - 1) % NUM_COLS] = Felt::ONE;
            }
            let actual = evaluations(&rows, rho);
            assert!(actual[..31].iter().flatten().all(|&v| v == QuadFelt::ZERO));
            assert_eq!(
                actual[31],
                [-direct_polynomial(&rows, rho), QuadFelt::ZERO],
                "challenge {rho:?}, coordinate {coordinate}"
            );
            if coordinate > 0 {
                rows[(coordinate - 1) / NUM_COLS][(coordinate - 1) % NUM_COLS] = Felt::ZERO;
            }
        }
    }
}

#[test]
fn native_aux_preserves_lookup_prefix_and_closes_each_cycle() {
    let modes = [
        TraceMode::Compression,
        TraceMode::AeadXof { clk: 19 },
        TraceMode::CompressionWithMultiplicity { multiplicity: 7 },
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    ];
    let rows: Vec<_> = modes.into_iter().flat_map(sample).collect();
    let main = matrix(&rows);
    let challenges =
        [QuadFelt::from_u32(7), QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)])];
    let (aux, sums) = MidenAir::EidosCompression.build_aux_trace(&main, &[], &[], &challenges);
    let (prefix, prefix_sums) = miden_stark::lookup::build_logup_aux_trace_with_preprocessed(
        &MidenAir::EidosCompression,
        &main,
        None,
        &challenges,
    );
    assert_eq!(sums, prefix_sums);
    for row in 0..rows.len() {
        assert_eq!(
            &aux.values[row * AUX_COLS..row * AUX_COLS + NUM_LOGUP_COLS],
            &prefix.values[row * NUM_LOGUP_COLS..(row + 1) * NUM_LOGUP_COLS]
        );
    }
    // The register's position is independent of the matrix stride. Its writer preserves both
    // the lookup prefix and any columns that follow the register.
    let wider_width = AUX_COLS + 1;
    let sentinel = QuadFelt::from_u32(23);
    let mut wider = RowMajorMatrix::new(vec![sentinel; rows.len() * wider_width], wider_width);
    fill_aux_register(&main, &mut wider, AUX_REGISTER_COL, challenges[1]);
    for (r, row) in wider.values.chunks_exact(wider_width).enumerate() {
        assert_eq!(row[AUX_REGISTER_COL], aux.values[r * AUX_COLS + AUX_REGISTER_COL]);
        assert!(row[..AUX_REGISTER_COL].iter().all(|&v| v == sentinel));
        assert!(row[AUX_REGISTER_COL + 1..].iter().all(|&v| v == sentinel));
    }
    assert!(
        fingerprint_evaluations(&rows, &aux, challenges[1])
            .iter()
            .flatten()
            .all(|&v| v == QuadFelt::ZERO)
    );
    for rho in [QuadFelt::ZERO, QuadFelt::ONE] {
        assert!(evaluations(&rows, rho).iter().flatten().all(|&v| v == QuadFelt::ZERO));
    }
}

#[test]
fn auxiliary_register_cells_and_cycle_resets_are_constrained() {
    let cycle = sample(TraceMode::Compression);
    let rows: Vec<_> = cycle.into_iter().chain(cycle).collect();
    let mut aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; rows.len() * AUX_COLS], AUX_COLS);
    fill_aux_register(&matrix(&rows), &mut aux, AUX_REGISTER_COL, QuadFelt::ONE);

    for row in 0..rows.len() {
        let cell = row * AUX_COLS + AUX_REGISTER_COL;
        aux.values[cell] += QuadFelt::ONE;
        let result = fingerprint_evaluations(&rows, &aux, QuadFelt::ONE);
        // The predecessor equation binds every cell, including both cycle starts and the wrap.
        assert_ne!(result[(row + rows.len() - 1) % rows.len()][0], QuadFelt::ZERO, "row {row}");
        aux.values[cell] -= QuadFelt::ONE;
    }

    // At rho = 1, a constant offset satisfies the recurrence. The per-cycle reset must reject it.
    for row in aux.values.as_chunks_mut::<AUX_COLS>().0 {
        row[AUX_REGISTER_COL] += QuadFelt::ONE;
    }
    for (row, [recurrence, reset]) in
        fingerprint_evaluations(&rows, &aux, QuadFelt::ONE).into_iter().enumerate()
    {
        assert_eq!(recurrence, QuadFelt::ZERO, "row {row}");
        assert_eq!(reset, QuadFelt::from_u32(u32::from(row % BLOCK_PERIOD == 0)), "row {row}");
    }
}

#[test]
fn every_a_carry_message_and_initial_cv_word_is_bound() {
    let original = sample(TraceMode::CompressionWithMultiplicity { multiplicity: 0 });
    let rho = QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)]);
    for t in 0..FUSED_G_ROWS {
        for g in 0..NUM_G {
            let mut rows = original;
            rows[t][g_k3_col(g)] =
                Felt::from_u64((rows[t][g_k3_col(g)].as_canonical_u64() + 1) % 3);
            assert_ne!(evaluations(&rows, rho)[31][0], QuadFelt::ZERO, "carry {t}, {g}");
        }
    }
    for i in 0..16 {
        let mut rows = original;
        rows[28 + i / 4][footer_range_slot_col(2 * (i % 4), 0)] += Felt::ONE;
        assert_ne!(evaluations(&rows, rho)[31][0], QuadFelt::ZERO, "message {i}");
    }
    for i in 0..8 {
        let mut rows = original;
        let mut cv =
            core::array::from_fn(|g| footer_cv_word(|c| rows[31][c], g).as_canonical_u64() as u32);
        cv[i] ^= 1;
        write_full_felt_footer_cv(&mut rows[31], cv);
        assert_ne!(evaluations(&rows, rho)[31][0], QuadFelt::ZERO, "CV {i}");
    }
}

#[test]
fn opposite_errors_cannot_cancel_between_cycles() {
    let cycle = sample(TraceMode::CompressionWithMultiplicity { multiplicity: 0 });
    let mut rows: Vec<_> = cycle.into_iter().chain(cycle).collect();
    let rho = QuadFelt::new([Felt::from_u32(11), Felt::from_u32(13)]);
    rows[0][g_k3_col(0)] += Felt::ONE;
    rows[32][g_k3_col(0)] -= Felt::ONE;
    let result = evaluations(&rows, rho);
    assert_ne!(result[31][0], QuadFelt::ZERO);
    assert_eq!(result[31][0], -result[63][0]);
    assert!(
        result
            .iter()
            .enumerate()
            .all(|(r, v)| matches!(r, 31 | 63) || *v == [QuadFelt::ZERO; 2])
    );
}
