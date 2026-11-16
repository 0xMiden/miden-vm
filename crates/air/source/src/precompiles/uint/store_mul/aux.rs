use alloc::vec::Vec;
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_stark::{
    air::{AuxTrace, AuxTraceInputs},
    lookup::LookupError,
};

use super::{
    AUX_WIDTH, CARRY_HI_BEGIN, CARRY_LO_BEGIN, MUL_COL_OFFSET, NUM_LOGUP_COLS, NUM_MAIN_COLS,
    STORE_PERIOD, UintStoreMulAir,
};
use crate::precompiles::uint::mul::{
    COL_ACT as M_COL_ACT, COL_BORROW as M_COL_BORROW, COL_KAPPA_A as M_COL_KAPPA_A, GAMMA_OFFSET,
    GAMMA_SLOTS, NUM_GAMMA, NUM_Q_LIMBS, PERIOD as MUL_PERIOD, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q,
    ROW_R, S_KEEP, TERM_CELL_KAPPA_C_SIGNED,
};

pub(crate) fn build_aux(
    inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
) -> Result<AuxTrace<QuadFelt>, LookupError> {
    let main = inputs.main;
    let challenges = inputs.challenges;
    let witness = miden_stark::lookup::build_logup_aux_trace(&UintStoreMulAir, inputs)?;
    let mut aux = witness.columns;
    let sigma = witness.exports;
    assert_eq!(aux.width(), AUX_WIDTH);
    let beta = challenges[1];

    // One challenge-power table serves both the STORE and MUL registers.
    let mut bp32 = [QuadFelt::ZERO; NUM_GAMMA + 1];
    beta.powers().fill(&mut bp32);
    let bp8: &[QuadFelt; 8] = bp32[..8].try_into().expect("store fingerprint weights");
    let t32 = Felt::new(1u64 << 32).expect("2^32 < Goldilocks p");

    let t16 = Felt::from(1u32 << 16);
    let x_minus_t = beta - t16;
    let gamma_offset = Felt::from(GAMMA_OFFSET);
    let slot_weights: [QuadFelt; 2 * NUM_GAMMA] = array::from_fn(|s| {
        let w = x_minus_t * bp32[s / 2];
        if s % 2 == 1 { w.mul_2exp_u64(16) } else { w }
    });
    let slots_by_row: [Vec<(usize, usize)>; MUL_PERIOD] = {
        let mut by_row: [Vec<(usize, usize)>; MUL_PERIOD] = core::array::from_fn(|_| Vec::new());
        for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            by_row[row].push((s, cell));
        }
        by_row
    };

    use miden_crypto::parallel::*;

    // Chunk boundaries are also MUL cycle boundaries. The S register is reset on ROW_C;
    // the two additive registers carry their chunk totals into the following chunks.
    const CHUNK_ROWS: usize = 512;
    const _: () = assert!(CHUNK_ROWS.is_multiple_of(MUL_PERIOD));
    const _: () = assert!(CHUNK_ROWS.is_multiple_of(STORE_PERIOD));
    const _: () =
        assert!(ROW_C == MUL_PERIOD - 1 && S_KEEP[ROW_C] == 0 && ROW_A != ROW_C && ROW_P != ROW_C);
    let totals: Vec<_> = aux
        .values
        .par_chunks_mut(CHUNK_ROWS * AUX_WIDTH)
        .zip(main.values.par_chunks(CHUNK_ROWS * NUM_MAIN_COLS))
        .map(|(output, input)| {
            let mut store_id = QuadFelt::ZERO;
            let mut mul_id = QuadFelt::ZERO;
            let mut mul_s = QuadFelt::ZERO;
            for (r, (out, values)) in output
                .as_chunks_mut::<AUX_WIDTH>()
                .0
                .iter_mut()
                .zip(input.as_chunks::<NUM_MAIN_COLS>().0)
                .enumerate()
            {
                out[NUM_LOGUP_COLS..].copy_from_slice(&[store_id, mul_id, mul_s]);
                // STORE contrib.
                let store_cell = |c: usize| -> Felt { values[c] };
                let recomb_lo07 = || {
                    let limbs: [Felt; 4] = array::from_fn(|k| {
                        store_cell(2 * k) + store_cell(2 * k + 1).mul_2exp_u64(16)
                    });
                    <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                        bp8[..4].try_into().expect("four limb weights"),
                        &limbs,
                    )
                };
                let recomb_hi07 = || {
                    let limbs: [Felt; 4] = array::from_fn(|k| {
                        store_cell(2 * k) + store_cell(2 * k + 1).mul_2exp_u64(16)
                    });
                    <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                        bp8[4..].try_into().expect("four limb weights"),
                        &limbs,
                    )
                };
                let recomb_hi815 = || {
                    let limbs: [Felt; 4] = array::from_fn(|k| {
                        store_cell(8 + 2 * k) + store_cell(8 + 2 * k + 1).mul_2exp_u64(16)
                    });
                    <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                        bp8[4..].try_into().expect("four limb weights"),
                        &limbs,
                    )
                };
                let store_contrib: QuadFelt = match r % STORE_PERIOD {
                    0 => recomb_lo07(),
                    1 => recomb_hi07(),
                    2 => recomb_lo07() + recomb_hi815(),
                    3 => {
                        let carry_lo = (0..4)
                            .map(|j| {
                                let w = bp8[j + 1] - bp8[j] * t32;
                                w * store_cell(CARRY_LO_BEGIN + j)
                            })
                            .sum::<QuadFelt>();
                        let carry_hi = (0..3)
                            .map(|j| {
                                let w = bp8[4 + j + 1] - bp8[4 + j] * t32;
                                w * store_cell(CARRY_HI_BEGIN + j)
                            })
                            .sum::<QuadFelt>();
                        let direct_lo = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                            bp8[..4].try_into().expect("low bound weights"),
                            &array::from_fn(&store_cell),
                        );
                        let direct_hi = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                            bp8[4..].try_into().expect("high bound weights"),
                            &array::from_fn(|k| store_cell(8 + k)),
                        );
                        carry_lo + carry_hi - (direct_lo + direct_hi)
                    },
                    _ => unreachable!("STORE_PERIOD = 4"),
                };
                store_id += store_contrib;

                // MUL contrib.
                let mul_cell = |c: usize| -> Felt { values[MUL_COL_OFFSET + c] };
                let row_kind = r % MUL_PERIOD;
                let mul_kappa_a = mul_cell(M_COL_KAPPA_A);
                let mul_act = mul_cell(M_COL_ACT);

                let full16_sum = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<8>(
                    bp32[..8].try_into().expect("low operand weights"),
                    &array::from_fn(&mul_cell),
                ) + <QuadFelt as Algebra<Felt>>::mixed_dot_product::<8>(
                    bp32[8..16].try_into().expect("high operand weights"),
                    &array::from_fn(|i| mul_cell(8 + i)),
                );
                let full_q_sum = full16_sum + bp32[NUM_Q_LIMBS - 1] * mul_cell(NUM_Q_LIMBS - 1);
                let even_weights: [QuadFelt; 8] = array::from_fn(|m| bp32[2 * m]);
                let val_sum = <QuadFelt as Algebra<Felt>>::mixed_dot_product(
                    &even_weights,
                    &array::from_fn(&mul_cell),
                );

                let role_contrib: QuadFelt = match row_kind {
                    _ if row_kind == ROW_B => mul_s * full16_sum,
                    _ if row_kind == ROW_P => {
                        let borrow = mul_cell(M_COL_BORROW);
                        (full16_sum + QuadFelt::ONE) * borrow
                    },
                    _ if row_kind == ROW_Q => -((mul_s + QuadFelt::ONE) * full_q_sum),
                    _ if row_kind == ROW_R => -val_sum,
                    _ if row_kind == ROW_C => {
                        let kappa_c_signed = values[MUL_COL_OFFSET + TERM_CELL_KAPPA_C_SIGNED];
                        val_sum * kappa_c_signed
                    },
                    _ => QuadFelt::ZERO,
                };
                let gamma_contrib: QuadFelt = slots_by_row[row_kind]
                    .iter()
                    .map(|&(s, c)| {
                        let v = if s % 2 == 0 {
                            mul_cell(c) - mul_act * gamma_offset
                        } else {
                            mul_cell(c)
                        };
                        slot_weights[s] * v
                    })
                    .sum();
                mul_id += role_contrib + gamma_contrib;

                let build: QuadFelt = match row_kind {
                    _ if row_kind == ROW_A => full16_sum * mul_kappa_a,
                    _ if row_kind == ROW_P => full16_sum,
                    _ => QuadFelt::ZERO,
                };
                let keep = Felt::from(S_KEEP[row_kind] as u32);
                mul_s = mul_s * keep + build;
            }
            (store_id, mul_id)
        })
        .collect();

    // Preserve the running sums even when the supplied main trace does not satisfy the AIR.
    let mut offset = (QuadFelt::ZERO, QuadFelt::ZERO);
    let offsets: Vec<_> = totals
        .into_iter()
        .map(|total| {
            let previous = offset;
            offset.0 += total.0;
            offset.1 += total.1;
            previous
        })
        .collect();
    aux.values
        .par_chunks_mut(CHUNK_ROWS * AUX_WIDTH)
        .zip(offsets.into_par_iter())
        .for_each(|(output, (store_offset, mul_offset))| {
            if store_offset != QuadFelt::ZERO || mul_offset != QuadFelt::ZERO {
                for row in output.as_chunks_mut::<AUX_WIDTH>().0 {
                    row[NUM_LOGUP_COLS] += store_offset;
                    row[NUM_LOGUP_COLS + 1] += mul_offset;
                }
            }
        });

    Ok(AuxTrace { columns: aux, exports: sigma })
}
