use alloc::vec::Vec;
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_stark::{
    air::{AuxTrace, AuxTraceInputs},
    lookup::{LookupError, build_logup_aux_trace},
};

use super::{
    AUX_WIDTH, COL_ACT, COL_BORROW, COL_KAPPA_A, GAMMA_OFFSET, GAMMA_SLOTS, NUM_GAMMA,
    NUM_MAIN_COLS, NUM_Q_LIMBS, PERIOD, REG_ID, REG_S, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q, ROW_R,
    S_KEEP, TERM_CELL_KAPPA_C_SIGNED, UintMulAir,
};

pub(crate) fn build_aux(
    inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
) -> Result<AuxTrace<QuadFelt>, LookupError> {
    let main = inputs.main;
    let challenges = inputs.challenges;
    let mut aux = build_logup_aux_trace(&UintMulAir, inputs)?;
    let n = main.height();
    let beta = challenges[1];

    // β⁰..β³¹ + the γ slot weights (mirroring the AIR's).
    let mut bp = [QuadFelt::ZERO; NUM_GAMMA + 1];
    beta.powers().fill(&mut bp);
    let t16 = Felt::from(1u32 << 16);
    let x_minus_t = beta - t16;
    let offset = Felt::from(GAMMA_OFFSET);
    let slot_weights: [QuadFelt; 2 * NUM_GAMMA] = array::from_fn(|s| {
        let w = x_minus_t * bp[s / 2];
        if s % 2 == 1 { w.mul_2exp_u64(16) } else { w }
    });
    // Per row-role: the hosted γ slots (slot index, cell).
    let slots_by_row: [Vec<(usize, usize)>; PERIOD] = {
        let mut by_row: [Vec<(usize, usize)>; PERIOD] = array::from_fn(|_| Vec::new());
        for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            by_row[row].push((s, cell));
        }
        by_row
    };

    // Fill the existing `id` and `S` suffix in place, before each row's updates.
    // The declared lookup prefix and normalized export are independent of these registers.
    let mut id = QuadFelt::ZERO;
    let mut s_reg = QuadFelt::ZERO;
    for r in 0..n {
        aux.columns.values[r * AUX_WIDTH + REG_ID] = id;
        aux.columns.values[r * AUX_WIDTH + REG_S] = s_reg;

        let cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let row_kind = r % PERIOD;
        let kappa_a = cell(COL_KAPPA_A);
        let act = cell(COL_ACT);

        let full16_sum = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<8>(
            bp[..8].try_into().expect("low operand weights"),
            &array::from_fn(&cell),
        ) + <QuadFelt as Algebra<Felt>>::mixed_dot_product::<8>(
            bp[8..16].try_into().expect("high operand weights"),
            &array::from_fn(|i| cell(8 + i)),
        );
        let full_q_sum = full16_sum + bp[NUM_Q_LIMBS - 1] * cell(NUM_Q_LIMBS - 1);
        let even_weights: [QuadFelt; 8] = array::from_fn(|m| bp[2 * m]);
        let val_sum =
            <QuadFelt as Algebra<Felt>>::mixed_dot_product(&even_weights, &array::from_fn(&cell));

        let role_contrib: QuadFelt = match row_kind {
            _ if row_kind == ROW_B => s_reg * full16_sum,
            // +borrow·(bound(β)+1); the +1 of p = bound + 1 rides β⁰.
            _ if row_kind == ROW_P => {
                let borrow = main.values[r * NUM_MAIN_COLS + COL_BORROW];
                (full16_sum + QuadFelt::ONE) * borrow
            },
            _ if row_kind == ROW_Q => -((s_reg + QuadFelt::ONE) * full_q_sum),
            _ if row_kind == ROW_R => -val_sum,
            _ if row_kind == ROW_C => {
                let kappa_c_signed = main.values[r * NUM_MAIN_COLS + TERM_CELL_KAPPA_C_SIGNED];
                val_sum * kappa_c_signed
            },
            _ => QuadFelt::ZERO,
        };
        let gamma_contrib: QuadFelt = slots_by_row[row_kind]
            .iter()
            .map(|&(s, c)| {
                let v = if s % 2 == 0 { cell(c) - act * offset } else { cell(c) };
                slot_weights[s] * v
            })
            .sum();
        id += role_contrib + gamma_contrib;

        let build: QuadFelt = match row_kind {
            _ if row_kind == ROW_A => full16_sum * kappa_a,
            _ if row_kind == ROW_P => full16_sum,
            _ => QuadFelt::ZERO,
        };
        let keep = Felt::from(S_KEEP[row_kind] as u32);
        s_reg = s_reg * keep + build;
    }

    Ok(aux)
}
