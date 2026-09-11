use alloc::vec::Vec;
use core::array;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    AUX_WIDTH, COL_ACT, COL_BORROW, COL_KAPPA_A, GAMMA_OFFSET, GAMMA_SLOTS, NUM_GAMMA,
    NUM_MAIN_COLS, NUM_Q_LIMBS, PERIOD, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q, ROW_R, S_KEEP,
    TERM_CELL_KAPPA_C_SIGNED, UintMulAir,
};
use crate::logup::build_logup_aux_trace;

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Cols 0–2: LogUp running sum + the two fraction columns.
    let (logup, sigma) = build_logup_aux_trace(&UintMulAir, main, challenges);
    let logup_width = logup.width();
    let n = main.height();
    let beta = challenges[1];

    // β⁰..β³¹ + the γ slot weights (mirroring the AIR's).
    let mut bp = [QuadFelt::ZERO; NUM_GAMMA + 1];
    bp[0] = QuadFelt::ONE;
    for i in 1..NUM_GAMMA + 1 {
        bp[i] = bp[i - 1] * beta;
    }
    let t16 = QuadFelt::from(Felt::from(1u32 << 16));
    let x_minus_t = beta - t16;
    let offset = Felt::from(GAMMA_OFFSET);
    let slot_weight = |s: usize| -> QuadFelt {
        let w = x_minus_t * bp[s / 2];
        if s % 2 == 1 { w * t16 } else { w }
    };
    // Per row-role: the hosted γ slots (slot index, cell).
    let slots_by_row: [Vec<(usize, usize)>; PERIOD] = {
        let mut by_row: [Vec<(usize, usize)>; PERIOD] = array::from_fn(|_| Vec::new());
        for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            by_row[row].push((s, cell));
        }
        by_row
    };

    // Cols 3–4: the `id` and `S` registers. Both start at 0; the
    // updates mirror UintMulAir's role-gated expressions exactly.
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    let mut s_reg = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);
        data.push(s_reg);

        let cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let row_kind = r % PERIOD;
        let kappa_a = QuadFelt::from(cell(COL_KAPPA_A));
        let act = cell(COL_ACT);

        let full16_sum =
            (0..16).fold(QuadFelt::ZERO, |acc, i| acc + bp[i] * QuadFelt::from(cell(i)));
        let full_q_sum =
            (0..NUM_Q_LIMBS).fold(QuadFelt::ZERO, |acc, i| acc + bp[i] * QuadFelt::from(cell(i)));
        let val_sum =
            (0..8).fold(QuadFelt::ZERO, |acc, m| acc + bp[2 * m] * QuadFelt::from(cell(m)));

        let role_contrib: QuadFelt = match row_kind {
            _ if row_kind == ROW_B => s_reg * full16_sum,
            // +borrow·(bound(β)+1); the +1 of p = bound + 1 rides β⁰.
            _ if row_kind == ROW_P => {
                let borrow = main.values[r * NUM_MAIN_COLS + COL_BORROW];
                QuadFelt::from(borrow) * (full16_sum + QuadFelt::ONE)
            },
            _ if row_kind == ROW_Q => -((s_reg + QuadFelt::ONE) * full_q_sum),
            _ if row_kind == ROW_R => -val_sum,
            _ if row_kind == ROW_C => {
                let kappa_c_signed = main.values[r * NUM_MAIN_COLS + TERM_CELL_KAPPA_C_SIGNED];
                QuadFelt::from(kappa_c_signed) * val_sum
            },
            _ => QuadFelt::ZERO,
        };
        let gamma_contrib: QuadFelt =
            slots_by_row[row_kind].iter().fold(QuadFelt::ZERO, |acc, &(s, c)| {
                let v = if s % 2 == 0 { cell(c) - act * offset } else { cell(c) };
                acc + slot_weight(s) * QuadFelt::from(v)
            });
        id += role_contrib + gamma_contrib;

        let build: QuadFelt = match row_kind {
            _ if row_kind == ROW_A => kappa_a * full16_sum,
            _ if row_kind == ROW_P => full16_sum,
            _ => QuadFelt::ZERO,
        };
        let keep = QuadFelt::from(Felt::from(S_KEEP[row_kind] as u32));
        s_reg = s_reg * keep + build;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
