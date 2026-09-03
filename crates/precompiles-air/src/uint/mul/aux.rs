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

/// The mul component's `id` and staging `S` registers, read out of a main-trace column band.
///
/// `row_width` is the width of the enclosing trace and `col_offset` the band's first column, so
/// the per-row updates match `super::eval_main`'s role-gated expressions exactly.
pub(crate) struct MulRegisters {
    bp: [QuadFelt; NUM_GAMMA + 1],
    t16: QuadFelt,
    x_minus_t: QuadFelt,
    offset: Felt,
    /// Per row-role: the hosted γ slots (slot index, cell).
    slots_by_row: [Vec<(usize, usize)>; PERIOD],
    row_width: usize,
    col_offset: usize,
    s: QuadFelt,
}

impl MulRegisters {
    pub(crate) fn new(beta: QuadFelt, row_width: usize, col_offset: usize) -> Self {
        // β⁰..β³¹ + the γ slot weights (mirroring the AIR's).
        let mut bp = [QuadFelt::ZERO; NUM_GAMMA + 1];
        bp[0] = QuadFelt::ONE;
        for i in 1..NUM_GAMMA + 1 {
            bp[i] = bp[i - 1] * beta;
        }
        let t16 = QuadFelt::from(Felt::from(1u32 << 16));
        let slots_by_row: [Vec<(usize, usize)>; PERIOD] = {
            let mut by_row: [Vec<(usize, usize)>; PERIOD] = array::from_fn(|_| Vec::new());
            for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
                by_row[row].push((s, cell));
            }
            by_row
        };
        Self {
            bp,
            t16,
            x_minus_t: beta - t16,
            offset: Felt::from(GAMMA_OFFSET),
            slots_by_row,
            row_width,
            col_offset,
            s: QuadFelt::ZERO,
        }
    }

    fn slot_weight(&self, s: usize) -> QuadFelt {
        let w = self.x_minus_t * self.bp[s / 2];
        if s % 2 == 1 { w * self.t16 } else { w }
    }

    /// The staging register's value on the row that `step` will read next.
    pub(crate) fn s(&self) -> QuadFelt {
        self.s
    }

    /// Row `r`'s contribution to the `id` accumulator; advances `S` to row `r + 1`.
    pub(crate) fn step(&mut self, main: &RowMajorMatrix<Felt>, r: usize) -> QuadFelt {
        let bp = &self.bp;
        let cell = |c: usize| -> Felt { main.values[r * self.row_width + self.col_offset + c] };
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
            _ if row_kind == ROW_B => self.s * full16_sum,
            // +borrow·(bound(β)+1); the +1 of p = bound + 1 rides β⁰.
            _ if row_kind == ROW_P => {
                QuadFelt::from(cell(COL_BORROW)) * (full16_sum + QuadFelt::ONE)
            },
            _ if row_kind == ROW_Q => -((self.s + QuadFelt::ONE) * full_q_sum),
            _ if row_kind == ROW_R => -val_sum,
            _ if row_kind == ROW_C => QuadFelt::from(cell(TERM_CELL_KAPPA_C_SIGNED)) * val_sum,
            _ => QuadFelt::ZERO,
        };
        let gamma_contrib: QuadFelt =
            self.slots_by_row[row_kind].iter().fold(QuadFelt::ZERO, |acc, &(s, c)| {
                let v = if s % 2 == 0 {
                    cell(c) - act * self.offset
                } else {
                    cell(c)
                };
                acc + self.slot_weight(s) * QuadFelt::from(v)
            });

        let build: QuadFelt = match row_kind {
            _ if row_kind == ROW_A => kappa_a * full16_sum,
            _ if row_kind == ROW_P => full16_sum,
            _ => QuadFelt::ZERO,
        };
        let keep = QuadFelt::from(Felt::from(S_KEEP[row_kind] as u32));
        self.s = self.s * keep + build;

        role_contrib + gamma_contrib
    }
}

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Cols 0–2: LogUp running sum + the two fraction columns.
    let (logup, sigma) = build_logup_aux_trace(&UintMulAir, main, challenges);
    let logup_width = logup.width();
    let n = main.height();
    let mut registers = MulRegisters::new(challenges[1], NUM_MAIN_COLS, 0);

    // Cols 3–4: the `id` and `S` registers. Both start at 0.
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);
        data.push(registers.s());
        id += registers.step(main, r);
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
