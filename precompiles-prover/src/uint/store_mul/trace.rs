//! Trace generation for [`UintStoreMulAir`](super::UintStoreMulAir).
//!
//! Store and mul each lay their own rows via their standalone trace-gen
//! ([`crate::uint::trace::generate_trace_padded_to`],
//! [`crate::uint::mul::trace::generate_trace`]) — same block content,
//! same native padding mechanism (store's self-referential zero blocks,
//! mul's `act = 0` blocks). Mul routes its store demand first (as the
//! original dependency order required), producing its own natively
//! padded height; store is then generated with a block-count floor
//! matching that height, so it comes out at `max(store's natural
//! height, mul's natural height)` directly; if mul's own height was the
//! smaller one, it's zero-extended to match (mul's padding is already
//! all-zero, so more of it is exactly more native padding). The two
//! column ranges are then concatenated per row.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    AUX_WIDTH, CARRY_CELLS_BEGIN, MUL_COL_OFFSET, NUM_MAIN_COLS, STORE_NUM_MAIN_COLS, STORE_PERIOD,
    UintStoreMulAir,
};
use crate::{
    logup::build_logup_aux_trace,
    primitives::byte_pair_lut::BytePairLutRequires,
    uint::{
        mul::{
            COL_ACT as M_COL_ACT, COL_BORROW as M_COL_BORROW, COL_KAPPA_A as M_COL_KAPPA_A,
            GAMMA_OFFSET, GAMMA_SLOTS, NUM_GAMMA, NUM_MAIN_COLS as MUL_NUM_MAIN_COLS, NUM_Q_LIMBS,
            PERIOD as MUL_PERIOD, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q, ROW_R, S_KEEP,
            TERM_CELL_KAPPA_C_SIGNED,
            trace::{UintMulRequires, generate_trace as mul_trace},
        },
        trace::{UintStoreRequires, generate_trace_padded_to as store_trace_padded_to},
    },
};

pub fn generate_trace(
    store: UintStoreRequires,
    mul: UintMulRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let mut store = store;
    let mul_main = mul_trace(mul, &mut store, bpl);

    // `mul_main.height()` is a power of two and `STORE_PERIOD` divides it
    // (both are powers of two), so this floor is too —
    // `generate_trace_padded_to` needs that to stay a valid power-of-two
    // block count.
    let store_min_blocks = mul_main.height() / STORE_PERIOD;
    let store_main = store_trace_padded_to(store, bpl, store_min_blocks);
    let h_merged = store_main.height();

    let mut mul_vals = mul_main.values;
    mul_vals.resize(h_merged * MUL_NUM_MAIN_COLS, Felt::ZERO);

    let mut vals = Vec::with_capacity(h_merged * NUM_MAIN_COLS);
    for r in 0..h_merged {
        vals.extend_from_slice(
            &store_main.values[r * STORE_NUM_MAIN_COLS..(r + 1) * STORE_NUM_MAIN_COLS],
        );
        vals.extend_from_slice(&mul_vals[r * MUL_NUM_MAIN_COLS..(r + 1) * MUL_NUM_MAIN_COLS]);
    }
    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Witness-bearing companion to
/// [`UintStoreMulAir`](crate::uint::store_mul::UintStoreMulAir).
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    let (logup, sigma) = build_logup_aux_trace(&UintStoreMulAir, main, challenges);
    let logup_width = logup.width();
    let n = main.height();
    let beta = challenges[1];

    // STORE's own register math (mirrors `uint::trace::build_aux`
    // exactly, reading cols 0..10).
    let mut bp8 = [QuadFelt::ZERO; 8];
    bp8[0] = QuadFelt::ONE;
    for i in 1..8 {
        bp8[i] = bp8[i - 1] * beta;
    }
    let two16 = Felt::from(1u32 << 16);
    let t32 = QuadFelt::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

    // MUL's own register math (mirrors `uint::mul::trace::build_aux`
    // exactly, reading cols `MUL_COL_OFFSET`..`NUM_MAIN_COLS`).
    let mut bp32 = [QuadFelt::ZERO; NUM_GAMMA + 1];
    bp32[0] = QuadFelt::ONE;
    for i in 1..NUM_GAMMA + 1 {
        bp32[i] = bp32[i - 1] * beta;
    }
    let t16 = QuadFelt::from(Felt::from(1u32 << 16));
    let x_minus_t = beta - t16;
    let gamma_offset = Felt::from(GAMMA_OFFSET);
    let slot_weight = |s: usize| -> QuadFelt {
        let w = x_minus_t * bp32[s / 2];
        if s % 2 == 1 { w * t16 } else { w }
    };
    let slots_by_row: [Vec<(usize, usize)>; MUL_PERIOD] = {
        let mut by_row: [Vec<(usize, usize)>; MUL_PERIOD] = core::array::from_fn(|_| Vec::new());
        for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            by_row[row].push((s, cell));
        }
        by_row
    };

    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut store_id = QuadFelt::ZERO;
    let mut mul_id = QuadFelt::ZERO;
    let mut mul_s = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(store_id);
        data.push(mul_id);
        data.push(mul_s);

        // STORE contrib.
        let store_cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let store_contrib: QuadFelt = match r % STORE_PERIOD {
            0 | 3 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = store_cell(2 * k) + two16 * store_cell(2 * k + 1);
                s + bp8[k] * QuadFelt::from(rk)
            }),
            2 | 4 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = store_cell(2 * k) + two16 * store_cell(2 * k + 1);
                s + bp8[4 + k] * QuadFelt::from(rk)
            }),
            5 => (0..4).fold(QuadFelt::ZERO, |s, j| {
                let w = bp8[j + 1] - bp8[j] * t32;
                s + w * QuadFelt::from(store_cell(CARRY_CELLS_BEGIN + j))
                    - bp8[j] * QuadFelt::from(store_cell(j))
            }),
            6 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let carry = if k < 3 {
                    let j = 4 + k;
                    (bp8[j + 1] - bp8[j] * t32) * QuadFelt::from(store_cell(CARRY_CELLS_BEGIN + k))
                } else {
                    QuadFelt::ZERO
                };
                s + carry - bp8[4 + k] * QuadFelt::from(store_cell(k))
            }),
            _ => QuadFelt::ZERO,
        };
        store_id += store_contrib;

        // MUL contrib.
        let mul_cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + MUL_COL_OFFSET + c] };
        let row_kind = r % MUL_PERIOD;
        let mul_kappa_a = QuadFelt::from(mul_cell(M_COL_KAPPA_A));
        let mul_act = mul_cell(M_COL_ACT);

        let full16_sum =
            (0..16).fold(QuadFelt::ZERO, |acc, i| acc + bp32[i] * QuadFelt::from(mul_cell(i)));
        let full_q_sum = (0..NUM_Q_LIMBS)
            .fold(QuadFelt::ZERO, |acc, i| acc + bp32[i] * QuadFelt::from(mul_cell(i)));
        let val_sum =
            (0..8).fold(QuadFelt::ZERO, |acc, m| acc + bp32[2 * m] * QuadFelt::from(mul_cell(m)));

        let role_contrib: QuadFelt = match row_kind {
            _ if row_kind == ROW_B => mul_s * full16_sum,
            _ if row_kind == ROW_P => {
                let borrow = mul_cell(M_COL_BORROW);
                QuadFelt::from(borrow) * (full16_sum + QuadFelt::ONE)
            },
            _ if row_kind == ROW_Q => -((mul_s + QuadFelt::ONE) * full_q_sum),
            _ if row_kind == ROW_R => -val_sum,
            _ if row_kind == ROW_C => {
                let kappa_c_signed =
                    main.values[r * NUM_MAIN_COLS + MUL_COL_OFFSET + TERM_CELL_KAPPA_C_SIGNED];
                QuadFelt::from(kappa_c_signed) * val_sum
            },
            _ => QuadFelt::ZERO,
        };
        let gamma_contrib: QuadFelt =
            slots_by_row[row_kind].iter().fold(QuadFelt::ZERO, |acc, &(s, c)| {
                let v = if s % 2 == 0 {
                    mul_cell(c) - mul_act * gamma_offset
                } else {
                    mul_cell(c)
                };
                acc + slot_weight(s) * QuadFelt::from(v)
            });
        mul_id += role_contrib + gamma_contrib;

        let build: QuadFelt = match row_kind {
            _ if row_kind == ROW_A => mul_kappa_a * full16_sum,
            _ if row_kind == ROW_P => full16_sum,
            _ => QuadFelt::ZERO,
        };
        let keep = QuadFelt::from(Felt::from(S_KEEP[row_kind] as u32));
        mul_s = mul_s * keep + build;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
