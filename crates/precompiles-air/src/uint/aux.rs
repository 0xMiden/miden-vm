use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{AUX_WIDTH, CARRY_HI_BEGIN, CARRY_LO_BEGIN, NUM_MAIN_COLS, PERIOD, UintStoreAir};
use crate::logup::build_logup_aux_trace;

/// The store component's `id` register, read out of a main-trace column band.
///
/// `row_width` is the width of the enclosing trace and `col_offset` the band's first column, so
/// the per-row contribution matches `super::eval_main`'s role-gated expression exactly.
pub(crate) struct StoreRegisters {
    bp: [QuadFelt; 8],
    two16: Felt,
    t32: QuadFelt,
    row_width: usize,
    col_offset: usize,
}

impl StoreRegisters {
    pub(crate) fn new(beta: QuadFelt, row_width: usize, col_offset: usize) -> Self {
        // β^0..β^7.
        let mut bp = [QuadFelt::ZERO; 8];
        bp[0] = QuadFelt::ONE;
        for i in 1..8 {
            bp[i] = bp[i - 1] * beta;
        }
        Self {
            bp,
            two16: Felt::from(1u32 << 16),
            t32: QuadFelt::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p")),
            row_width,
            col_offset,
        }
    }

    /// Row `r`'s contribution to the `id` accumulator.
    pub(crate) fn contrib(&self, main: &RowMajorMatrix<Felt>, r: usize) -> QuadFelt {
        let bp = &self.bp;
        let limb = |c: usize| -> Felt { main.values[r * self.row_width + self.col_offset + c] };
        let recomb_lo07 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + self.two16 * limb(2 * k + 1);
                s + bp[k] * QuadFelt::from(rk)
            })
        };
        let recomb_hi07 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + self.two16 * limb(2 * k + 1);
                s + bp[4 + k] * QuadFelt::from(rk)
            })
        };
        let recomb_hi815 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(8 + 2 * k) + self.two16 * limb(8 + 2 * k + 1);
                s + bp[4 + k] * QuadFelt::from(rk)
            })
        };
        match r % PERIOD {
            0 => recomb_lo07(),
            1 => recomb_hi07(),
            2 => recomb_lo07() + recomb_hi815(),
            // Bound (closing) row: subtract both direct 4×32 halves, add
            // both hosted carries' (β^{j+1} − t·β^j) terms.
            3 => {
                let carry_lo = (0..4).fold(QuadFelt::ZERO, |s, j| {
                    let w = bp[j + 1] - bp[j] * self.t32;
                    s + w * QuadFelt::from(limb(CARRY_LO_BEGIN + j))
                });
                let carry_hi = (0..3).fold(QuadFelt::ZERO, |s, j| {
                    let w = bp[4 + j + 1] - bp[4 + j] * self.t32;
                    s + w * QuadFelt::from(limb(CARRY_HI_BEGIN + j))
                });
                let direct_lo =
                    (0..4).fold(QuadFelt::ZERO, |s, k| s + bp[k] * QuadFelt::from(limb(k)));
                let direct_hi =
                    (0..4).fold(QuadFelt::ZERO, |s, k| s + bp[4 + k] * QuadFelt::from(limb(8 + k)));
                carry_lo - direct_lo + carry_hi - direct_hi
            },
            _ => unreachable!("PERIOD = 4"),
        }
    }
}

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Col 0: LogUp running sum over the UintVal provide / consume.
    let (logup, sigma) = build_logup_aux_trace(&UintStoreAir, main, challenges);
    let n = main.height();
    let registers = StoreRegisters::new(challenges[1], NUM_MAIN_COLS, 0);

    // Col 1: the SZ register. id[0] = 0; id[r+1] = id[r] + contrib(row r).
    let logup_width = logup.width();
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);
        id += registers.contrib(main, r);
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
