use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{AUX_WIDTH, CARRY_HI_BEGIN, CARRY_LO_BEGIN, NUM_MAIN_COLS, PERIOD, UintStoreAir};
use crate::logup::build_logup_aux_trace;

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Col 0: LogUp running sum over the UintVal provide / consume.
    let (logup, sigma) = build_logup_aux_trace(&UintStoreAir, main, challenges);
    let n = main.height();
    let beta = challenges[1];

    // β^0..β^7.
    let mut bp = [QuadFelt::ZERO; 8];
    bp[0] = QuadFelt::ONE;
    for i in 1..8 {
        bp[i] = bp[i - 1] * beta;
    }
    let two16 = Felt::from(1u32 << 16);
    let t32 = QuadFelt::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

    // Col 1: the SZ register. id[0] = 0; id[r+1] = id[r] + contrib(row r),
    // contrib matching UintStoreAir's role-gated expression exactly.
    let logup_width = logup.width();
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);

        let limb = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let recomb_lo07 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + two16 * limb(2 * k + 1);
                s + bp[k] * QuadFelt::from(rk)
            })
        };
        let recomb_hi07 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + two16 * limb(2 * k + 1);
                s + bp[4 + k] * QuadFelt::from(rk)
            })
        };
        let recomb_hi815 = || {
            (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(8 + 2 * k) + two16 * limb(8 + 2 * k + 1);
                s + bp[4 + k] * QuadFelt::from(rk)
            })
        };
        let contrib: QuadFelt = match r % PERIOD {
            0 => recomb_lo07(),
            1 => recomb_hi07(),
            2 => recomb_lo07() + recomb_hi815(),
            // Bound (closing) row: subtract both direct 4×32 halves, add
            // both hosted carries' (β^{j+1} − t·β^j) terms.
            3 => {
                let carry_lo = (0..4).fold(QuadFelt::ZERO, |s, j| {
                    let w = bp[j + 1] - bp[j] * t32;
                    s + w * QuadFelt::from(limb(CARRY_LO_BEGIN + j))
                });
                let carry_hi = (0..3).fold(QuadFelt::ZERO, |s, j| {
                    let w = bp[4 + j + 1] - bp[4 + j] * t32;
                    s + w * QuadFelt::from(limb(CARRY_HI_BEGIN + j))
                });
                let direct_lo =
                    (0..4).fold(QuadFelt::ZERO, |s, k| s + bp[k] * QuadFelt::from(limb(k)));
                let direct_hi =
                    (0..4).fold(QuadFelt::ZERO, |s, k| s + bp[4 + k] * QuadFelt::from(limb(8 + k)));
                carry_lo - direct_lo + carry_hi - direct_hi
            },
            _ => unreachable!("PERIOD = 4"),
        };
        id += contrib;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
