use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_stark::{
    air::native::{AuxTrace, AuxTraceInputs},
    lookup::native::{LookupError, build_logup_aux_trace},
};

use super::{
    AUX_WIDTH, CARRY_HI_BEGIN, CARRY_LO_BEGIN, NUM_MAIN_COLS, PERIOD, REGISTER_COL, UintStoreAir,
};

pub(crate) fn build_aux(
    inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
) -> Result<AuxTrace<QuadFelt>, LookupError> {
    let main = inputs.main;
    let challenges = inputs.challenges;
    let mut aux = build_logup_aux_trace(&UintStoreAir, inputs)?;
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

    // The SZ suffix starts at zero and follows the authored role-gated recurrence.
    // The normalized LogUp export and its prefix columns remain untouched.
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        aux.columns.values[r * AUX_WIDTH + REGISTER_COL] = id;

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

    Ok(aux)
}
