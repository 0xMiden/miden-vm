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
    beta.powers().fill(&mut bp);
    let t32 = Felt::new(1u64 << 32).expect("2^32 < Goldilocks p");

    // The SZ suffix starts at zero and follows the authored role-gated recurrence.
    // The normalized LogUp export and its prefix columns remain untouched.
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        aux.columns.values[r * AUX_WIDTH + REGISTER_COL] = id;

        let limb = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let recomb_lo07 = || {
            let limbs: [Felt; 4] =
                array::from_fn(|k| limb(2 * k) + limb(2 * k + 1).mul_2exp_u64(16));
            <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                bp[..4].try_into().expect("four limb weights"),
                &limbs,
            )
        };
        let recomb_hi07 = || {
            let limbs: [Felt; 4] =
                array::from_fn(|k| limb(2 * k) + limb(2 * k + 1).mul_2exp_u64(16));
            <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                bp[4..].try_into().expect("four limb weights"),
                &limbs,
            )
        };
        let recomb_hi815 = || {
            let limbs: [Felt; 4] =
                array::from_fn(|k| limb(8 + 2 * k) + limb(8 + 2 * k + 1).mul_2exp_u64(16));
            <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                bp[4..].try_into().expect("four limb weights"),
                &limbs,
            )
        };
        let contrib: QuadFelt = match r % PERIOD {
            0 => recomb_lo07(),
            1 => recomb_hi07(),
            2 => recomb_lo07() + recomb_hi815(),
            // Bound (closing) row: subtract both direct 4×32 halves, add
            // both hosted carries' (β^{j+1} − t·β^j) terms.
            3 => {
                let carry_lo = (0..4)
                    .map(|j| {
                        let w = bp[j + 1] - bp[j] * t32;
                        w * limb(CARRY_LO_BEGIN + j)
                    })
                    .sum::<QuadFelt>();
                let carry_hi = (0..3)
                    .map(|j| {
                        let w = bp[4 + j + 1] - bp[4 + j] * t32;
                        w * limb(CARRY_HI_BEGIN + j)
                    })
                    .sum::<QuadFelt>();
                let direct_lo = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                    bp[..4].try_into().expect("low bound weights"),
                    &array::from_fn(&limb),
                );
                let direct_hi = <QuadFelt as Algebra<Felt>>::mixed_dot_product::<4>(
                    bp[4..].try_into().expect("high bound weights"),
                    &array::from_fn(|k| limb(8 + k)),
                );
                carry_lo + carry_hi - (direct_lo + direct_hi)
            },
            _ => unreachable!("PERIOD = 4"),
        };
        id += contrib;
    }

    Ok(aux)
}
