use alloc::vec::Vec;
use core::array;

use miden_core::{Felt, ONE, ZERO, crypto::hash::Rpo256 as Hasher, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

// --- Periodic columns ---------------------------------------------------------------------------

/// Flag for the first row of each cycle in the periodic column.
pub const CYCLE_ROW_0: [Felt; 8] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

/// Flag for the second to last row of each cycle in the periodic column.
pub const CYCLE_ROW_6: [Felt; 8] = [ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ONE, ZERO];
/// Flag for the last row of each cycle in the periodic column.
pub const CYCLE_ROW_7: [Felt; 8] = [ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ONE];

/// Constants for the first half of the RPO round. The length is not padded to the period.
pub const RPO256_ARK1: [[Felt; 12]; 7] = Hasher::ARK1;

/// Constants for the second half of the RPO round. The length is not padded to the period.
pub const RPO256_ARK2: [[Felt; 12]; 7] = Hasher::ARK2;

/// The number of periodic columns used in the Bitwise chiplet AIR.
pub const NUM_HASHER_PERIODIC_VALUES: usize = 27;

/// Returns the periodic columns used in the Hasher chiplet AIR.
pub fn hasher_periodic_columns() -> Vec<Vec<Felt>> {
    let mut periodic_table = vec![CYCLE_ROW_0.to_vec(), CYCLE_ROW_6.to_vec(), CYCLE_ROW_7.to_vec()];

    // Transpose and pad the RPO round constant values to match the periodic column format
    let ark1 = (0..RPO256_ARK1[0].len())
        .map(|i| {
            let mut v = RPO256_ARK1.iter().map(|row| row[i]).collect::<Vec<Felt>>();
            v.push(ZERO);
            v
        })
        .collect::<Vec<_>>();
    let ark2 = (0..RPO256_ARK2[0].len())
        .map(|i| {
            let mut v = RPO256_ARK2.iter().map(|row| row[i]).collect::<Vec<Felt>>();
            v.push(ZERO);
            v
        })
        .collect::<Vec<_>>();
    periodic_table.extend_from_slice(&ark1);
    periodic_table.extend_from_slice(&ark2);
    periodic_table
}

pub fn enforce_hasher_chiplet_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    enforce_hasher_chiplet_selector_columns(builder, local, next, periodic_values);
    enforce_hasher_chiplet_node_index(builder, local, next, periodic_values);
    enforce_hasher_chiplet_hasher_state(builder, local, next, periodic_values);
}

fn enforce_hasher_chiplet_selector_columns<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero((AB::Expr::ONE - local.chiplets[0].clone().into()) * (local.chiplets[1].clone().into() * local.chiplets[1].clone().into() - local.chiplets[1].clone().into()));
    builder.assert_zero((AB::Expr::ONE - local.chiplets[0].clone().into()) * (local.chiplets[2].clone().into() * local.chiplets[2].clone().into() - local.chiplets[2].clone().into()));
    builder.assert_zero((AB::Expr::ONE - local.chiplets[0].clone().into()) * (local.chiplets[3].clone().into() * local.chiplets[3].clone().into() - local.chiplets[3].clone().into()));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into()))) * (AB::ExprEF::ONE - AB::ExprEF::from(periodic_values[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(next.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(next.chiplets[2].clone().into()))) * (AB::ExprEF::from(next.chiplets[2].clone().into()) - AB::ExprEF::from(local.chiplets[2].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into()))) * (AB::ExprEF::ONE - AB::ExprEF::from(periodic_values[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(next.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(next.chiplets[2].clone().into()))) * (AB::ExprEF::from(next.chiplets[3].clone().into()) - AB::ExprEF::from(local.chiplets[3].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(next.chiplets[1].clone().into()));
    builder.assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(local.chiplets[2].clone().into()));
}

fn enforce_hasher_chiplet_node_index<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * (AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) + AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * AB::ExprEF::from(local.chiplets[3].clone().into())) * ((AB::ExprEF::from(local.chiplets[16].clone().into()) - AB::ExprEF::from(next.chiplets[16].clone().into()).double()) * (AB::ExprEF::from(local.chiplets[16].clone().into()) - AB::ExprEF::from(next.chiplets[16].clone().into()).double()) - (AB::ExprEF::from(local.chiplets[16].clone().into()) - AB::ExprEF::from(next.chiplets[16].clone().into()).double())));
    builder.assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * AB::ExprEF::from(local.chiplets[16].clone().into()));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * (AB::ExprEF::ONE - (AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) + AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) + AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * AB::ExprEF::from(local.chiplets[2].clone().into()) * AB::ExprEF::from(local.chiplets[3].clone().into()) + AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())))) * (AB::ExprEF::from(next.chiplets[16].clone().into()) - AB::ExprEF::from(local.chiplets[16].clone().into())));
}

fn enforce_hasher_chiplet_hasher_state<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    enforce_rpo_round(builder, local, next, periodic_values);

    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[4].clone().into()) - AB::ExprEF::from(local.chiplets[4].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[5].clone().into()) - AB::ExprEF::from(local.chiplets[5].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[6].clone().into()) - AB::ExprEF::from(local.chiplets[6].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[7].clone().into()) - AB::ExprEF::from(local.chiplets[7].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[8].clone().into()) - AB::ExprEF::from(local.chiplets[8].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[9].clone().into()) - AB::ExprEF::from(local.chiplets[9].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[10].clone().into()) - AB::ExprEF::from(local.chiplets[10].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[11].clone().into()) - AB::ExprEF::from(local.chiplets[11].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[12].clone().into()) - AB::ExprEF::from(local.chiplets[12].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[13].clone().into()) - AB::ExprEF::from(local.chiplets[13].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[14].clone().into()) - AB::ExprEF::from(local.chiplets[14].clone().into())));
    builder.when_transition().assert_zero_ext((AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * AB::ExprEF::from(local.chiplets[1].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[2].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[3].clone().into())) * (AB::ExprEF::from(next.chiplets[15].clone().into()) - AB::ExprEF::from(local.chiplets[15].clone().into())));
}

#[inline(always)]
pub fn apply_sbox<AB>(
    state: [AB::ExprEF; 12],
) -> [AB::ExprEF; 12]
where
    AB: MidenAirBuilder,
{
    state.map(|s| {
        let s2 = s.square();
        let s4 = s2.square();
        s * s4 * s2
    })
}

#[inline(always)]
pub fn apply_mds<AB>(
    state: [AB::ExprEF; 12],
) -> [AB::ExprEF; 12]
where
    AB: MidenAirBuilder,
{
    let mut result = [AB::ExprEF::ZERO; 12];
    result[0] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(8);
    result[1] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(21);
    result[2] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(22);
    result[3] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(6);
    result[4] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(7);
    result[5] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(9);
    result[6] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(10);
    result[7] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(13);
    result[8] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(26);
    result[9] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(8);
    result[10] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(23);
    result[11] = AB::ExprEF::from(state[0].clone()) * AB::ExprEF::from_u64(23) + AB::ExprEF::from(state[1].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[2].clone()) * AB::ExprEF::from_u64(26) + AB::ExprEF::from(state[3].clone()) * AB::ExprEF::from_u64(13) + AB::ExprEF::from(state[4].clone()) * AB::ExprEF::from_u64(10) + AB::ExprEF::from(state[5].clone()) * AB::ExprEF::from_u64(9) + AB::ExprEF::from(state[6].clone()) * AB::ExprEF::from_u64(7) + AB::ExprEF::from(state[7].clone()) * AB::ExprEF::from_u64(6) + AB::ExprEF::from(state[8].clone()) * AB::ExprEF::from_u64(22) + AB::ExprEF::from(state[9].clone()) * AB::ExprEF::from_u64(21) + AB::ExprEF::from(state[10].clone()) * AB::ExprEF::from_u64(8) + AB::ExprEF::from(state[11].clone()) * AB::ExprEF::from_u64(7);

    result
}

fn enforce_rpo_round<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    let h: [<AB as MidenAirBuilder>::ExprEF; 12] = [
        AB::ExprEF::from(local.chiplets[4].clone().into()),
        AB::ExprEF::from(local.chiplets[5].clone().into()),
        AB::ExprEF::from(local.chiplets[6].clone().into()),
        AB::ExprEF::from(local.chiplets[7].clone().into()),
        AB::ExprEF::from(local.chiplets[8].clone().into()),
        AB::ExprEF::from(local.chiplets[9].clone().into()),
        AB::ExprEF::from(local.chiplets[10].clone().into()),
        AB::ExprEF::from(local.chiplets[11].clone().into()),
        AB::ExprEF::from(local.chiplets[12].clone().into()),
        AB::ExprEF::from(local.chiplets[13].clone().into()),
        AB::ExprEF::from(local.chiplets[14].clone().into()),
        AB::ExprEF::from(local.chiplets[15].clone().into()),
    ];

    let step1_initial: [<AB as MidenAirBuilder>::ExprEF; 12] = apply_mds::<AB>(h);

    let ark1 = [
        AB::ExprEF::from(periodic_values[1].clone().into()),
        AB::ExprEF::from(periodic_values[2].clone().into()),
        AB::ExprEF::from(periodic_values[5].clone().into()),
        AB::ExprEF::from(periodic_values[6].clone().into()),
        AB::ExprEF::from(periodic_values[7].clone().into()),
        AB::ExprEF::from(periodic_values[8].clone().into()),
        AB::ExprEF::from(periodic_values[9].clone().into()),
        AB::ExprEF::from(periodic_values[10].clone().into()),
        AB::ExprEF::from(periodic_values[11].clone().into()),
        AB::ExprEF::from(periodic_values[12].clone().into()),
        AB::ExprEF::from(periodic_values[3].clone().into()),
        AB::ExprEF::from(periodic_values[4].clone().into())
    ];

    let step1_with_constants: [<AB as MidenAirBuilder>::ExprEF; 12] = array::from_fn(|i| AB::ExprEF::from(step1_initial[i].clone()) + ark1[i].clone());

    let step1_with_sbox: [<AB as MidenAirBuilder>::ExprEF; 12] = apply_sbox::<AB>(step1_with_constants.map(|e| e.into()));

    let step1_with_mds: [<AB as MidenAirBuilder>::ExprEF; 12] = apply_mds::<AB>(step1_with_sbox);

    let ark2 = [
        AB::ExprEF::from(periodic_values[1].clone().into()),
        AB::ExprEF::from(periodic_values[2].clone().into()),
        AB::ExprEF::from(periodic_values[5].clone().into()),
        AB::ExprEF::from(periodic_values[6].clone().into()),
        AB::ExprEF::from(periodic_values[7].clone().into()),
        AB::ExprEF::from(periodic_values[8].clone().into()),
        AB::ExprEF::from(periodic_values[9].clone().into()),
        AB::ExprEF::from(periodic_values[10].clone().into()),
        AB::ExprEF::from(periodic_values[11].clone().into()),
        AB::ExprEF::from(periodic_values[12].clone().into()),
        AB::ExprEF::from(periodic_values[3].clone().into()),
        AB::ExprEF::from(periodic_values[4].clone().into())
    ];

    let step1: [<AB as MidenAirBuilder>::ExprEF; 12] = array::from_fn(|i| AB::ExprEF::from(step1_with_mds[i].clone()) + ark2[i].clone());

    let h_prime: [<AB as MidenAirBuilder>::ExprEF; 12] = [
        AB::ExprEF::from(next.chiplets[4].clone().into()),
        AB::ExprEF::from(next.chiplets[5].clone().into()),
        AB::ExprEF::from(next.chiplets[6].clone().into()),
        AB::ExprEF::from(next.chiplets[7].clone().into()),
        AB::ExprEF::from(next.chiplets[8].clone().into()),
        AB::ExprEF::from(next.chiplets[9].clone().into()),
        AB::ExprEF::from(next.chiplets[10].clone().into()),
        AB::ExprEF::from(next.chiplets[11].clone().into()),
        AB::ExprEF::from(next.chiplets[12].clone().into()),
        AB::ExprEF::from(next.chiplets[13].clone().into()),
        AB::ExprEF::from(next.chiplets[14].clone().into()),
        AB::ExprEF::from(next.chiplets[15].clone().into()),
    ];

    let step2: [AB::ExprEF; 12] = apply_sbox::<AB>(h_prime);

    for i in 0..12 {
        builder.when_transition().assert_zero_ext(
            (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[0].clone().into())) * (AB::ExprEF::ONE - AB::ExprEF::from(periodic_values[0].clone().into())) * (step2[i].clone() - step1[i].clone())
        );
    }
}
