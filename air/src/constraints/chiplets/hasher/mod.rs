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
    // TODO: add main hasher selector columns constraints
}

fn enforce_hasher_chiplet_node_index<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    // TODO: add main hasher node index constraints
}

fn enforce_hasher_chiplet_hasher_state<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    // TODO: add main hasher state constraints
}
