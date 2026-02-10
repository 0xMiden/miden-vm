use alloc::vec::Vec;

use miden_core::{Felt, ONE, ZERO, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

// --- Periodic columns ---------------------------------------------------------------------------

/// Flag for the first row of each cycle in the periodic column.
pub const CYCLE_ROW_0: [Felt; 8] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

/// Negative flag for the last row of each cycle in the periodic column.
pub const INV_CYCLE_ROW_7: [Felt; 8] = [ONE, ONE, ONE, ONE, ONE, ONE, ONE, ZERO];

/// The number of periodic columns used in the Bitwise chiplet AIR.
pub const NUM_BITWISE_PERIODIC_VALUES: usize = 2;

/// Returns the periodic columns used in the Bitwise chiplet AIR.
pub fn bitwise_periodic_columns() -> Vec<Vec<Felt>> {
    vec![CYCLE_ROW_0.to_vec(), INV_CYCLE_ROW_7.to_vec()]
}

pub fn enforce_bitwise_chiplet_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    // TODO: add main bitwise constraints
}
