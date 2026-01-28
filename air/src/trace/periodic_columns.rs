use miden_core::crypto::hash::Rpo256;

use crate::Felt;

/// The number of periodic columns used in the Miden VM AIR.
pub const NUM_PERIODIC_VALUES: usize = 29;
/// The period of all periodic columns used in the Miden VM AIR.
pub const PERIOD: usize = 8;

/// Flag for the first row of each cycle in the periodic column.
pub const CYCLE_ROW_0: [Felt; 8] = [
    Felt::new(1),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
];
/// Negative flag for the last row of each cycle in the periodic column.
pub const INV_CYCLE_ROW_7: [Felt; 8] = [
    Felt::new(1),
    Felt::new(1),
    Felt::new(1),
    Felt::new(1),
    Felt::new(1),
    Felt::new(1),
    Felt::new(1),
    Felt::new(0),
];
/// Flag for the second to last row of each cycle in the periodic column.
pub const CYCLE_ROW_6: [Felt; 8] = [
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(1),
    Felt::new(0),
];
/// Flag for the last row of each cycle in the periodic column.
pub const CYCLE_ROW_7: [Felt; 8] = [
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(0),
    Felt::new(1),
];

/// Constants for the first half of the RPO round. Note that the length is not padded to the period.
pub const RPO256_ARK1: [[Felt; 12]; 7] = Rpo256::ARK1;
/// Constants for the second half of the RPO round. Note that the length is not padded to the
/// period.
pub const RPO256_ARK2: [[Felt; 12]; 7] = Rpo256::ARK2;
