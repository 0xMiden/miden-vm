use super::{bitwise::NUM_BITWISE_PERIODIC_VALUES, hasher::NUM_HASHER_PERIODIC_VALUES};

/// The number of periodic columns used in the Miden VM AIR.
pub const NUM_PERIODIC_VALUES: usize = NUM_BITWISE_PERIODIC_VALUES + NUM_HASHER_PERIODIC_VALUES;
