//! Tag group base IDs and sizes.

/// Base ID for the system constraint group.
pub const TAG_SYSTEM_BASE: usize = 0;
/// Number of system clock constraints.
pub const TAG_SYSTEM_CLK_COUNT: usize = 2;
/// Number of system context constraints.
pub const TAG_SYSTEM_CTX_COUNT: usize = 3;
/// Number of system function-hash constraints.
pub const TAG_SYSTEM_FN_HASH_COUNT: usize = 8;

/// Base ID for the system clock constraints.
pub const TAG_SYSTEM_CLK_BASE: usize = TAG_SYSTEM_BASE;
/// Base ID for the system context constraints.
pub const TAG_SYSTEM_CTX_BASE: usize = TAG_SYSTEM_CLK_BASE + TAG_SYSTEM_CLK_COUNT;
/// Base ID for the system function-hash constraints.
pub const TAG_SYSTEM_FN_HASH_BASE: usize = TAG_SYSTEM_CTX_BASE + TAG_SYSTEM_CTX_COUNT;

/// Total number of system constraints in this group.
pub const TAG_SYSTEM_COUNT: usize =
    TAG_SYSTEM_CLK_COUNT + TAG_SYSTEM_CTX_COUNT + TAG_SYSTEM_FN_HASH_COUNT;

/// Base ID for the range checker main constraint group.
pub const TAG_RANGE_MAIN_BASE: usize = TAG_SYSTEM_BASE + TAG_SYSTEM_COUNT;
/// Number of range checker main constraints in this group.
pub const TAG_RANGE_MAIN_COUNT: usize = 3;

/// Base ID for the range checker bus constraint group.
pub const TAG_RANGE_BUS_BASE: usize = TAG_RANGE_MAIN_BASE + TAG_RANGE_MAIN_COUNT;
/// Number of range checker bus constraints in this group.
#[cfg(all(test, feature = "std"))]
pub const TAG_RANGE_BUS_COUNT: usize = 1;

/// Total number of tagged constraints in the current group set.
#[cfg(all(test, feature = "std"))]
pub const TAG_TOTAL_COUNT: usize = TAG_RANGE_BUS_BASE + TAG_RANGE_BUS_COUNT;
