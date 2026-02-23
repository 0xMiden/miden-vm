//! Tag ID bases and counts for constraint groups.

#![allow(dead_code)]

/// Base ID for the system constraint group.
pub const TAG_SYSTEM_BASE: usize = 0;
/// Number of system constraints in this group.
pub const TAG_SYSTEM_COUNT: usize = 13;

/// Base ID for the range constraint group.
pub const TAG_RANGE_BASE: usize = TAG_SYSTEM_BASE + TAG_SYSTEM_COUNT;
/// Number of range constraints in this group.
pub const TAG_RANGE_COUNT: usize = 4;

/// Highest constraint ID (zero-based) for the current group set.
pub const CURRENT_MAX_ID: usize = TAG_RANGE_BASE + TAG_RANGE_COUNT - 1;
/// Total tagged constraints in the current group set.
pub const TOTAL_TAGS: usize = CURRENT_MAX_ID + 1;
