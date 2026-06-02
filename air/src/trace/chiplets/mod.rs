use miden_core::{Felt, ONE, ZERO};

pub mod ace;
pub mod bitwise;
pub mod hasher;
pub mod memory;

// CONSTANTS
// ================================================================================================

/// The number of columns in the chiplets which are used as selectors for the bitwise chiplet.
pub const NUM_BITWISE_SELECTORS: usize = 2;
/// The number of columns in the chiplets which are used as selectors for the memory chiplet.
pub const NUM_MEMORY_SELECTORS: usize = 3;
/// The number of columns in the chiplets which are used as selectors for the ACE chiplet.
pub const NUM_ACE_SELECTORS: usize = 4;
/// The number of columns in the chiplets which are used as selectors for the kernel ROM chiplet.
pub const NUM_KERNEL_ROM_SELECTORS: usize = 5;

/// Number of columns needed to record an execution trace of the kernel ROM chiplet.
pub const KERNEL_ROM_TRACE_WIDTH: usize = 5;
