//! Chiplets constraints module (partial).
//!
//! Currently we implement:
//! - chiplet selector constraints
//! - hasher chiplet main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//! - kernel ROM chiplet main-trace constraints
//!
//! Chiplet bus constraints are enforced in the `chiplets::bus` module.

pub mod ace;
pub mod bitwise;
pub mod bus;
pub mod hasher;
pub mod kernel_rom;
pub mod memory;
pub mod selectors;

use selectors::ChipletSelectors;

use crate::{MainTraceRow, MidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Selector constraints are already enforced in build_chiplet_selectors (called from lib.rs).
    hasher::enforce_hasher_constraints(builder, local, next, selectors);
    bitwise::enforce_bitwise_constraints(builder, local, next, selectors);
    memory::enforce_memory_constraints(builder, local, next, selectors);
    ace::enforce_ace_constraints(builder, local, next, selectors);
    kernel_rom::enforce_kernel_rom_constraints(builder, local, next, selectors);
}
