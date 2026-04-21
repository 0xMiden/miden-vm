//! Chiplets constraints module.
//!
//! Currently we implement:
//! - chiplet selector constraints (including hasher internal selectors)
//! - permutation sub-chiplet main-trace constraints
//! - controller sub-chiplet main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//!
//! Chiplet LogUp lookup-argument constraints are emitted by
//! [`crate::constraints::lookup::ChipletLookupAir`] and wired through
//! `MidenLookupAir` from `ProcessorAir::eval`.

pub mod ace;
pub mod bitwise;
pub mod columns;
pub mod hasher_control;
pub mod memory;
pub mod permutation;
pub mod selectors;

use selectors::ChipletSelectors;

use crate::{MainCols, MidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // Selector constraints (including hasher internal selectors) are enforced in
    // build_chiplet_selectors (called from lib.rs).

    // Hasher sub-chiplets: permutation + controller.
    permutation::enforce_permutation_constraints(builder, local, next, &selectors.permutation);
    hasher_control::enforce_controller_constraints(builder, local, next, &selectors.controller);

    bitwise::enforce_bitwise_constraints(builder, local, next, &selectors.bitwise);
    memory::enforce_memory_constraints(builder, local, next, &selectors.memory);
    ace::enforce_ace_constraints_all_rows(builder, local, next, &selectors.ace);
}
