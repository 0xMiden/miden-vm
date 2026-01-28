//! Input/output operations constraints.
//!
//! This module contains the constraint for the SDEPTH operation which pushes
//! the current stack depth onto the stack.

use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::{MainTraceRow, trace::stack::B0_COL_IDX};

#[cfg(test)]
pub mod tests;

// CONSTANTS
// ================================================================================================

/// Number of I/O operations constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 1;

/// The degrees of the I/O operations constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    8, // SDEPTH constraint (degree 7 flag + degree 1 equality check)
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all I/O operations constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // SDEPTH pushes the current stack depth onto the stack.
    // Constraint: s0' = depth.
    // Stack depth is stored in the b0 helper column (B0_COL_IDX within the stack array)
    let depth: AB::Expr = local.stack[B0_COL_IDX].clone().into();
    let next_top: AB::Expr = next.stack[0].clone().into();

    // s0' = depth
    let constraint = next_top - depth;
    builder.when_transition().assert_zero(op_flags.sdepth() * constraint);
}
