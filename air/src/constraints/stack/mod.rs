//! Stack constraints module (partial).
//!
//! This module currently exposes the general stack transition constraints. Additional stack
//! constraint groups (u32, field, crypto, overflow, etc.) will be added in later chunks.

pub mod general;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{MainTraceRow, constraints::op_flags::OpFlags};

// ENTRY POINTS
// ================================================================================================

/// Enforces stack main-trace constraints for this group.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    general::enforce_main(builder, local, next, op_flags);
}
