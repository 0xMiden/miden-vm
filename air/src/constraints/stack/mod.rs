//! Stack constraints module.
//!
//! This module currently exposes the general stack transition and stack overflow constraints.

pub mod bus;
pub mod general;
pub mod overflow;

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
    overflow::enforce_main(builder, local, next, op_flags);
}
