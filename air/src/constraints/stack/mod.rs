//! Stack constraints module.
//!
//! This module exposes the general stack transition, stack ops, stack arith/u32, stack crypto,
//! and stack overflow constraints.

pub mod bus;
pub mod crypto;
pub mod general;
pub mod ops;
pub mod overflow;
pub mod stack_arith;

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
    ops::enforce_main(builder, local, next, op_flags);
    crypto::enforce_main(builder, local, next, op_flags);
    stack_arith::enforce_main(builder, local, next, op_flags);
}
