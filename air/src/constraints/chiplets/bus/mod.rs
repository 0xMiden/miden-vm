//! Chiplets bus constraints.
//!
//! This module groups all auxiliary (bus) constraints associated with chiplets:
//! - b_chiplets: main chiplets communication bus
//! - b_hash_kernel: hash-kernel virtual table bus
//! - v_wiring: ACE wiring bus

pub mod chiplets;
pub mod hash_kernel;
pub mod wiring;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow, constraints::stack::op_flags::OpFlags};

// ENTRY POINTS
// ================================================================================================

/// Enforces all chiplets bus constraints (b_chiplets, b_hash_kernel, v_wiring).
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    chiplets::enforce_chiplets_bus_constraint(builder, local, next, op_flags);
    hash_kernel::enforce_hash_kernel_constraint(builder, local, next, op_flags);
    wiring::enforce_wiring_bus_constraint(builder, local, next);
}
