//! Chiplets bus constraints.
//!
//! This module groups auxiliary (bus) constraints associated with chiplets.
//! Currently implemented:
//! - b_hash_kernel: hash-kernel virtual table bus
//! - b_chiplets: main chiplets communication bus
//! - b_wiring: ACE wiring bus

pub mod chiplets;
pub mod hash_kernel;
pub mod wiring;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{Felt, MainTraceRow, constraints::op_flags::OpFlags};

/// Enforces chiplets bus constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    hash_kernel::enforce_hash_kernel_constraint(builder, local, next, op_flags);
    chiplets::enforce_chiplets_bus_constraint(builder, local, next, op_flags);
    wiring::enforce_wiring_bus_constraint(builder, local, next);
}
