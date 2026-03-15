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

use miden_crypto::stark::air::LiftedAirBuilder;

use crate::{Felt, MainTraceRow, constraints::op_flags::OpFlags, trace::Challenges};

/// Enforces chiplets bus constraints.
pub fn enforce_bus<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
    challenges: &Challenges<AB::ExprEF>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    hash_kernel::enforce_hash_kernel_constraint(builder, local, next, op_flags, challenges);
    chiplets::enforce_chiplets_bus_constraint(builder, local, next, op_flags, challenges);
    wiring::enforce_wiring_bus_constraint(builder, local, next, challenges);
}
