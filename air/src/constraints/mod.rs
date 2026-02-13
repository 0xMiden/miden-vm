//! Miden VM Constraints
//!
//! This module contains the constraint functions for the Miden VM processor.
//! Constraints are organized by component:
//! - System-level constraints (clock)
//! - Range checker constraints
//! - (Future: decoder, stack, chiplets)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub mod bus;
pub mod range;

/// Enforces the clock constraint: clk' = clk + 1
///
/// The clock must increment by 1 at each step, ensuring proper sequencing of operations.
pub fn enforce_clock_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let clk = local.clk.clone();
    let clk_next = next.clk.clone();

    // Clock boundary constraint: clk[0] = 0
    builder.when_first_row().assert_zero(clk.clone());

    // Clock transition constraint: clk' = clk + 1
    builder.when_transition().assert_eq(clk_next, clk + AB::Expr::ONE);
}
