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
    // Clock boundary constraint: clk[0] = 0
    builder.when_first_row().assert_zero(local.clk.clone());

    // Clock transition constraint: clk' = clk + 1
    let one_expr: AB::Expr = AB::F::ONE.into();
    builder
        .when_transition()
        .assert_eq(next.clk.clone(), local.clk.clone() + one_expr);
}
