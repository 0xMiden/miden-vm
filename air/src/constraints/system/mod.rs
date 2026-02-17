//! System constraints module.
//!
//! This module contains constraints for the system component of the Miden VM.
//!
//! ## System Columns
//!
//! - `clk`: VM execution clock (clk[0] = 0, clk' = clk + 1)
//! - `ctx`: Execution context ID (determines memory context isolation)
//! - `fn_hash[0..4]`: Current function digest (identifies executing procedure)
//!
//! Note: Only the clock constraint is enforced here. Context and function-hash transitions
//! are handled alongside decoder/stack gating constraints.

use miden_crypto::stark::air::MidenAirBuilder;
use p3_miden_air::PrimeCharacteristicRing;

use crate::MainTraceRow;

// ENTRY POINTS
// ================================================================================================

/// Enforces system constraints.
pub fn enforce_main<AB>(
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
