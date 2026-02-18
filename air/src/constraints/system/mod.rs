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
//! ## Context Transitions
//!
//! | Operation    | ctx'                    | Description               |
//! |--------------|-------------------------|---------------------------|
//! | CALL/DYNCALL | clk + 1                 | Create new context        |
//! | SYSCALL      | 0                       | Return to kernel context  |
//! | END          | (from block stack table)| Restore previous context  |
//! | Others       | ctx                     | Unchanged                 |
//!
//! ## Function Hash Transitions
//!
//! | Operation    | fn_hash'                | Description                         |
//! |--------------|-------------------------|-------------------------------------|
//! | CALL/DYNCALL | decoder_h[0..4]         | Load new procedure hash             |
//! | END          | (from block stack table)| Restore previous hash               |
//! | Others       | fn_hash                 | Unchanged (including DYN, SYSCALL)  |
//!
//! Note: END operation's restoration is handled by the block stack table (bus-based),
//! not by these constraints. These constraints only handle the non-END cases.
//!
//! ## Implementation status
//!
//! - Clock constraints are enforced in this module.
//! - Context and function-hash transitions are documented here for auditability; enforcement is
//!   integrated alongside decoder/stack gating as those constraints are wired in.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

// ENTRY POINTS
// ================================================================================================

/// Enforces system constraints
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
