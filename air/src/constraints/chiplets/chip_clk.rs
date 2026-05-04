//! Chiplet-trace row counter constraints.
//!
//! `chip_clk` is a chiplet-trace column that increments by 1 each row, starting at 1 on the
//! first row. It serves as the chiplet-side responder address for the hasher LogUp bus.
//!
//! The processor's chiplet trace generator fills this column with `[1, 2, 3, ..., trace_len]`.
//! On hasher controller-input rows, `chip_clk` equals what the decoder records into
//! `user_op_helpers[0]` (`HasherChipletShim::addr` in `processor/src/trace/execution_tracer.rs`),
//! so the request side and response side encode the same address value and the bus balances.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{ChipletCols, MidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces the chiplet-trace row-counter constraints:
///
/// - **Boundary:** `chip_clk` equals 1 on the first row.
/// - **Transition:** `chip_clk_next = chip_clk + 1` on every row pair.
pub fn enforce_chip_clk_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // Boundary: chip_clk[0] = 1.
    builder.when_first_row().assert_eq(local.chip_clk, AB::Expr::ONE);

    // Transition: chip_clk_next = chip_clk + 1.
    builder
        .when_transition()
        .assert_eq(next.chip_clk.into(), local.chip_clk.into() + AB::Expr::ONE);
}
