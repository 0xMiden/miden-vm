//! Bitwise chiplet constraints.
//!
//! The bitwise chiplet handles AND and XOR operations on 32-bit values.
//! Normal bitwise rows store byte witnesses for one full u32 operation. The AND8 lookup binds
//! each byte triple `(a_byte, b_byte, and_byte)`; the chiplet response bus recomposes the VM-facing
//! `(op, a, b, result)` message.

use crate::{
    AirBuilder, ChipletCols, MidenAirBuilder, constraints::chiplets::columns::BitwiseCols,
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all bitwise chiplet constraints.
///
/// This enforces the row-local operation flag. Byte range and bytewise AND correctness are
/// enforced by the shared AND8 lookup.
pub fn enforce_bitwise_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    _next: &ChipletCols<AB::Var>,
    normal_bitwise: AB::Expr,
) where
    AB: MidenAirBuilder,
{
    let cols: &BitwiseCols<AB::Var> = local.bitwise();

    // Normal bitwise rows are disabled while the AEAD stream overlay uses this region.
    let bitwise_builder = &mut builder.when(normal_bitwise);

    // 0 = AND, 1 = XOR.
    bitwise_builder.assert_bool(cols.op_flag);
}
