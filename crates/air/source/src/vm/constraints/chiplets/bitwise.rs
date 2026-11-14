//! Bitwise chiplet constraints.
//!
//! The bitwise chiplet handles AND and XOR operations on 32-bit values.
//! Normal bitwise rows store byte witnesses for one full u32 operation. The byte-pair lookup maps
//! each AND witness onto the canonical `(a_byte, b_byte, a_byte xor b_byte)` relation; the chiplet
//! response bus recomposes the VM-facing `(op, a, b, result)` message.

use {
    miden_stark::air::AirBuilder,
    crate::vm::MidenAirBuilder,
    crate::vm::constraints::chiplets::columns::BitwiseOpCols,
    crate::vm::constraints::chiplets::selectors::ChipletSelectors,
};

// ENTRY POINTS
// ================================================================================================

/// Enforce all bitwise chiplet constraints.
///
/// This enforces the row-local operation flag. Byte range and bytewise AND correctness are
/// enforced by the shared AND8 lookup.
pub fn enforce_bitwise_constraints<AB>(
    builder: &mut AB,
    cols: &BitwiseOpCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // The operation flag is meaningful only on bitwise rows.
    let bitwise_builder = &mut builder.when(selectors.bitwise_active.clone());

    // 0 = AND, 1 = XOR.
    bitwise_builder.assert_bool(cols.op_flag);
}
