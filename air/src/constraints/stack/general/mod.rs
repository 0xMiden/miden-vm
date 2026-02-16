//! General stack transition constraints.
//!
//! This module contains the general constraints that enforce how stack items transition
//! based on the operation type (no shift, left shift, right shift).
//!
//! ## Stack Transition Model
//!
//! The stack has 16 visible positions (0-15). For each operation, stack items can:
//! - **Stay in place** (no shift): item stays at same position
//! - **Shift left**: item moves to position i from position i+1
//! - **Shift right**: item moves to position i from position i-1
//!
//! ## Constraints
//!
//! 1. **Position 0**: Can receive from position 0 (no shift) or position 1 (left shift). Right
//!    shift doesn't apply - position 0 gets a new value pushed.
//!
//! 2. **Positions 1-14**: Can receive from position i (no shift), i+1 (left shift), or i-1 (right
//!    shift).
//!
//! 3. **Position 15**: Can receive from position 15 (no shift) or position 14 (right shift). Left
//!    shift at position 15 is handled by overflow constraints (zeroing).
//!
//! 4. **Top binary**: Enforced by the specific op constraints that require it.

use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::{
        op_flags::OpFlags,
        tagging::{TAG_STACK_GENERAL_BASE, TaggingAirBuilderExt},
    },
};

// CONSTANTS
// ================================================================================================

/// Number of general stack constraints.
/// 16 constraints for stack item transitions.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 16;

/// The degrees of the general stack constraints.
/// Each transition constraint is degree 8 (flag degree 7 * item degree 1).
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // stack transitions
];

/// Tag base ID for stack general constraints.
const STACK_GENERAL_BASE_ID: usize = TAG_STACK_GENERAL_BASE;

/// Tag namespaces for stack general constraints.
const STACK_GENERAL_NAMES: [&str; NUM_CONSTRAINTS] = [
    "stack.general.transition.0",
    "stack.general.transition.1",
    "stack.general.transition.2",
    "stack.general.transition.3",
    "stack.general.transition.4",
    "stack.general.transition.5",
    "stack.general.transition.6",
    "stack.general.transition.7",
    "stack.general.transition.8",
    "stack.general.transition.9",
    "stack.general.transition.10",
    "stack.general.transition.11",
    "stack.general.transition.12",
    "stack.general.transition.13",
    "stack.general.transition.14",
    "stack.general.transition.15",
];

// ENTRY POINTS
// ================================================================================================

/// Enforces all general stack transition constraints.
///
/// This includes:
/// - 16 constraints for stack item transitions at each position
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    // For each position i, the constraint ensures that the next value is consistent
    // with the current value based on the shift flags:
    //
    // next[i] * flag_sum = no_shift[i] * current[i]
    //                    + left_shift[i+1] * current[i+1]
    //                    + right_shift[i-1] * current[i-1]
    //
    // Where flag_sum is the sum of applicable flags for that position.
    // Position 0: no right shift (new value pushed instead)
    // next[0] * flag_sum = no_shift[0] * current[0] + left_shift[1] * current[1]
    {
        let flag_sum = op_flags.no_shift_at(0) + op_flags.left_shift_at(1);
        let expected = op_flags.no_shift_at(0) * local.stack[0].clone().into()
            + op_flags.left_shift_at(1) * local.stack[1].clone().into();
        let actual: AB::Expr = next.stack[0].clone().into();

        builder.tagged(STACK_GENERAL_BASE_ID, STACK_GENERAL_NAMES[0], |builder| {
            builder.when_transition().assert_zero(actual * flag_sum - expected);
        });
    }

    // Positions 1-14: all three shift types possible
    for (i, &namespace) in STACK_GENERAL_NAMES.iter().enumerate().take(15).skip(1) {
        let flag_sum = op_flags.no_shift_at(i)
            + op_flags.left_shift_at(i + 1)
            + op_flags.right_shift_at(i - 1);

        let expected = op_flags.no_shift_at(i) * local.stack[i].clone().into()
            + op_flags.left_shift_at(i + 1) * local.stack[i + 1].clone().into()
            + op_flags.right_shift_at(i - 1) * local.stack[i - 1].clone().into();
        let actual: AB::Expr = next.stack[i].clone().into();

        let id = STACK_GENERAL_BASE_ID + i;
        builder.tagged(id, namespace, |builder| {
            builder.when_transition().assert_zero(actual * flag_sum - expected);
        });
    }

    // Position 15: no left shift (handled by overflow constraints)
    // next[15] * flag_sum = no_shift[15] * current[15] + right_shift[14] * current[14]
    {
        let flag_sum = op_flags.no_shift_at(15) + op_flags.right_shift_at(14);
        let expected = op_flags.no_shift_at(15) * local.stack[15].clone().into()
            + op_flags.right_shift_at(14) * local.stack[14].clone().into();
        let actual: AB::Expr = next.stack[15].clone().into();

        builder.tagged(STACK_GENERAL_BASE_ID + 15, STACK_GENERAL_NAMES[15], |builder| {
            builder.when_transition().assert_zero(actual * flag_sum - expected);
        });
    }
}
