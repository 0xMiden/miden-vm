//! Public input boundary constraints.
//!
//! Enforces that the stack trace entries match the claimed public inputs:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]

use miden_stark::air::{Frame, Inputs, LiftedAirBuilder};
use p3_field::Dup;

use crate::vm::{CoreCols, NativeMidenAirBuilder};

// CONSTANTS
// ================================================================================================

const STACK_DEPTH: usize = 16;

/// Number of public values consumed by the stack boundary (stack_inputs + stack_outputs).
const PUBLIC_LEN: usize = STACK_DEPTH + STACK_DEPTH;

// ENTRY POINTS
// ================================================================================================

/// Enforces public input boundary constraints for the stack.
///
/// - First row: `stack[i] == stack_inputs[i]` for i in 0..16
/// - Last row:  `stack[i] == stack_outputs[i]` for i in 0..16
pub fn enforce_main<AB>(
    frame: &Frame<'_, AB>,
    inputs: Inputs<'_, AB>,
    builder: &mut AB,
    local: &CoreCols<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    let pv = inputs.public_values;
    let n = pv.len();
    assert!(n >= PUBLIC_LEN, "public values too short: {n} < {PUBLIC_LEN}");

    // First row: stack[i] == stack_inputs[i]
    {
        let builder = &mut builder.when(frame.first_row());
        for (i, value) in pv[..STACK_DEPTH].iter().enumerate() {
            builder.assert_eq(local.stack.get(i), value.dup());
        }
    }

    // Last row: stack[i] == stack_outputs[i]
    {
        let builder = &mut builder.when(frame.last_row());
        for (i, value) in pv[STACK_DEPTH..PUBLIC_LEN].iter().enumerate() {
            builder.assert_eq(local.stack.get(i), value.dup());
        }
    }
}
