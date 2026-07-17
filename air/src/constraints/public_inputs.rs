//! Public input boundary constraints.
//!
//! Enforces that the stack trace entries match the claimed public inputs:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]

use miden_crypto::stark::air::AirBuilder;

use crate::{CoreCols, MidenAirBuilder};

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
pub fn enforce_main<AB>(builder: &mut AB, local: &CoreCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // Copy public values into local arrays to release the immutable borrow on builder.
    let pv = builder.public_values();
    let n = pv.len();
    assert!(n >= PUBLIC_LEN, "public values too short: {n} < {PUBLIC_LEN}");
    let si: [AB::PublicVar; STACK_DEPTH] = core::array::from_fn(|i| pv[i]);
    let so: [AB::PublicVar; STACK_DEPTH] = core::array::from_fn(|i| pv[STACK_DEPTH + i]);

    // First row: stack[i] == stack_inputs[i]
    {
        let builder = &mut builder.when_first_row();
        #[expect(
            clippy::needless_range_loop,
            reason = "index-based loop keeps the stack input slot mapping explicit"
        )]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), si[i]);
        }
    }

    // Last row: stack[i] == stack_outputs[i]
    {
        let builder = &mut builder.when_last_row();
        #[expect(
            clippy::needless_range_loop,
            reason = "index-based loop keeps the stack output slot mapping explicit"
        )]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), so[i]);
        }
    }
}
