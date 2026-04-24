//! Public input boundary constraints.
//!
//! Enforces that the stack trace entries matches the claimed public inputs:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]

use miden_crypto::stark::air::AirBuilder;

use crate::{MainCols, MidenAirBuilder};

// CONSTANTS
// ================================================================================================

const STACK_DEPTH: usize = 16;

/// Number of public values at the tail of the public_values slice
/// (stack_inputs + stack_outputs + pc_transcript_state).
const TAIL_LEN: usize = STACK_DEPTH + STACK_DEPTH + 4;

// ENTRY POINTS
// ================================================================================================

/// Enforces public input boundary constraints for the stack.
///
/// - First row: `stack[i] == stack_inputs[i]` for i in 0..16
/// - Last row:  `stack[i] == stack_outputs[i]` for i in 0..16
pub fn enforce_main<AB>(builder: &mut AB, local: &MainCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // Copy public values into local arrays to release the immutable borrow on builder.
    let pv = builder.public_values();
    let n = pv.len();
    assert!(n >= TAIL_LEN, "public values too short: {n} < {TAIL_LEN}");
    let si: [AB::PublicVar; STACK_DEPTH] = core::array::from_fn(|i| pv[n - TAIL_LEN + i]);
    let so: [AB::PublicVar; STACK_DEPTH] =
        core::array::from_fn(|i| pv[n - TAIL_LEN + STACK_DEPTH + i]);

    // First row: stack[i] == stack_inputs[i]
    {
        let builder = &mut builder.when_first_row();
        #[allow(clippy::needless_range_loop)]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), si[i]);
        }
    }

    // Last row: stack[i] == stack_outputs[i]
    {
        let builder = &mut builder.when_last_row();
        #[allow(clippy::needless_range_loop)]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), so[i]);
        }
    }
}
