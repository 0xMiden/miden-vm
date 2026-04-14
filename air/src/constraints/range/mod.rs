//! Range Checker Main Trace Constraints
//!
//! This module contains main trace constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//!
//! Bus constraints for the range checker are in `bus`.

pub mod columns;

use miden_crypto::stark::air::AirBuilder;

use crate::{MainCols, MidenAirBuilder, constraints::constants::*};

// ENTRY POINTS
// ================================================================================================

/// Enforces range checker main-trace constraints.
pub fn enforce_main<AB>(builder: &mut AB, local: &MainCols<AB::Var>, next: &MainCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    let v = local.range.value;
    let v_next = next.range.value;

    // Range checker boundaries: V[0] = 0, V[last] = 2^16 - 1
    {
        builder.when_first_row().assert_zero(v);
        builder.when_last_row().assert_eq(v, TWO_POW_16_MINUS_1);
    }

    // Transition constraint for the V column (degree 9).
    // V must change by one of: {0, 1, 3, 9, 27, 81, 243, 729, 2187}
    // - 0 allows V to stay constant during padding rows
    // - Others are powers of 3: {3^0, 3^1, 3^2, 3^3, 3^4, 3^5, 3^6, 3^7}
    {
        let change_v = v_next - v;
        builder.when_transition().assert_zero(
            change_v.clone()
                * (change_v.clone() - F_1)
                * (change_v.clone() - F_3)
                * (change_v.clone() - F_9)
                * (change_v.clone() - F_27)
                * (change_v.clone() - F_81)
                * (change_v.clone() - F_243)
                * (change_v.clone() - F_729)
                * (change_v - F_2187),
        );
    }
}
