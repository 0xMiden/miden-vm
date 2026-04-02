//! Range Checker Main Trace Constraints
//!
//! This module contains main trace constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//!
//! Bus constraints for the range checker are in `bus`.

use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::constants::*,
    trace::{RANGE_CHECK_TRACE_OFFSET, range},
};

pub mod bus;

// CONSTANTS
// ================================================================================================

// --- SLICE-RELATIVE INDICES ---------------------------------------------------------------------
const RANGE_V_COL_IDX: usize = range::V_COL_IDX - RANGE_CHECK_TRACE_OFFSET;

// ENTRY POINTS
// ================================================================================================

/// Enforces range checker main-trace constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_range_boundary_constraints(builder, local);
    enforce_range_transition_constraint(builder, local, next);
}

/// Enforces boundary constraints for the range checker.
///
/// - First row: V[0] = 0 (range checker starts at 0)
/// - Last row: V[last] = 65535 (range checker ends at 2^16 - 1)
pub fn enforce_range_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    let v = local.range[RANGE_V_COL_IDX];

    // First row: V[0] = 0
    builder.when_first_row().assert_zero(v);

    // Last row: V[last] = 65535 (2^16 - 1)
    builder.when_last_row().assert_eq(v, TWO_POW_16_MINUS_1);
}

/// Enforces the transition constraint for the range checker V column.
///
/// The V column must change by one of: {0, 1, 3, 9, 27, 81, 243, 729, 2187}
/// - 0 allows V to stay constant during padding rows
/// - Others are powers of 3: {3^0, 3^1, 3^2, 3^3, 3^4, 3^5, 3^6, 3^7}
///
/// This is a degree-9 constraint.
pub fn enforce_range_transition_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let v = local.range[RANGE_V_COL_IDX];
    let v_next = next.range[RANGE_V_COL_IDX];
    let change_v = v_next - v;

    // Powers of 3: {1, 3, 9, 27, 81, 243, 729, 2187}
    // Note: Extra factor of change_v allows V to stay constant (change_v = 0) during padding
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
