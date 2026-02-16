//! Range Checker Main Trace Constraints
//!
//! This module contains main trace constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//!
//! Bus constraints for the range checker are in `bus`.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::{
    MainTraceRow,
    constraints::tagging::TaggingAirBuilderExt,
    trace::{RANGE_CHECK_TRACE_OFFSET, range},
};

pub mod bus;

// CONSTANTS
// ================================================================================================

// --- SLICE-RELATIVE INDICES ---------------------------------------------------------------------
const RANGE_V_COL_IDX: usize = range::V_COL_IDX - RANGE_CHECK_TRACE_OFFSET;

// TAGGING CONSTANTS
// ================================================================================================

const RANGE_MAIN_BASE_ID: usize = 13;
const RANGE_MAIN_NAMES: [&str; 3] =
    ["range.main.v.first_row", "range.main.v.last_row", "range.main.v.transition"];

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
    let v = local.range[RANGE_V_COL_IDX].clone();

    // First row: V[0] = 0
    builder.tagged(RANGE_MAIN_BASE_ID, RANGE_MAIN_NAMES[0], |builder| {
        builder.when_first_row().assert_zero(v.clone());
    });

    // Last row: V[last] = 65535 (2^16 - 1)
    let sixty_five_k = AB::Expr::from_u32(65535);
    builder.tagged(RANGE_MAIN_BASE_ID + 1, RANGE_MAIN_NAMES[1], |builder| {
        builder.when_last_row().assert_eq(v, sixty_five_k);
    });
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
    let v = local.range[RANGE_V_COL_IDX].clone();
    let v_next = next.range[RANGE_V_COL_IDX].clone();
    let change_v = v_next - v;

    // Powers of 3: {1, 3, 9, 27, 81, 243, 729, 2187}
    let one_expr = AB::Expr::ONE;
    let three = AB::Expr::from_u16(3);
    let nine = AB::Expr::from_u16(9);
    let twenty_seven = AB::Expr::from_u16(27);
    let eighty_one = AB::Expr::from_u16(81);
    let two_forty_three = AB::Expr::from_u16(243);
    let seven_twenty_nine = AB::Expr::from_u16(729);
    let two_one_eight_seven = AB::Expr::from_u16(2187);

    // Note: Extra factor of change_v allows V to stay constant (change_v = 0) during padding
    builder.tagged(RANGE_MAIN_BASE_ID + 2, RANGE_MAIN_NAMES[2], |builder| {
        builder.when_transition().assert_zero(
            change_v.clone()
                * (change_v.clone() - one_expr)
                * (change_v.clone() - three)
                * (change_v.clone() - nine)
                * (change_v.clone() - twenty_seven)
                * (change_v.clone() - eighty_one)
                * (change_v.clone() - two_forty_three)
                * (change_v.clone() - seven_twenty_nine)
                * (change_v - two_one_eight_seven),
        );
    });
}
