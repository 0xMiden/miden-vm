//! Range Checker Constraints
//!
//! This module contains constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//! - Bus constraint: LogUp multiset check for range check requests

pub mod bus;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

/// Enforces boundary constraints for the range checker.
///
/// - First row: V[0] = 0 (range checker starts at 0)
/// - Last row: V[last] = 65535 (range checker ends at 2^16 - 1)
pub fn enforce_main_range_constraints<AB>(
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
fn enforce_range_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // First row: V[0] = 0
    builder.when_first_row().assert_zero(local.range[1].clone());

    // Last row: V[last] = 65535 (2^16 - 1)
    let sixty_five_k = AB::Expr::from_u32(65535);
    builder.when_last_row().assert_eq(local.range[1].clone(), sixty_five_k);
}

/// Enforces the transition constraint for the range checker V column.
///
/// The V column must change by one of: {0, 1, 3, 9, 27, 81, 243, 729, 2187}
/// - 0 allows V to stay constant during padding rows
/// - Others are powers of 3: {3^0, 3^1, 3^2, 3^3, 3^4, 3^5, 3^6, 3^7}
///
/// This is a degree-9 constraint.
fn enforce_range_transition_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let change_v = next.range[1].clone() - local.range[1].clone();

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
    builder.when_transition().assert_zero(
        change_v.clone()
            * (change_v.clone() - one_expr)
            * (change_v.clone() - three)
            * (change_v.clone() - nine)
            * (change_v.clone() - twenty_seven)
            * (change_v.clone() - eighty_one)
            * (change_v.clone() - two_forty_three)
            * (change_v.clone() - seven_twenty_nine)
            * (change_v.clone() - two_one_eight_seven),
    );
}
