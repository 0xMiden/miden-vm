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
    builder.when_first_row().assert_zero(local.range[1].clone().into());
    builder.when_last_row().assert_zero(local.range[1].clone().into() - AB::Expr::from_u64(65535));
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
    builder.when_transition().assert_zero((next.range[1].clone().into() - local.range[1].clone().into()) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::ONE) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(3)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(9)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(27)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(81)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(243)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(729)) * (next.range[1].clone().into() - local.range[1].clone().into() - AB::Expr::from_u64(2187)));
}
