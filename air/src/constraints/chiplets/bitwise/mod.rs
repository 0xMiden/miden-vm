use alloc::vec::Vec;

use miden_core::{Felt, ONE, ZERO, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

// --- Periodic columns ---------------------------------------------------------------------------

/// Flag for the first row of each cycle in the periodic column.
pub const CYCLE_ROW_0: [Felt; 8] = [ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

/// Negative flag for the last row of each cycle in the periodic column.
pub const INV_CYCLE_ROW_7: [Felt; 8] = [ONE, ONE, ONE, ONE, ONE, ONE, ONE, ZERO];

/// The number of periodic columns used in the Bitwise chiplet AIR.
pub const NUM_BITWISE_PERIODIC_VALUES: usize = 2;

/// Returns the periodic columns used in the Bitwise chiplet AIR.
pub fn bitwise_periodic_columns() -> Vec<Vec<Felt>> {
    vec![CYCLE_ROW_0.to_vec(), INV_CYCLE_ROW_7.to_vec()]
}

pub fn enforce_bitwise_chiplet_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[2].clone().into() * local.chiplets[2].clone().into() - local.chiplets[2].clone().into()));
    builder.when_transition().assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::from(next.chiplets[2].clone().into()) - AB::ExprEF::from(local.chiplets[2].clone().into())));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[5].clone().into() * local.chiplets[5].clone().into() - local.chiplets[5].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[6].clone().into() * local.chiplets[6].clone().into() - local.chiplets[6].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[7].clone().into() * local.chiplets[7].clone().into() - local.chiplets[7].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[8].clone().into() * local.chiplets[8].clone().into() - local.chiplets[8].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[9].clone().into() * local.chiplets[9].clone().into() - local.chiplets[9].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[10].clone().into() * local.chiplets[10].clone().into() - local.chiplets[10].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[11].clone().into() * local.chiplets[11].clone().into() - local.chiplets[11].clone().into()));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[12].clone().into() * local.chiplets[12].clone().into() - local.chiplets[12].clone().into()));
    builder.assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[0].clone().into()) * (AB::ExprEF::from(local.chiplets[3].clone().into()) - (AB::ExprEF::from(local.chiplets[5].clone().into()) + AB::ExprEF::from(local.chiplets[6].clone().into()).double() + AB::ExprEF::from_u64(4) * AB::ExprEF::from(local.chiplets[7].clone().into()) + AB::ExprEF::from_u64(8) * AB::ExprEF::from(local.chiplets[8].clone().into()))));
    builder.assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[0].clone().into()) * (AB::ExprEF::from(local.chiplets[4].clone().into()) - (AB::ExprEF::from(local.chiplets[9].clone().into()) + AB::ExprEF::from(local.chiplets[10].clone().into()).double() + AB::ExprEF::from_u64(4) * AB::ExprEF::from(local.chiplets[11].clone().into()) + AB::ExprEF::from_u64(8) * AB::ExprEF::from(local.chiplets[12].clone().into()))));
    builder.when_transition().assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::from(next.chiplets[3].clone().into()) - (AB::ExprEF::from(local.chiplets[3].clone().into()) * AB::ExprEF::from_u64(16) + AB::ExprEF::from(local.chiplets[5].clone().into()) + AB::ExprEF::from(local.chiplets[6].clone().into()).double() + AB::ExprEF::from_u64(4) * AB::ExprEF::from(local.chiplets[7].clone().into()) + AB::ExprEF::from_u64(8) * AB::ExprEF::from(local.chiplets[8].clone().into()))));
    builder.when_transition().assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::from(next.chiplets[4].clone().into()) - (AB::ExprEF::from(local.chiplets[4].clone().into()) * AB::ExprEF::from_u64(16) + AB::ExprEF::from(local.chiplets[9].clone().into()) + AB::ExprEF::from(local.chiplets[10].clone().into()).double() + AB::ExprEF::from_u64(4) * AB::ExprEF::from(local.chiplets[11].clone().into()) + AB::ExprEF::from_u64(8) * AB::ExprEF::from(local.chiplets[12].clone().into()))));
    builder.assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[0].clone().into()) * AB::ExprEF::from(local.chiplets[13].clone().into()));
    builder.when_transition().assert_zero_ext(AB::ExprEF::from(local.chiplets[0].clone().into()) * (AB::ExprEF::ONE - AB::ExprEF::from(local.chiplets[1].clone().into())) * AB::ExprEF::from(periodic_values[1].clone().into()) * (AB::ExprEF::from(next.chiplets[13].clone().into()) - AB::ExprEF::from(local.chiplets[14].clone().into())));
    builder.assert_zero(local.chiplets[0].clone().into() * (AB::Expr::ONE - local.chiplets[1].clone().into()) * (local.chiplets[14].clone().into() - (local.chiplets[13].clone().into() * AB::Expr::from_u64(16) + local.chiplets[2].clone().into() * (local.chiplets[5].clone().into() + local.chiplets[9].clone().into() - (local.chiplets[5].clone().into() * local.chiplets[9].clone().into() + local.chiplets[5].clone().into() * local.chiplets[9].clone().into()) + (local.chiplets[6].clone().into() + local.chiplets[10].clone().into() - (local.chiplets[6].clone().into() * local.chiplets[10].clone().into() + local.chiplets[6].clone().into() * local.chiplets[10].clone().into())).double() + AB::Expr::from_u64(4) * (local.chiplets[7].clone().into() + local.chiplets[11].clone().into() - (local.chiplets[7].clone().into() * local.chiplets[11].clone().into() + local.chiplets[7].clone().into() * local.chiplets[11].clone().into())) + AB::Expr::from_u64(8) * (local.chiplets[8].clone().into() + local.chiplets[12].clone().into() - (local.chiplets[8].clone().into() * local.chiplets[12].clone().into() + local.chiplets[8].clone().into() * local.chiplets[12].clone().into())) - (local.chiplets[5].clone().into() * local.chiplets[9].clone().into() + local.chiplets[6].clone().into() * local.chiplets[10].clone().into() + local.chiplets[6].clone().into() * local.chiplets[10].clone().into() + AB::Expr::from_u64(4) * local.chiplets[7].clone().into() * local.chiplets[11].clone().into() + AB::Expr::from_u64(8) * local.chiplets[8].clone().into() * local.chiplets[12].clone().into())) + local.chiplets[5].clone().into() * local.chiplets[9].clone().into() + local.chiplets[6].clone().into() * local.chiplets[10].clone().into() + local.chiplets[6].clone().into() * local.chiplets[10].clone().into() + AB::Expr::from_u64(4) * local.chiplets[7].clone().into() * local.chiplets[11].clone().into() + AB::Expr::from_u64(8) * local.chiplets[8].clone().into() * local.chiplets[12].clone().into())));
}
