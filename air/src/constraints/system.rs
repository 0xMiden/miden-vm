use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_main_system_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_system_boundary_constraints(builder, local);
    enforce_clock_constraints(builder, local, next);
    enforce_execution_context_constraints(builder, local, next);
    enforce_function_hash_constraints(builder, local, next);
}

fn enforce_system_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    builder.when_first_row().assert_zero(local.clk.clone().into());
}

/// Enforces the clock constraint: clk' = clk + 1
///
/// The clock must increment by 1 at each step, ensuring proper sequencing of operations.
fn enforce_clock_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.when_transition().assert_zero(next.clk.clone().into() - (local.clk.clone().into() + AB::Expr::ONE));
}

fn enforce_execution_context_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
        builder.when_transition().assert_zero((local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into())) * (next.fn_hash[0].clone().into() - (local.clk.clone().into() + AB::Expr::ONE)));
        builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.fn_hash[0].clone().into());
        builder.when_transition().assert_zero((AB::Expr::ONE - (local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()))) * (next.fn_hash[0].clone().into() - local.fn_hash[0].clone().into()));
        
}

fn enforce_function_hash_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
        builder.when_transition().assert_zero((local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into())) * (next.fn_hash[2].clone().into() - local.decoder[8].clone().into()));
        builder.when_transition().assert_zero((local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into())) * (next.fn_hash[3].clone().into() - local.decoder[9].clone().into()));
        builder.when_transition().assert_zero((local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into())) * (next.fn_hash[2].clone().into() - local.decoder[10].clone().into()));
        builder.when_transition().assert_zero((local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into())) * (next.fn_hash[3].clone().into() - local.decoder[11].clone().into()));
        builder.when_transition().assert_zero((AB::Expr::ONE - (local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()))) * (next.fn_hash[2].clone().into() - local.fn_hash[2].clone().into()));
        builder.when_transition().assert_zero((AB::Expr::ONE - (local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()))) * (next.fn_hash[3].clone().into() - local.fn_hash[3].clone().into()));
        builder.when_transition().assert_zero((AB::Expr::ONE - (local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()))) * (next.fn_hash[2].clone().into() - local.fn_hash[2].clone().into()));
        builder.when_transition().assert_zero((AB::Expr::ONE - (local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()))) * (next.fn_hash[3].clone().into() - local.fn_hash[3].clone().into()));

}
