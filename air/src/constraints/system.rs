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
    builder
        .when_transition()
        .assert_zero(next.clk.clone().into() - (local.clk.clone().into() + AB::Expr::ONE));
}

fn enforce_execution_context_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add execution context constraints
}

fn enforce_function_hash_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add function hash constraints
}
