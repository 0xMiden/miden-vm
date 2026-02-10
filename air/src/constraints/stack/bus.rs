use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_stack_bus_constraints<AB>(
    builder: &mut AB,
    alpha: AB::RandomVar,
    beta_challenges: &[AB::RandomVar],
    aux_current: &[AB::VarEF],
    aux_next: &[AB::VarEF],
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    enforce_stack_overflow_bus_constraints(
        builder,
        alpha,
        beta_challenges,
        aux_current,
        aux_next,
        local,
        next,
        periodic_values,
    );
}

pub fn enforce_stack_overflow_bus_constraints<AB>(
    builder: &mut AB,
    alpha: AB::RandomVar,
    beta_challenges: &[AB::RandomVar],
    aux_current: &[AB::VarEF],
    aux_next: &[AB::VarEF],
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    // TODO: add stack overflow bus constraint
}
