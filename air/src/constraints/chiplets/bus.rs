use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_chiplets_bus_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>, periodic_values: &[AB::PeriodicVal])
where
    AB: MidenAirBuilder,
{
    enforce_chiplets_virtual_table_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next, periodic_values);
    enforce_chiplets_communication_bus_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next, periodic_values);
    super::ace::bus::enforce_ace_wiring_bus_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next);
}

pub fn enforce_chiplets_virtual_table_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>, periodic_values: &[AB::PeriodicVal])
where
    AB: MidenAirBuilder,
{
    // TODO: add chiplets virtual table constraint
}

pub fn enforce_chiplets_communication_bus_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>, periodic_values: &[AB::PeriodicVal])
where
    AB: MidenAirBuilder,
{
    // TODO: add chiplets communication bus constraint
}
