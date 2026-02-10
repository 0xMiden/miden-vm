use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::trace::MainTraceRow;

pub fn enforce_ace_wiring_bus_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add ACE bus constraint
}
