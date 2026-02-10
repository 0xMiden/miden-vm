use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_decoder_bus_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    enforce_block_stack_table_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next);
    enforce_block_hash_table_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next);
    enforce_op_group_table_constraints(builder, alpha, beta_challenges, aux_current, aux_next, local, next);
}

pub fn enforce_block_stack_table_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add block stack table constraint
}

pub fn enforce_block_hash_table_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add block hash table constraint
}

pub fn enforce_op_group_table_constraints<AB>(builder: &mut AB, alpha: AB::RandomVar, beta_challenges: &[AB::RandomVar], aux_current: &[AB::VarEF], aux_next: &[AB::VarEF], local: &MainTraceRow<AB::Var>, next: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add op group table constraint
}
