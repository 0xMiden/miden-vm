pub mod bus;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_main_decoder_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_decoder_boundary_constraints(builder, local);
    enforce_general_constraints(builder, local, next);
    enforce_basic_block_constraints(builder, local, next);
    enforce_op_flags_bits_constraints(builder, local, next);
}

fn enforce_decoder_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add decoder boundary constraints
}

fn enforce_general_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add general constraints
}

fn enforce_basic_block_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add basic block constraints
}

fn enforce_op_batch_flags_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add op batch flags constraints
}

fn enforce_op_flags_bits_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_u32_bit_constraints(builder, local, next);
    enforce_high_degree_bit_constraints(builder, local, next);
    enforce_very_high_degree_bit_constraints(builder, local, next);
}

fn enforce_u32_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add u32 bit constraints
}

fn enforce_high_degree_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add high degree bit constraints
}

fn enforce_very_high_degree_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add very high degree bit constraints
}
