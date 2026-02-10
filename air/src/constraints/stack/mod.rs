pub mod bus;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_main_stack_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_stack_boundary_constraints(builder, local);
    enforce_stack_general_constraints(builder, local, next);
    enforce_stack_operation_constraints(builder, local, next);
}

fn enforce_stack_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: add stack boundary constraints
}

pub fn enforce_stack_general_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_stack_overflow_flag_constraints(builder, local, next);
    enforce_stack_depth_constraints(builder, local, next);
    enforce_right_shift_b1_constraint(builder, local, next);
    enforce_left_shift_zero_insertion(builder, local, next);
}

pub fn enforce_stack_overflow_flag_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add stack overflow flag constraints
}

pub fn enforce_stack_depth_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add stack depth constraints
}

pub fn enforce_right_shift_b1_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add right shift b1 constraints
}

pub fn enforce_left_shift_zero_insertion<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add left shift zero insertion constraints
}

pub fn enforce_stack_operation_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add stack operation constraints
}
