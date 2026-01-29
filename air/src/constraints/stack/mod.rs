pub mod bus;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_main_stack_constraints<AB>(
    _builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: Add constraints
}
