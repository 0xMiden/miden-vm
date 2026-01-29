use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_stack_bus_constraints<AB>(_builder: &mut AB, _local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // TODO: Add constraints
}
