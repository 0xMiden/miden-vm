use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_chiplets_bus_constraints<AB>(_builder: &mut AB, _local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{

}
