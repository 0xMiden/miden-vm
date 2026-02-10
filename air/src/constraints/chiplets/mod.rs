mod ace;
pub mod bitwise;
pub mod hasher;
mod kernel_rom;
mod memory;
pub mod bus;
pub mod periodic_columns;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_main_chiplets_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    enforce_chiplets_transition_constraint(
        builder,
        local,
        next,
        periodic_values,
    );
}

fn enforce_chiplets_transition_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    periodic_values: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder,
{
    enforce_chiplets_selector_constraint(builder, local, next);

    ace::enforce_ace_chiplet_constraints(builder, local, next);
    bitwise::enforce_bitwise_chiplet_constraints(builder, local, next, periodic_values);
    hasher::enforce_hasher_chiplet_constraints(builder, local, next, periodic_values);
    kernel_rom::enforce_kernel_rom_chiplet_constraints(builder, local, next);
    memory::enforce_memory_chiplet_constraints(builder, local, next);
}

fn enforce_chiplets_selector_constraint<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    // TODO: add chiplets selector constraints
}
