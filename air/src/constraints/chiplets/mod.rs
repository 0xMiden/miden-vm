mod ace;
mod bitwise;
mod hasher;
mod kernel_rom;
mod memory;
mod bus;

use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_chiplets_constraints<AB>(
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
    bus::enforce_chiplets_bus_constraint(builder, local);
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
    builder.assert_zero(local.chiplets[0].clone() * local.chiplets[0].clone() - local.chiplets[0].clone());
    builder.assert_zero(local.chiplets[0].clone() * (local.chiplets[1].clone() * local.chiplets[1].clone() - local.chiplets[1].clone()));
    builder.assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * (local.chiplets[2].clone() * local.chiplets[2].clone() - local.chiplets[2].clone()));
    builder.assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * local.chiplets[2].clone() * (local.chiplets[3].clone() * local.chiplets[3].clone() - local.chiplets[3].clone()));
    builder.assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * local.chiplets[2].clone() * local.chiplets[3].clone() * (local.chiplets[4].clone() * local.chiplets[4].clone() - local.chiplets[4].clone()));
    builder.when_transition().assert_zero(local.chiplets[0].clone() * (next.chiplets[0].clone() - local.chiplets[0].clone()));
    builder.when_transition().assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * (next.chiplets[1].clone() - local.chiplets[1].clone()));
    builder.when_transition().assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * local.chiplets[2].clone() * (next.chiplets[2].clone() - local.chiplets[2].clone()));
    builder.when_transition().assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * local.chiplets[2].clone() * local.chiplets[3].clone() * (next.chiplets[3].clone() - local.chiplets[3].clone()));
    builder.when_transition().assert_zero(local.chiplets[0].clone() * local.chiplets[1].clone() * local.chiplets[2].clone() * local.chiplets[3].clone() * local.chiplets[4].clone() * (next.chiplets[4].clone() - local.chiplets[4].clone()));
}
