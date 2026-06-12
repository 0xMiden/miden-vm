//! Standalone Poseidon2 permutation AIR constraints.

use core::borrow::Borrow;

use miden_crypto::stark::air::{AirBuilder, WindowAccess};

use crate::{
    MidenAirBuilder,
    constraints::poseidon2_permutation::columns::{
        Poseidon2PermutationCols, Poseidon2PermutationPeriodicCols,
    },
};

pub mod columns;
pub mod state;

/// Enforce Poseidon2 permutation trace constraints.
pub fn enforce_main<AB>(builder: &mut AB)
where
    AB: MidenAirBuilder,
{
    let main = builder.main();
    let local: &Poseidon2PermutationCols<AB::Var> = (*main.current_slice()).borrow();
    let next: &Poseidon2PermutationCols<AB::Var> = (*main.next_slice()).borrow();
    let periodic: Poseidon2PermutationPeriodicCols<AB::PeriodicVar> =
        *builder.periodic_values().borrow();

    let not_cycle_end: AB::Expr = periodic.not_cycle_end();

    state::enforce_permutation_steps(builder, local, next, &periodic);

    // Multiplicity is constant within each 16-row cycle. Padding cycles use
    // multiplicity zero, so they are valid cycles but invisible to the perm-link bus.
    builder.when(not_cycle_end).assert_eq(next.multiplicity, local.multiplicity);
}
