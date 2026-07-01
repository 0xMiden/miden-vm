//! Poseidon2 permutation AIR constraints.
//!
//! Every row belongs to a 16-row permutation cycle. Rows 0..=14 enforce state transitions,
//! row 15 holds the cycle output, and the perm-link lookup argument binds rows 0 and 15
//! to the hasher controller.

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

    // Multiplicity is constant within each 16-row cycle. Padding cycles use multiplicity 0,
    // so they satisfy the permutation AIR but contribute nothing to LogUp.
    builder.when(not_cycle_end).assert_eq(next.multiplicity, local.multiplicity);
}
