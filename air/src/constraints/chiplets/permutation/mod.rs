//! Permutation sub-chiplet constraints.
//!
//! The permutation sub-chiplet executes Poseidon2 permutations as 16-row cycles.
//! It is active when `s_perm = 1` (the permutation segment selector).
//!
//! ## Sub-modules
//!
//! - [`state`]: Poseidon2 round transition constraints
//!
//! ## Column Layout (via [`PermutationCols`])
//!
//! | Column       | Purpose |
//! |--------------|---------|
//! | w0, w1, w2   | S-box witnesses (same physical columns as hasher selectors) |
//! | h[0..12)     | Poseidon2 state (RATE0, RATE1, CAP) |
//! | multiplicity | Request multiplicity (same physical column as node_index) |
//! | s_perm       | Permutation segment selector (consumed by chiplet selectors) |

pub mod state;

use core::borrow::Borrow;

use miden_crypto::stark::air::AirBuilder;

use crate::{
    MainCols, MidenAirBuilder,
    constraints::chiplets::{
        columns::{HasherPeriodicCols, PeriodicCols},
        selectors::ChipletFlags,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce all permutation sub-chiplet constraints.
///
/// Receives pre-computed [`ChipletFlags`] from `build_chiplet_selectors`. The `s_perm`
/// column is never referenced directly by constraint code.
pub fn enforce_permutation_constraints<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let periodic_hasher: HasherPeriodicCols<AB::PeriodicVar> = {
        let periodic: &PeriodicCols<AB::PeriodicVar> = builder.periodic_values().borrow();
        periodic.hasher
    };

    let cols = local.permutation();
    let cols_next = next.permutation();

    // not_cycle_end: 1 on perm-cycle rows 0-14, 0 on the cycle boundary row 15.
    let not_cycle_end: AB::Expr = [
        periodic_hasher.is_init_ext,
        periodic_hasher.is_ext,
        periodic_hasher.is_packed_int,
        periodic_hasher.is_int_ext,
    ]
    .map(Into::into)
    .into_iter()
    .sum();

    // --- Poseidon2 permutation step constraints ---
    // Gate by is_active (= s_perm, degree 1) alone. This is sound because
    // the tri-state selector constraints confine s_perm to hasher rows.
    // Keeping the gate at degree 1 is critical: the S-box has degree 7, and
    // with the periodic selector (degree 1), the total constraint degree is
    // 1 + 1 + 7 = 9, which matches the system's max degree.
    state::enforce_permutation_steps(
        builder,
        flags.is_active.clone(),
        cols,
        cols_next,
        &periodic_hasher,
    );

    // --- Structural confinement on perm rows ---
    // is_boundary, direction_bit, and mrupdate_id are unused on permutation rows
    // and must be zero to avoid accidental coupling with controller-side logic.
    builder.when(flags.is_active.clone()).assert_zeros(cols.unused_padding());

    // --- Multiplicity constancy within perm cycles ---
    // On perm rows that are NOT the cycle boundary (row 15), multiplicity must stay
    // constant. This ensures each 16-row cycle has a single multiplicity value.
    // Degree: is_active(1) * not_cycle_end(1) * diff(1) = 3.
    builder
        .when(flags.is_active.clone())
        .when(not_cycle_end.clone())
        .assert_eq(cols_next.multiplicity, cols.multiplicity);

    // --- Cycle boundary alignment ---
    // The permutation section must be aligned to the 16-row Poseidon2 cycle: the
    // first perm row must land on cycle row 0 and the last on cycle row 15.
    // Together these guarantee every permutation spans exactly one complete cycle,
    // so the periodic column selectors assign the correct round type to each row.
    //
    // Entry alignment: the row before the first perm row (= last controller row)
    // must be on cycle row 15. `flags.next_is_first` = `ctrl.is_last * s_perm'`,
    // which equals `ctrl.is_last` because the transition rules force `s_perm' = 1`
    // when `ctrl.is_last` fires.
    // Degree: next_is_first(3) * not_cycle_end(1) = 4.
    builder.when(flags.next_is_first.clone()).assert_zero(not_cycle_end.clone());

    // Exit safety: the last permutation row must be on cycle row 15.
    // This prevents cross-chiplet next-row reads from firing under perm gates.
    // Degree: is_last(2) * not_cycle_end(1) = 3.
    builder.when(flags.is_last.clone()).assert_zero(not_cycle_end);
}
