//! Hasher chiplet periodic columns.
//!
//! This module defines the periodic columns used by the Poseidon2 hasher chiplet.
//! The hasher operates on a 32-row cycle, and periodic columns provide cycle-position
//! markers and round constants.
//!
//! ## Column Layout
//!
//! | Index | Name           | Description |
//! |-------|----------------|-------------|
//! | 0     | cycle_row_0    | 1 on first row of cycle, 0 elsewhere |
//! | 1     | cycle_row_30   | 1 on penultimate row (lookahead for output) |
//! | 2     | cycle_row_31   | 1 on final row (boundary/output row) |
//! | 3     | p2_is_external | 1 on external round rows (1-4, 27-30) |
//! | 4     | p2_is_internal | 1 on internal round rows (5-26) |
//! | 5-16  | ark_ext[0..12] | External round constants per lane |
//! | 17    | ark_int        | Internal round constant (lane 0 only) |

use alloc::vec::Vec;

use miden_core::chiplets::hasher::Hasher;

use crate::Felt;

// CONSTANTS
// ================================================================================================

/// Length of one hash cycle.
pub const HASH_CYCLE_LEN: usize = 32;

/// Width of the hasher state.
pub const STATE_WIDTH: usize = 12;

// Periodic column indices.
pub const P_CYCLE_ROW_0: usize = 0;
pub const P_CYCLE_ROW_30: usize = 1;
pub const P_CYCLE_ROW_31: usize = 2;
pub const P_IS_EXTERNAL: usize = 3;
pub const P_IS_INTERNAL: usize = 4;
pub const P_ARK_EXT_START: usize = 5;
pub const P_ARK_INT: usize = P_ARK_EXT_START + STATE_WIDTH;

/// Total number of periodic columns for the hasher chiplet.
pub const NUM_PERIODIC_COLUMNS: usize = P_ARK_INT + 1;

// INTERNAL HELPERS
// ================================================================================================

/// Returns periodic columns for the Poseidon2 hasher chiplet.
///
/// ## Layout
///
/// All columns repeat every 32 rows, matching one permutation cycle:
///
/// - **Cycle markers** (`cycle_row_0`, `cycle_row_30`, `cycle_row_31`): Single-one markers for the
///   first row, penultimate row, and final row of a cycle. Row 31 is the boundary/output row where
///   we do **not** enforce a step transition.
///
/// - **Step selectors** (`p2_is_external`, `p2_is_internal`): Mutually exclusive step selectors:
///   - Rows 1-4 and 27-30 are external rounds (full S-box on all lanes + M_E).
///   - Rows 5-26 are internal rounds (add RC to lane 0, S-box lane 0 only, then M_I).
///   - Row 0 is the initial "linear" step (M_E only) and row 31 is no-op; both selectors are 0.
///
/// - **External round constants** (`ark_ext_0..11`): Lane-indexed constants, non-zero only on
///   external-round rows (1-4 = initial; 27-30 = terminal).
///
/// - **Internal round constant** (`ark_int`): Constant for lane 0 only, non-zero on internal rows
///   5-26.
#[allow(clippy::needless_range_loop)]
pub fn periodic_columns() -> Vec<Vec<Felt>> {
    let mut cols: Vec<Vec<Felt>> = Vec::with_capacity(NUM_PERIODIC_COLUMNS);

    // -------------------------------------------------------------------------
    // Cycle markers
    // -------------------------------------------------------------------------
    let mut row0 = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut row30 = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut row31 = vec![Felt::ZERO; HASH_CYCLE_LEN];
    row0[0] = Felt::ONE;
    row30[30] = Felt::ONE;
    row31[31] = Felt::ONE;
    cols.push(row0);
    cols.push(row30);
    cols.push(row31);

    // -------------------------------------------------------------------------
    // Step-type selectors
    // -------------------------------------------------------------------------
    let mut p2_is_external = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut p2_is_internal = vec![Felt::ZERO; HASH_CYCLE_LEN];

    // External rounds: rows 1-4 (initial) and 27-30 (terminal)
    for r in 1..=4 {
        p2_is_external[r] = Felt::ONE;
    }
    for r in 27..=30 {
        p2_is_external[r] = Felt::ONE;
    }

    // Internal rounds: rows 5-26
    for r in 5..=26 {
        p2_is_internal[r] = Felt::ONE;
    }

    cols.push(p2_is_external);
    cols.push(p2_is_internal);

    // -------------------------------------------------------------------------
    // External round constants (12 lanes)
    // -------------------------------------------------------------------------
    for lane in 0..STATE_WIDTH {
        let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];
        // Initial external rounds: rows 1-4
        for r in 1..=4 {
            col[r] = Hasher::ARK_EXT_INITIAL[r - 1][lane];
        }
        // Terminal external rounds: rows 27-30
        for r in 27..=30 {
            col[r] = Hasher::ARK_EXT_TERMINAL[r - 27][lane];
        }
        cols.push(col);
    }

    // -------------------------------------------------------------------------
    // Internal round constant (lane 0 only)
    // -------------------------------------------------------------------------
    let mut ark_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
    ark_int[5..=26].copy_from_slice(&Hasher::ARK_INT);
    cols.push(ark_int);

    cols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_dimensions() {
        let cols = periodic_columns();
        assert_eq!(cols.len(), NUM_PERIODIC_COLUMNS);
        for col in &cols {
            assert_eq!(col.len(), HASH_CYCLE_LEN);
        }
    }

    #[test]
    fn cycle_markers_are_exclusive() {
        let cols = periodic_columns();
        for (row_idx, ((row0, row30), row31)) in cols[P_CYCLE_ROW_0]
            .iter()
            .zip(&cols[P_CYCLE_ROW_30])
            .zip(&cols[P_CYCLE_ROW_31])
            .enumerate()
        {
            // Booleanity checks
            assert_eq!(*row0 * (*row0 - Felt::ONE), Felt::ZERO);
            assert_eq!(*row30 * (*row30 - Felt::ONE), Felt::ZERO);
            assert_eq!(*row31 * (*row31 - Felt::ONE), Felt::ZERO);

            // Mutual exclusivity (XOR when boolean)
            assert_eq!(*row0 * *row30, Felt::ZERO);
            assert_eq!(*row0 * *row31, Felt::ZERO);
            assert_eq!(*row30 * *row31, Felt::ZERO);

            // Exactness: only the designated rows are 1.
            let expected = match row_idx {
                0 | 30 | 31 => Felt::ONE,
                _ => Felt::ZERO,
            };
            assert_eq!(*row0 + *row30 + *row31, expected);
        }
    }

    #[test]
    fn step_selectors_are_exclusive() {
        let cols = periodic_columns();
        for (row_idx, (is_ext, is_int)) in
            cols[P_IS_EXTERNAL].iter().zip(&cols[P_IS_INTERNAL]).enumerate()
        {
            // Booleanity checks
            assert_eq!(*is_ext * (*is_ext - Felt::ONE), Felt::ZERO);
            assert_eq!(*is_int * (*is_int - Felt::ONE), Felt::ZERO);

            // Mutual exclusivity (XOR when boolean)
            assert_eq!(*is_ext * *is_int, Felt::ZERO);

            // Exactness per row
            let expected = match row_idx {
                1..=4 | 27..=30 => (Felt::ONE, Felt::ZERO),
                5..=26 => (Felt::ZERO, Felt::ONE),
                _ => (Felt::ZERO, Felt::ZERO),
            };
            assert_eq!((*is_ext, *is_int), expected);
        }
    }
}
