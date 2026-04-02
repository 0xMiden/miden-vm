//! Periodic column structs for chiplet constraints.
//!
//! Periodic columns repeat on a fixed cycle and provide cycle-position markers and
//! round constants to chiplet constraint code. This module defines `#[repr(C)]` structs
//! with a [`Borrow`] impl on `[T]`, so callers can write
//! `builder.periodic_values().borrow()` to get a typed `&PeriodicCols<_>`.
//!
//! ## Column Layout
//!
//! | Index | Chiplet  | Field                          |
//! |-------|----------|--------------------------------|
//! | 0     | Hasher   | cycle_row_0                    |
//! | 1     | Hasher   | cycle_row_30                   |
//! | 2     | Hasher   | cycle_row_31                   |
//! | 3     | Hasher   | is_external                    |
//! | 4     | Hasher   | is_internal                    |
//! | 5-16  | Hasher   | ark_ext[0..12]                 |
//! | 17    | Hasher   | ark_int                        |
//! | 18    | Bitwise  | k_first                        |
//! | 19    | Bitwise  | k_transition                   |

use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, mem::size_of};

use miden_core::chiplets::hasher::Hasher;

use super::{
    Felt,
    hasher::{HASH_CYCLE_LEN, STATE_WIDTH},
};

// COLUMN STRUCTS
// ================================================================================================

/// All chiplet periodic columns (20 columns).
///
/// Aggregates hasher (18 columns) and bitwise (2 columns) periodic values into a single
/// typed view. Use `builder.periodic_values().borrow()` to obtain a `&PeriodicCols<_>`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PeriodicCols<T> {
    /// Hasher periodic columns (cycle markers, step selectors, round constants).
    pub hasher: HasherPeriodicCols<T>,
    /// Bitwise periodic columns.
    pub bitwise: BitwisePeriodicCols<T>,
}

/// Hasher chiplet periodic columns (18 columns, period = 32 rows).
///
/// Provides cycle-position markers, step-type selectors, and Poseidon2 round constants
/// for the hasher chiplet.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HasherPeriodicCols<T> {
    /// 1 on first row of 32-row cycle, 0 elsewhere.
    pub cycle_row_0: T,
    /// 1 on penultimate row (lookahead for output).
    pub cycle_row_30: T,
    /// 1 on final row (boundary/output row).
    pub cycle_row_31: T,
    /// 1 on external round rows (1-4, 27-30).
    pub is_external: T,
    /// 1 on internal round rows (5-26).
    pub is_internal: T,
    /// External round constants per lane (12 lanes), non-zero on external-round rows.
    pub ark_ext: [T; STATE_WIDTH],
    /// Internal round constant (lane 0 only), non-zero on internal-round rows (5-26).
    pub ark_int: T,
}

/// Bitwise chiplet periodic columns (2 columns, period = 8 rows).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BitwisePeriodicCols<T> {
    /// Marks first row of 8-row cycle: `[1, 0, 0, 0, 0, 0, 0, 0]`.
    pub k_first: T,
    /// Marks non-last rows of 8-row cycle: `[1, 1, 1, 1, 1, 1, 1, 0]`.
    pub k_transition: T,
}

// PERIODIC COLUMN GENERATION
// ================================================================================================

#[allow(clippy::new_without_default)]
impl HasherPeriodicCols<Vec<Felt>> {
    /// Generate periodic columns for the Poseidon2 hasher chiplet.
    ///
    /// All columns repeat every 32 rows, matching one permutation cycle:
    ///
    /// - **Cycle markers** (`cycle_row_0`, `cycle_row_30`, `cycle_row_31`): Single-one markers for
    ///   the first row, penultimate row, and final row of a cycle. Row 31 is the boundary/output
    ///   row where we do **not** enforce a step transition.
    ///
    /// - **Step selectors** (`is_external`, `is_internal`): Mutually exclusive step selectors:
    ///   - Rows 1-4 and 27-30 are external rounds (full S-box on all lanes + M_E).
    ///   - Rows 5-26 are internal rounds (add RC to lane 0, S-box lane 0 only, then M_I).
    ///   - Row 0 is the initial "linear" step (M_E only) and row 31 is no-op; both selectors are 0.
    ///
    /// - **External round constants** (`ark_ext[0..12]`): Lane-indexed constants, non-zero only on
    ///   external-round rows (1-4 = initial; 27-30 = terminal).
    ///
    /// - **Internal round constant** (`ark_int`): Constant for lane 0 only, non-zero on internal
    ///   rows 5-26.
    #[allow(clippy::needless_range_loop)]
    pub fn new() -> Self {
        // Cycle markers
        let mut cycle_row_0 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut cycle_row_30 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut cycle_row_31 = vec![Felt::ZERO; HASH_CYCLE_LEN];
        cycle_row_0[0] = Felt::ONE;
        cycle_row_30[30] = Felt::ONE;
        cycle_row_31[31] = Felt::ONE;

        // Step-type selectors
        let mut is_external = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_internal = vec![Felt::ZERO; HASH_CYCLE_LEN];

        // External rounds: rows 1-4 (initial) and 27-30 (terminal)
        for r in 1..=4 {
            is_external[r] = Felt::ONE;
        }
        for r in 27..=30 {
            is_external[r] = Felt::ONE;
        }

        // Internal rounds: rows 5-26
        for r in 5..=26 {
            is_internal[r] = Felt::ONE;
        }

        // External round constants (12 lanes)
        let ark_ext = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];
            // Initial external rounds: rows 1-4
            for r in 1..=4 {
                col[r] = Hasher::ARK_EXT_INITIAL[r - 1][lane];
            }
            // Terminal external rounds: rows 27-30
            for r in 27..=30 {
                col[r] = Hasher::ARK_EXT_TERMINAL[r - 27][lane];
            }
            col
        });

        // Internal round constant (lane 0 only)
        let mut ark_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
        ark_int[5..=26].copy_from_slice(&Hasher::ARK_INT);

        Self {
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_ext,
            ark_int,
        }
    }
}

#[allow(clippy::new_without_default)]
impl BitwisePeriodicCols<Vec<Felt>> {
    /// Generate periodic columns for the bitwise chiplet.
    ///
    /// - `k_first`: `[1, 0, 0, 0, 0, 0, 0, 0]` (period 8)
    /// - `k_transition`: `[1, 1, 1, 1, 1, 1, 1, 0]` (period 8)
    pub fn new() -> Self {
        let k_first = vec![
            Felt::ONE,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
        ];

        let k_transition = vec![
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ONE,
            Felt::ZERO,
        ];

        Self { k_first, k_transition }
    }
}

impl PeriodicCols<Vec<Felt>> {
    /// Generate all chiplet periodic columns as a flat `Vec<Vec<Felt>>`.
    ///
    /// Combines hasher and bitwise periodic columns in layout order.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let HasherPeriodicCols {
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_ext:
                [
                    ark_0,
                    ark_1,
                    ark_2,
                    ark_3,
                    ark_4,
                    ark_5,
                    ark_6,
                    ark_7,
                    ark_8,
                    ark_9,
                    ark_10,
                    ark_11,
                ],
            ark_int,
        } = HasherPeriodicCols::new();

        let BitwisePeriodicCols { k_first, k_transition } = BitwisePeriodicCols::new();

        vec![
            cycle_row_0,
            cycle_row_30,
            cycle_row_31,
            is_external,
            is_internal,
            ark_0,
            ark_1,
            ark_2,
            ark_3,
            ark_4,
            ark_5,
            ark_6,
            ark_7,
            ark_8,
            ark_9,
            ark_10,
            ark_11,
            ark_int,
            k_first,
            k_transition,
        ]
    }
}

// TOTAL COUNT
// ================================================================================================

/// Total number of periodic columns across all chiplets.
pub const NUM_PERIODIC_COLUMNS: usize = size_of::<PeriodicCols<u8>>();

// BORROW IMPL
// ================================================================================================

impl<T> Borrow<PeriodicCols<T>> for [T] {
    fn borrow(&self) -> &PeriodicCols<T> {
        debug_assert_eq!(self.len(), NUM_PERIODIC_COLUMNS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<PeriodicCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

// COMPILE-TIME ASSERTIONS
// ================================================================================================

const _: () = {
    assert!(size_of::<PeriodicCols<u8>>() == 20);
    assert!(size_of::<HasherPeriodicCols<u8>>() == 18);
    assert!(size_of::<BitwisePeriodicCols<u8>>() == 2);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_dimensions() {
        let cols = PeriodicCols::periodic_columns();
        assert_eq!(cols.len(), NUM_PERIODIC_COLUMNS);

        // Hasher columns (first 18) have period 32; bitwise columns (last 2) have period 8.
        let (hasher_cols, bitwise_cols) = cols.split_at(size_of::<HasherPeriodicCols<u8>>());
        for col in hasher_cols {
            assert_eq!(col.len(), HASH_CYCLE_LEN);
        }
        for col in bitwise_cols {
            assert_eq!(col.len(), 8);
        }
    }

    #[test]
    fn hasher_cycle_markers_are_exclusive() {
        let h = HasherPeriodicCols::new();
        for (row_idx, ((row0, row30), row31)) in
            h.cycle_row_0.iter().zip(&h.cycle_row_30).zip(&h.cycle_row_31).enumerate()
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
    fn hasher_step_selectors_are_exclusive() {
        let h = HasherPeriodicCols::new();
        for (row_idx, (is_ext, is_int)) in h.is_external.iter().zip(&h.is_internal).enumerate() {
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
