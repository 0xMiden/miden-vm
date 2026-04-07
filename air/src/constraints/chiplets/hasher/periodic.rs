//! Hasher chiplet periodic columns.
//!
//! This module defines the periodic columns used by the Poseidon2 hasher chiplet.
//! The hasher operates on a 16-row cycle, and periodic columns provide cycle-position
//! selectors and round constants.
//!
//! ## Column Layout (16 columns, period 16)
//!
//! | Index | Name           | Description |
//! |-------|----------------|-------------|
//! | 0     | is_init_ext    | 1 on row 0 (init linear + first external round) |
//! | 1     | is_ext         | 1 on rows 1-3, 12-14 (single external round) |
//! | 2     | is_packed_int  | 1 on rows 4-10 (3 packed internal rounds) |
//! | 3     | is_int_ext     | 1 on row 11 (int22 + ext5 merged) |
//! | 4-15  | ark[0..12]     | Shared round constants (see below) |
//!
//! ## Round Constant Sharing
//!
//! The 12 `ark` columns carry external round constants on external rows (0-3, 11-14)
//! and internal round constants in `ark[0..2]` on packed-internal rows (4-10).
//! Different constraints read them with different semantics, gated by the mutually
//! exclusive selectors. Row 11's internal constant (ARK_INT[21]) is hardcoded in the
//! constraint rather than stored in a periodic column.
//!
//! ## Derived Expressions
//!
//! `cycle_row_15` (the boundary row marker) is not stored as a column. Instead:
//! ```text
//! 1 - cycle_row_15 = is_init_ext + is_ext + is_packed_int + is_int_ext
//! ```
//! The perm_seg constraints always use it in the form `(1 - cycle_row_N)`.
//!
//! ## 16-Row Schedule
//!
//! ```text
//! Row  Transition              Selectors active
//! 0    init + ext1             is_init_ext
//! 1    ext2                    is_ext
//! 2    ext3                    is_ext
//! 3    ext4                    is_ext
//! 4    int1+int2+int3          is_packed_int
//! 5    int4+int5+int6          is_packed_int
//! 6    int7+int8+int9          is_packed_int
//! 7    int10+int11+int12       is_packed_int
//! 8    int13+int14+int15       is_packed_int
//! 9    int16+int17+int18       is_packed_int
//! 10   int19+int20+int21       is_packed_int
//! 11   int22+ext5              is_int_ext
//! 12   ext6                    is_ext
//! 13   ext7                    is_ext
//! 14   ext8                    is_ext
//! 15   boundary                (none)
//! ```

use alloc::vec::Vec;

use miden_core::chiplets::hasher::Hasher;

use crate::Felt;

// CONSTANTS
// ================================================================================================

/// Length of one hash cycle (16 rows: 15 transitions + 1 boundary).
pub const HASH_CYCLE_LEN: usize = 16;

/// Width of the hasher state.
pub const STATE_WIDTH: usize = 12;

// Periodic column indices.

/// 1 on row 0 (init linear + first external round).
pub const P_IS_INIT_EXT: usize = 0;

/// 1 on rows 1-3, 12-14 (single external round).
pub const P_IS_EXT: usize = 1;

/// 1 on rows 4-10 (3 packed internal rounds).
pub const P_IS_PACKED_INT: usize = 2;

/// 1 on row 11 (int22 + ext5 merged).
pub const P_IS_INT_EXT: usize = 3;

/// Start of the 12 shared round constant columns.
pub const P_ARK_START: usize = 4;

/// Total number of periodic columns for the hasher chiplet.
pub const NUM_PERIODIC_COLUMNS: usize = P_ARK_START + STATE_WIDTH;

// INTERNAL HELPERS
// ================================================================================================

/// Returns periodic columns for the Poseidon2 hasher chiplet.
///
/// All columns repeat every 16 rows, matching one permutation cycle.
///
/// The 4 selector columns identify the row type. The 12 ark columns carry either
/// external round constants (on external rows) or internal round constants in
/// `ark[0..2]` (on packed-internal rows). See module docs for the full mapping.
#[allow(clippy::needless_range_loop)]
pub fn periodic_columns() -> Vec<Vec<Felt>> {
    let mut cols: Vec<Vec<Felt>> = Vec::with_capacity(NUM_PERIODIC_COLUMNS);

    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------
    let mut is_init_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut is_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut is_packed_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
    let mut is_int_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];

    is_init_ext[0] = Felt::ONE;

    for r in [1, 2, 3, 12, 13, 14] {
        is_ext[r] = Felt::ONE;
    }

    for r in 4..=10 {
        is_packed_int[r] = Felt::ONE;
    }

    is_int_ext[11] = Felt::ONE;

    cols.push(is_init_ext);
    cols.push(is_ext);
    cols.push(is_packed_int);
    cols.push(is_int_ext);

    // -------------------------------------------------------------------------
    // Shared round constants (12 columns)
    // -------------------------------------------------------------------------
    // On external rows (0-3, 11-14): hold per-lane external round constants.
    // On packed-internal rows (4-10): ark[0..2] hold 3 internal round constants,
    //   ark[3..12] are zero.
    // On boundary (row 15): all zero.
    for lane in 0..STATE_WIDTH {
        let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];

        // Row 0 (init+ext1): first initial external round constants
        col[0] = Hasher::ARK_EXT_INITIAL[0][lane];

        // Rows 1-3 (ext2, ext3, ext4): remaining initial external round constants
        for r in 1..=3 {
            col[r] = Hasher::ARK_EXT_INITIAL[r][lane];
        }

        // Rows 4-10 (packed internal): internal constants in lanes 0-2 only
        if lane < 3 {
            for triple in 0..7_usize {
                let row = 4 + triple;
                let ark_idx = triple * 3 + lane;
                col[row] = Hasher::ARK_INT[ark_idx];
            }
        }

        // Row 11 (int22+ext5): terminal external round 0 constants
        // (internal constant ARK_INT[21] is hardcoded in the constraint)
        col[11] = Hasher::ARK_EXT_TERMINAL[0][lane];

        // Rows 12-14 (ext6, ext7, ext8): remaining terminal external round constants
        for r in 12..=14 {
            col[r] = Hasher::ARK_EXT_TERMINAL[r - 11][lane];
        }

        cols.push(col);
    }

    cols
}

#[cfg(test)]
#[allow(clippy::needless_range_loop)]
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
    fn selectors_are_exclusive_and_cover_rows_0_to_14() {
        let cols = periodic_columns();
        for row in 0..HASH_CYCLE_LEN {
            let init = cols[P_IS_INIT_EXT][row];
            let ext = cols[P_IS_EXT][row];
            let packed = cols[P_IS_PACKED_INT][row];
            let intx = cols[P_IS_INT_EXT][row];

            // Booleanity
            for &v in &[init, ext, packed, intx] {
                assert_eq!(v * (v - Felt::ONE), Felt::ZERO, "non-boolean at row {row}");
            }

            // Mutual exclusivity
            let sum = init + ext + packed + intx;
            if row < 15 {
                assert_eq!(sum, Felt::ONE, "selector sum != 1 at row {row}");
            } else {
                assert_eq!(sum, Felt::ZERO, "selector sum != 0 at boundary row {row}");
            }

            // Correct row type
            match row {
                0 => assert_eq!(init, Felt::ONE),
                1..=3 | 12..=14 => assert_eq!(ext, Felt::ONE),
                4..=10 => assert_eq!(packed, Felt::ONE),
                11 => assert_eq!(intx, Felt::ONE),
                15 => assert_eq!(sum, Felt::ZERO),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn external_round_constants_correct() {
        let cols = periodic_columns();

        // Row 0: ARK_EXT_INITIAL[0]
        for lane in 0..STATE_WIDTH {
            assert_eq!(cols[P_ARK_START + lane][0], Hasher::ARK_EXT_INITIAL[0][lane]);
        }

        // Rows 1-3: ARK_EXT_INITIAL[1..3]
        for r in 1..=3 {
            for lane in 0..STATE_WIDTH {
                assert_eq!(cols[P_ARK_START + lane][r], Hasher::ARK_EXT_INITIAL[r][lane]);
            }
        }

        // Row 11: ARK_EXT_TERMINAL[0]
        for lane in 0..STATE_WIDTH {
            assert_eq!(cols[P_ARK_START + lane][11], Hasher::ARK_EXT_TERMINAL[0][lane]);
        }

        // Rows 12-14: ARK_EXT_TERMINAL[1..3]
        for r in 12..=14 {
            for lane in 0..STATE_WIDTH {
                assert_eq!(cols[P_ARK_START + lane][r], Hasher::ARK_EXT_TERMINAL[r - 11][lane]);
            }
        }
    }

    #[test]
    fn internal_round_constants_correct() {
        let cols = periodic_columns();

        // Rows 4-10: packed internal round constants in ark[0..2]
        for triple in 0..7_usize {
            let row = 4 + triple;
            for k in 0..3 {
                let ark_idx = triple * 3 + k;
                assert_eq!(
                    cols[P_ARK_START + k][row],
                    Hasher::ARK_INT[ark_idx],
                    "mismatch at row {row}, int constant {k} (ARK_INT[{ark_idx}])"
                );
            }
            // ark[3..12] must be zero on packed-internal rows
            for lane in 3..STATE_WIDTH {
                assert_eq!(
                    cols[P_ARK_START + lane][row],
                    Felt::ZERO,
                    "ark[{lane}] nonzero at packed-int row {row}"
                );
            }
        }
    }

    #[test]
    fn boundary_row_all_zero() {
        let cols = periodic_columns();
        for col_idx in P_ARK_START..NUM_PERIODIC_COLUMNS {
            assert_eq!(cols[col_idx][15], Felt::ZERO, "ark column {col_idx} nonzero at row 15");
        }
    }
}
