//! Periodic columns for the Poseidon2 permutation cycle.
//!
//! 16-row period encoding the packed schedule:
//!
//! ```text
//! Row  Transition              Selector
//! 0    init + ext1             is_init_ext
//! 1-3  ext2..ext4              is_ext
//! 4-10 3× packed internal      is_packed_int
//! 11   int22 + ext5            is_int_ext
//! 12-14 ext6..ext8             is_ext
//! 15   boundary (no step)      (none)
//! ```
//!
//! The four step selectors are mutex and sum to 1 on rows 0..15, 0 on
//! row 15 (= cycle boundary).
//!
//! The 12 `ark` columns carry per-lane round constants:
//! - rows 0..3:  `ARK_EXT_INITIAL[0..4]`
//! - rows 4..10: `ARK_INT[3·triple + k]` in lanes 0..3 (triple = row − 4), zeros in lanes 3..12.
//! - row 11:     `ARK_EXT_TERMINAL[0]` (the internal constant `ARK_INT[21]` for row 11's int leg is
//!   hardcoded into the constraint).
//! - rows 12..14: `ARK_EXT_TERMINAL[1..4]`
//! - row 15:     all zero.

use miden_core::{Felt, chiplets::hasher::Hasher};

use crate::transcript::poseidon2::math::STATE_WIDTH;

/// Length of one permutation cycle (= 16 rows).
pub const PERIOD: usize = 16;

/// Number of preprocessed columns produced by [`poseidon2_program`].
pub const NUM_PERIODIC_COLS: usize = 4 + STATE_WIDTH;

// COLUMN INDICES
// ================================================================================================

/// 1 at row 0 (init linear + first external round).
pub const PCOL_IS_INIT_EXT: usize = 0;
/// 1 at rows 1–3 and 12–14 (single external round).
pub const PCOL_IS_EXT: usize = 1;
/// 1 at rows 4–10 (3 packed internal rounds per row).
pub const PCOL_IS_PACKED_INT: usize = 2;
/// 1 at row 11 (int22 + ext5 merged).
pub const PCOL_IS_INT_EXT: usize = 3;
/// First `ark` column (12 columns; range `PCOL_ARK_BEGIN..PCOL_ARK_END`).
pub const PCOL_ARK_BEGIN: usize = 4;
/// One past the last `ark` column.
pub const PCOL_ARK_END: usize = PCOL_ARK_BEGIN + STATE_WIDTH;

// ROW INDICES (within the period)
// ================================================================================================

/// Row 0 — the merged `init linear + ext1` step.
pub const ROW_INIT_EXT: usize = 0;
/// Last row of the cycle — boundary (no transition).
pub const ROW_BOUNDARY: usize = PERIOD - 1;
/// Row of the merged `int22 + ext5` step.
pub const ROW_INT_EXT: usize = 11;
/// First row of the packed-internal range (inclusive).
pub const PACKED_INT_BEGIN: usize = 4;
/// One past the last row of the packed-internal range.
pub const PACKED_INT_END: usize = 11;
/// Number of packed-internal rows.
pub const NUM_PACKED_INT_ROWS: usize = PACKED_INT_END - PACKED_INT_BEGIN;
/// Number of internal-round constants consumed by the packed rows
/// (= `NUM_PACKED_INT_ROWS · 3`).
pub const NUM_PACKED_INT_RCS: usize = NUM_PACKED_INT_ROWS * 3;

// ARK INDEX HELPERS
// ================================================================================================

/// Hardcoded internal-round constant used in the `int22 + ext5` step
/// (row 11). The 22nd internal round constant; lives in the constraint
/// rather than a periodic column slot.
pub const ARK_INT_LAST_IDX: usize = NUM_PACKED_INT_RCS;

// PROGRAM
// ================================================================================================

/// Generate the 16-row periodic program.
pub fn poseidon2_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let mut cols: [Vec<Felt>; NUM_PERIODIC_COLS] =
        core::array::from_fn(|_| vec![Felt::ZERO; PERIOD]);

    // Step selectors.
    cols[PCOL_IS_INIT_EXT][ROW_INIT_EXT] = Felt::ONE;
    for r in [1, 2, 3, 12, 13, 14] {
        cols[PCOL_IS_EXT][r] = Felt::ONE;
    }
    cols[PCOL_IS_PACKED_INT][PACKED_INT_BEGIN..PACKED_INT_END].fill(Felt::ONE);
    cols[PCOL_IS_INT_EXT][ROW_INT_EXT] = Felt::ONE;

    // Ark columns — initial externals (rows 0–3).
    for (r, ark_row) in Hasher::ARK_EXT_INITIAL.iter().enumerate() {
        for lane in 0..STATE_WIDTH {
            cols[PCOL_ARK_BEGIN + lane][r] = ark_row[lane];
        }
    }

    // Ark columns — packed internals (rows 4–10): 3 RCs per row in
    // lanes 0..3, zeros elsewhere.
    for triple in 0..NUM_PACKED_INT_ROWS {
        let row = PACKED_INT_BEGIN + triple;
        for k in 0..3 {
            let ark_idx = triple * 3 + k;
            cols[PCOL_ARK_BEGIN + k][row] = Hasher::ARK_INT[ark_idx];
        }
    }

    // Ark columns — int+ext merged (row 11): the external leg's
    // constants. The internal leg uses `ARK_INT[ARK_INT_LAST_IDX]`,
    // hardcoded into the constraint.
    for lane in 0..STATE_WIDTH {
        cols[PCOL_ARK_BEGIN + lane][ROW_INT_EXT] = Hasher::ARK_EXT_TERMINAL[0][lane];
    }

    // Ark columns — terminal externals (rows 12–14).
    for (r, ark_row) in (12..=14).zip(Hasher::ARK_EXT_TERMINAL.iter().skip(1)) {
        for lane in 0..STATE_WIDTH {
            cols[PCOL_ARK_BEGIN + lane][r] = ark_row[lane];
        }
    }

    cols
}
