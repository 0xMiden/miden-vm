//! Column layout for the Poseidon2 permutation AIR.
//!
//! Each row contains the current Poseidon2 state, three row-scheduled witness columns, and the
//! permutation cycle id. Periodic columns describe the fixed 16-row schedule and provide the round
//! constants consumed by the transition constraints.

use alloc::{vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, chiplets::hasher::Hasher, field::PrimeCharacteristicRing};

use crate::trace::chiplets::hasher::{HASH_CYCLE_LEN, STATE_WIDTH};

/// Row-scheduled witness columns used by the permutation AIR.
pub const NUM_SBOX_WITNESSES: usize = 3;

/// First row of a 16-row cycle; holds the input state.
pub const CYCLE_INPUT_ROW: usize = 0;

/// First initial-external row after the cycle input row.
pub const INITIAL_EXTERNAL_ROUND_START: usize = 1;

/// Exclusive end of the initial-external rows.
pub const INITIAL_EXTERNAL_ROUND_END: usize = 4;

/// First row containing packed internal rounds.
pub const PACKED_INTERNAL_ROUND_START: usize = INITIAL_EXTERNAL_ROUND_END;

/// Number of rows with three packed internal rounds.
pub const NUM_PACKED_INTERNAL_ROUND_ROWS: usize = 7;

/// Exclusive end of the packed-internal rows.
pub const PACKED_INTERNAL_ROUND_END: usize =
    PACKED_INTERNAL_ROUND_START + NUM_PACKED_INTERNAL_ROUND_ROWS;

/// Row containing the final internal round and the first terminal external round.
pub const INTERNAL_PLUS_EXTERNAL_ROW: usize = PACKED_INTERNAL_ROUND_END;

/// First terminal-external row after the internal-plus-external row.
pub const TERMINAL_EXTERNAL_ROUND_START: usize = INTERNAL_PLUS_EXTERNAL_ROW + 1;

/// Output row of a 16-row cycle.
pub const CYCLE_OUTPUT_ROW: usize = HASH_CYCLE_LEN - 1;

/// Exclusive end of the terminal-external rows.
pub const TERMINAL_EXTERNAL_ROUND_END: usize = CYCLE_OUTPUT_ROW;

/// Number of terminal-external rows after [`INTERNAL_PLUS_EXTERNAL_ROW`].
pub const NUM_TRAILING_EXTERNAL_ROUND_ROWS: usize =
    TERMINAL_EXTERNAL_ROUND_END - TERMINAL_EXTERNAL_ROUND_START;

/// Index of the final internal-round constant.
pub const LAST_INTERNAL_ROUND_ARK_IDX: usize = NUM_PACKED_INTERNAL_ROUND_ROWS * NUM_SBOX_WITNESSES;

/// Poseidon2 permutation trace columns.
///
/// `witnesses` hold internal-round S-box outputs on internal-round rows. On the cycle input and
/// output rows, `witnesses[0]` holds the perm-link multiplicity for the cycle; other unused
/// witness cells are zero.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Poseidon2PermutationCols<T> {
    pub witnesses: [T; NUM_SBOX_WITNESSES],
    pub state: [T; STATE_WIDTH],
    pub perm_id: T,
}

/// Number of columns in the Poseidon2 permutation AIR.
pub const NUM_POSEIDON2_PERMUTATION_COLS: usize = NUM_SBOX_WITNESSES + STATE_WIDTH + 1;

impl<T> Borrow<Poseidon2PermutationCols<T>> for [T] {
    fn borrow(&self) -> &Poseidon2PermutationCols<T> {
        debug_assert_eq!(self.len(), NUM_POSEIDON2_PERMUTATION_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<Poseidon2PermutationCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

impl<T> BorrowMut<Poseidon2PermutationCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Poseidon2PermutationCols<T> {
        debug_assert_eq!(self.len(), NUM_POSEIDON2_PERMUTATION_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<Poseidon2PermutationCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &mut cols[0]
    }
}

/// Poseidon2 permutation periodic columns.
///
/// The selectors are mutually exclusive and repeat every 16 rows:
///
/// ```text
/// row      selector        ARK columns
/// 0        is_init_ext     ARK_EXT_INITIAL[0]
/// 1..=3    is_ext          ARK_EXT_INITIAL[1..=3]
/// 4..=10   is_packed_int   ARK_INT triples in ark[0..3]
/// 11       is_int_ext      ARK_EXT_TERMINAL[0]
/// 12..=14  is_ext          ARK_EXT_TERMINAL[1..=3]
/// 15       none            zero
/// ```
///
/// The final internal-round constant `ARK_INT[21]` is not stored in a periodic column; the
/// row-11 transition uses it directly.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Poseidon2PermutationPeriodicCols<T> {
    pub is_init_ext: T,
    pub is_ext: T,
    pub is_packed_int: T,
    pub is_int_ext: T,
    pub ark: [T; STATE_WIDTH],
}

/// Number of periodic columns used by the Poseidon2 permutation AIR.
pub const NUM_POSEIDON2_PERMUTATION_PERIODIC_COLUMNS: usize =
    size_of::<Poseidon2PermutationPeriodicCols<u8>>();

impl<T: Copy> Poseidon2PermutationPeriodicCols<T> {
    /// Returns 1 on transition rows 0..=14 of each cycle.
    pub fn not_cycle_end<E>(&self) -> E
    where
        T: Into<E>,
        E: PrimeCharacteristicRing,
    {
        self.is_init_ext.into()
            + self.is_ext.into()
            + self.is_packed_int.into()
            + self.is_int_ext.into()
    }
}

impl Default for Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    /// Builds the 16-row periodic selector and round-constant columns.
    pub fn new() -> Self {
        let mut is_init_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_packed_int = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_int_ext = vec![Felt::ZERO; HASH_CYCLE_LEN];

        is_init_ext[CYCLE_INPUT_ROW] = Felt::ONE;
        for value in &mut is_ext[INITIAL_EXTERNAL_ROUND_START..INITIAL_EXTERNAL_ROUND_END] {
            *value = Felt::ONE;
        }
        for value in &mut is_ext[TERMINAL_EXTERNAL_ROUND_START..TERMINAL_EXTERNAL_ROUND_END] {
            *value = Felt::ONE;
        }
        for value in &mut is_packed_int[PACKED_INTERNAL_ROUND_START..PACKED_INTERNAL_ROUND_END] {
            *value = Felt::ONE;
        }
        is_int_ext[INTERNAL_PLUS_EXTERNAL_ROW] = Felt::ONE;

        let ark = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];

            col[CYCLE_INPUT_ROW] = Hasher::ARK_EXT_INITIAL[0][lane];
            for (offset, value) in col[INITIAL_EXTERNAL_ROUND_START..INITIAL_EXTERNAL_ROUND_END]
                .iter_mut()
                .enumerate()
            {
                let row = INITIAL_EXTERNAL_ROUND_START + offset;
                *value = Hasher::ARK_EXT_INITIAL[row][lane];
            }

            if lane < NUM_SBOX_WITNESSES {
                for triple in 0..NUM_PACKED_INTERNAL_ROUND_ROWS {
                    col[PACKED_INTERNAL_ROUND_START + triple] =
                        Hasher::ARK_INT[triple * NUM_SBOX_WITNESSES + lane];
                }
            }

            col[INTERNAL_PLUS_EXTERNAL_ROW] = Hasher::ARK_EXT_TERMINAL[0][lane];
            for (offset, value) in col[TERMINAL_EXTERNAL_ROUND_START..TERMINAL_EXTERNAL_ROUND_END]
                .iter_mut()
                .enumerate()
            {
                let row = TERMINAL_EXTERNAL_ROUND_START + offset;
                *value = Hasher::ARK_EXT_TERMINAL[row - INTERNAL_PLUS_EXTERNAL_ROW][lane];
            }

            col
        });

        Self {
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            ark,
        }
    }

    /// Generates periodic columns as a flat vector in struct-field order.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let Poseidon2PermutationPeriodicCols {
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            ark: [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11],
        } = Self::new();

        vec![
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            a0,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
            a8,
            a9,
            a10,
            a11,
        ]
    }
}

impl<T> Borrow<Poseidon2PermutationPeriodicCols<T>> for [T] {
    fn borrow(&self) -> &Poseidon2PermutationPeriodicCols<T> {
        debug_assert_eq!(self.len(), NUM_POSEIDON2_PERMUTATION_PERIODIC_COLUMNS);
        let (prefix, cols, suffix) =
            unsafe { self.align_to::<Poseidon2PermutationPeriodicCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

const _: () = {
    assert!(size_of::<Poseidon2PermutationCols<u8>>() == NUM_POSEIDON2_PERMUTATION_COLS);
    assert!(
        size_of::<Poseidon2PermutationPeriodicCols<u8>>()
            == NUM_POSEIDON2_PERMUTATION_PERIODIC_COLUMNS
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon2_step_selectors_are_exclusive() {
        let periodic = Poseidon2PermutationPeriodicCols::new();

        for row in 0..HASH_CYCLE_LEN {
            let init_ext = periodic.is_init_ext[row];
            let ext = periodic.is_ext[row];
            let packed_int = periodic.is_packed_int[row];
            let int_ext = periodic.is_int_ext[row];

            assert_eq!(init_ext * (init_ext - Felt::ONE), Felt::ZERO);
            assert_eq!(ext * (ext - Felt::ONE), Felt::ZERO);
            assert_eq!(packed_int * (packed_int - Felt::ONE), Felt::ZERO);
            assert_eq!(int_ext * (int_ext - Felt::ONE), Felt::ZERO);

            let sum = init_ext + ext + packed_int + int_ext;
            assert!(sum == Felt::ZERO || sum == Felt::ONE, "selectors overlap on row {row}: {sum}");

            if row == CYCLE_OUTPUT_ROW {
                assert_eq!(sum, Felt::ZERO);
            } else {
                assert_eq!(sum, Felt::ONE);
            }
        }
    }

    #[test]
    fn poseidon2_external_round_constants_are_correct() {
        let periodic = Poseidon2PermutationPeriodicCols::new();

        for lane in 0..STATE_WIDTH {
            assert_eq!(periodic.ark[lane][0], Hasher::ARK_EXT_INITIAL[0][lane]);

            for row in INITIAL_EXTERNAL_ROUND_START..INITIAL_EXTERNAL_ROUND_END {
                assert_eq!(periodic.ark[lane][row], Hasher::ARK_EXT_INITIAL[row][lane]);
            }

            assert_eq!(
                periodic.ark[lane][INTERNAL_PLUS_EXTERNAL_ROW],
                Hasher::ARK_EXT_TERMINAL[0][lane]
            );
            for row in TERMINAL_EXTERNAL_ROUND_START..TERMINAL_EXTERNAL_ROUND_END {
                assert_eq!(
                    periodic.ark[lane][row],
                    Hasher::ARK_EXT_TERMINAL[row - INTERNAL_PLUS_EXTERNAL_ROW][lane]
                );
            }
        }
    }

    #[test]
    fn poseidon2_internal_round_constants_are_correct() {
        let periodic = Poseidon2PermutationPeriodicCols::new();

        for triple in 0..NUM_PACKED_INTERNAL_ROUND_ROWS {
            let row = PACKED_INTERNAL_ROUND_START + triple;
            for lane in 0..NUM_SBOX_WITNESSES {
                assert_eq!(
                    periodic.ark[lane][row],
                    Hasher::ARK_INT[triple * NUM_SBOX_WITNESSES + lane]
                );
            }

            for lane in NUM_SBOX_WITNESSES..STATE_WIDTH {
                assert_eq!(periodic.ark[lane][row], Felt::ZERO);
            }
        }
    }

    #[test]
    fn poseidon2_boundary_row_is_zero() {
        let periodic = Poseidon2PermutationPeriodicCols::new();
        let row = CYCLE_OUTPUT_ROW;

        assert_eq!(periodic.is_init_ext[row], Felt::ZERO);
        assert_eq!(periodic.is_ext[row], Felt::ZERO);
        assert_eq!(periodic.is_packed_int[row], Felt::ZERO);
        assert_eq!(periodic.is_int_ext[row], Felt::ZERO);

        for lane in 0..STATE_WIDTH {
            assert_eq!(periodic.ark[lane][row], Felt::ZERO);
        }
    }
}
