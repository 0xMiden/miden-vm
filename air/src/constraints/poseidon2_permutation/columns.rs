//! Column layout for the Poseidon2 permutation AIR.
//!
//! Each row contains the current Poseidon2 state, three S-box witnesses used by packed
//! internal-round rows, and one request multiplicity. Periodic columns describe the fixed
//! 16-row schedule and provide the round constants consumed by the transition constraints.

use alloc::{vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, chiplets::hasher::Hasher, field::PrimeCharacteristicRing};

use crate::trace::chiplets::hasher::{HASH_CYCLE_LEN, STATE_WIDTH};

/// Witness columns used by packed internal-round rows.
pub const NUM_SBOX_WITNESSES: usize = 3;

/// Poseidon2 permutation trace columns.
///
/// `witnesses` hold internal-round S-box outputs on rows 4..=11 and are zero otherwise.
/// `multiplicity` is constant over a cycle and is used only by the perm-link LogUp bus.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Poseidon2PermutationCols<T> {
    pub witnesses: [T; NUM_SBOX_WITNESSES],
    pub state: [T; STATE_WIDTH],
    pub multiplicity: T,
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

        is_init_ext[0] = Felt::ONE;
        for row in [1, 2, 3, 12, 13, 14] {
            is_ext[row] = Felt::ONE;
        }
        for row in 4..=10 {
            is_packed_int[row] = Felt::ONE;
        }
        is_int_ext[11] = Felt::ONE;

        let ark = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];

            col[0] = Hasher::ARK_EXT_INITIAL[0][lane];
            for row in 1..=3 {
                col[row] = Hasher::ARK_EXT_INITIAL[row][lane];
            }

            if lane < NUM_SBOX_WITNESSES {
                for triple in 0..7 {
                    col[4 + triple] = Hasher::ARK_INT[triple * NUM_SBOX_WITNESSES + lane];
                }
            }

            col[11] = Hasher::ARK_EXT_TERMINAL[0][lane];
            for row in 12..=14 {
                col[row] = Hasher::ARK_EXT_TERMINAL[row - 11][lane];
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
