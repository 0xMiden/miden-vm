//! Column layout for the standalone Poseidon2 permutation AIR.

use alloc::{vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, chiplets::hasher::Hasher, field::PrimeCharacteristicRing};

use crate::trace::chiplets::hasher::{HASH_CYCLE_LEN, STATE_WIDTH};

/// Number of witness columns used by packed internal-round rows.
pub const NUM_SBOX_WITNESSES: usize = 3;

/// Poseidon2 permutation trace columns.
///
/// One row is one packed Poseidon2 transition row. A full permutation cycle is
/// 16 consecutive rows. `multiplicity` is constant across the cycle and is zero
/// on dummy padding cycles.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Poseidon2PermutationCols<T> {
    /// S-box witness columns for packed internal rows.
    pub witnesses: [T; NUM_SBOX_WITNESSES],
    /// Poseidon2 state (12 field elements: 8 rate + 4 capacity).
    pub state: [T; STATE_WIDTH],
    /// Request multiplicity for the perm-link bus.
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

/// Poseidon2 permutation periodic columns (period = 16 rows).
///
/// The first four columns identify the packed transition shape. The 12 `ark`
/// columns carry external round constants on external rows and internal round
/// constants in `ark[0..3]` on packed-internal rows.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Poseidon2PermutationPeriodicCols<T> {
    /// 1 on row 0 (init linear + first external round).
    pub is_init_ext: T,
    /// 1 on rows 1-3, 12-14 (single external round).
    pub is_ext: T,
    /// 1 on rows 4-10 (3 packed internal rounds).
    pub is_packed_int: T,
    /// 1 on row 11 (int22 + ext5 merged).
    pub is_int_ext: T,
    /// Shared round constants.
    pub ark: [T; STATE_WIDTH],
}

/// Number of periodic columns used by the Poseidon2 permutation AIR.
pub const NUM_POSEIDON2_PERMUTATION_PERIODIC_COLUMNS: usize =
    size_of::<Poseidon2PermutationPeriodicCols<u8>>();

impl<T: Copy> Poseidon2PermutationPeriodicCols<T> {
    /// Returns 1 on all rows except the final row of each 16-row cycle.
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

#[allow(clippy::new_without_default)]
impl Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    /// Generate Poseidon2 periodic columns as 16-row cycles.
    #[allow(clippy::needless_range_loop)]
    pub fn new() -> Self {
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

        let ark = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];

            col[0] = Hasher::ARK_EXT_INITIAL[0][lane];
            for r in 1..=3 {
                col[r] = Hasher::ARK_EXT_INITIAL[r][lane];
            }

            if lane < 3 {
                for triple in 0..7_usize {
                    let row = 4 + triple;
                    let ark_idx = triple * 3 + lane;
                    col[row] = Hasher::ARK_INT[ark_idx];
                }
            }

            col[11] = Hasher::ARK_EXT_TERMINAL[0][lane];
            for r in 12..=14 {
                col[r] = Hasher::ARK_EXT_TERMINAL[r - 11][lane];
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

impl Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    /// Generate the periodic columns as a flat vector in struct-field order.
    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let Poseidon2PermutationPeriodicCols {
            is_init_ext,
            is_ext,
            is_packed_int,
            is_int_ext,
            ark: [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11],
        } = Poseidon2PermutationPeriodicCols::new();

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
