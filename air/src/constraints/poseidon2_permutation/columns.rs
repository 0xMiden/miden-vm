use alloc::{vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, chiplets::hasher::Hasher, field::PrimeCharacteristicRing};

use crate::trace::chiplets::hasher::{HASH_CYCLE_LEN, STATE_WIDTH};

pub const NUM_SBOX_WITNESSES: usize = 1;

pub const CYCLE_INPUT_ROW: usize = 0;
pub const CYCLE_OUTPUT_ROW: usize = HASH_CYCLE_LEN - 1;

pub const INITIAL_EXTERNAL_ROUND_START: usize = 0;
pub const INITIAL_EXTERNAL_ROUND_END: usize = 0;
pub const PACKED_INTERNAL_ROUND_START: usize = 0;
pub const NUM_PACKED_INTERNAL_ROUND_ROWS: usize = Hasher::NUM_ROUNDS;
#[allow(dead_code)]
pub const PACKED_INTERNAL_ROUND_END: usize = Hasher::NUM_ROUNDS;
pub const INTERNAL_PLUS_EXTERNAL_ROW: usize = 0;
#[allow(dead_code)]
pub const TERMINAL_EXTERNAL_ROUND_START: usize = 0;
#[allow(dead_code)]
pub const TERMINAL_EXTERNAL_ROUND_END: usize = 0;
pub const NUM_TRAILING_EXTERNAL_ROUND_ROWS: usize = 0;
pub const LAST_INTERNAL_ROUND_ARK_IDX: usize = 0;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct Poseidon2PermutationCols<T> {
    pub witnesses: [T; NUM_SBOX_WITNESSES],
    pub state: [T; STATE_WIDTH],
    pub perm_id: T,
}

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

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Poseidon2PermutationPeriodicCols<T> {
    pub is_cycle_start: T,
    pub is_round: T,
    pub ark1: [T; STATE_WIDTH],
    pub ark2: [T; STATE_WIDTH],
}

pub const NUM_POSEIDON2_PERMUTATION_PERIODIC_COLUMNS: usize =
    size_of::<Poseidon2PermutationPeriodicCols<u8>>();

impl<T: Copy> Poseidon2PermutationPeriodicCols<T> {
    pub fn not_cycle_end<E>(&self) -> E
    where
        T: Into<E>,
        E: PrimeCharacteristicRing,
    {
        self.is_round.into()
    }
}

impl Default for Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2PermutationPeriodicCols<Vec<Felt>> {
    pub fn new() -> Self {
        let mut is_cycle_start = vec![Felt::ZERO; HASH_CYCLE_LEN];
        let mut is_round = vec![Felt::ZERO; HASH_CYCLE_LEN];

        is_cycle_start[CYCLE_INPUT_ROW] = Felt::ONE;
        for value in &mut is_round[..Hasher::NUM_ROUNDS] {
            *value = Felt::ONE;
        }

        let ark1 = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];
            for (round, value) in col.iter_mut().take(Hasher::NUM_ROUNDS).enumerate() {
                *value = Hasher::ARK1[round][lane];
            }
            col
        });

        let ark2 = core::array::from_fn(|lane| {
            let mut col = vec![Felt::ZERO; HASH_CYCLE_LEN];
            for (round, value) in col.iter_mut().take(Hasher::NUM_ROUNDS).enumerate() {
                *value = Hasher::ARK2[round][lane];
            }
            col
        });

        Self { is_cycle_start, is_round, ark1, ark2 }
    }

    pub fn periodic_columns() -> Vec<Vec<Felt>> {
        let Poseidon2PermutationPeriodicCols {
            is_cycle_start,
            is_round,
            ark1: [a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a110, a111],
            ark2: [a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a210, a211],
        } = Self::new();

        vec![
            is_cycle_start,
            is_round,
            a10,
            a11,
            a12,
            a13,
            a14,
            a15,
            a16,
            a17,
            a18,
            a19,
            a110,
            a111,
            a20,
            a21,
            a22,
            a23,
            a24,
            a25,
            a26,
            a27,
            a28,
            a29,
            a210,
            a211,
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
            assert_eq!(
                periodic.is_cycle_start[row] * (periodic.is_cycle_start[row] - Felt::ONE),
                Felt::ZERO
            );
            assert_eq!(periodic.is_round[row] * (periodic.is_round[row] - Felt::ONE), Felt::ZERO);
            assert_eq!(
                periodic.is_cycle_start[row] * (periodic.is_round[row] - Felt::ONE),
                Felt::ZERO
            );

            if row == CYCLE_OUTPUT_ROW {
                assert_eq!(periodic.is_round[row], Felt::ZERO);
            } else {
                assert_eq!(periodic.is_round[row], Felt::ONE);
            }
        }
    }

    #[test]
    fn poseidon2_external_round_constants_are_correct() {
        let periodic = Poseidon2PermutationPeriodicCols::new();

        for round in 0..Hasher::NUM_ROUNDS {
            for lane in 0..STATE_WIDTH {
                assert_eq!(periodic.ark1[lane][round], Hasher::ARK1[round][lane]);
                assert_eq!(periodic.ark2[lane][round], Hasher::ARK2[round][lane]);
            }
        }

        for lane in 0..STATE_WIDTH {
            assert_eq!(periodic.ark1[lane][CYCLE_OUTPUT_ROW], Felt::ZERO);
            assert_eq!(periodic.ark2[lane][CYCLE_OUTPUT_ROW], Felt::ZERO);
        }
    }
}
