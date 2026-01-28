use alloc::vec::Vec;

// RE-EXPORTS
// ================================================================================================
pub use miden_core::utils::*;
use miden_core::{Felt, ONE, ZERO, field::Field};
use rayon::prelude::*;

use crate::PrimeField64;

// HELPER FUNCTIONS
// ================================================================================================

/// Splits an element into two field elements containing 32-bit integer values
#[inline(always)]
pub(crate) fn split_element(value: Felt) -> (Felt, Felt) {
    let value = value.as_canonical_u64();
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (Felt::new(hi), Felt::new(lo))
}

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_canonical_u64());
    (Felt::new(hi as u64), Felt::new(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}

// BATCH INVERSION
// ================================================================================================

/// Parallel batch inversion using Montgomery's trick, with zeros left unchanged.
///
/// Processes chunks in parallel using rayon, each chunk using Montgomery's trick.
pub(crate) fn batch_inversion_par(values: &mut [Felt]) {
    const CHUNK_SIZE: usize = 1024;

    // We need to work with a copy since we're modifying in place
    let input: Vec<Felt> = values.to_vec();

    input.par_chunks(CHUNK_SIZE).zip(values.par_chunks_mut(CHUNK_SIZE)).for_each(
        |(input_chunk, output_chunk)| {
            batch_inversion_helper(input_chunk, output_chunk);
        },
    );
}

/// Montgomery's trick for batch inversion, handling zeros.
fn batch_inversion_helper(values: &[Felt], result: &mut [Felt]) {
    debug_assert_eq!(values.len(), result.len());

    if values.is_empty() {
        return;
    }

    // Forward pass: compute cumulative products, skipping zeros
    let mut last = ONE;
    for (result, &value) in result.iter_mut().zip(values.iter()) {
        *result = last;
        if value != ZERO {
            last *= value;
        }
    }

    // Invert the final cumulative product
    last = last.inverse();

    // Backward pass: compute individual inverses
    for i in (0..values.len()).rev() {
        if values[i] == ZERO {
            result[i] = ZERO;
        } else {
            result[i] *= last;
            last *= values[i];
        }
    }
}

/// Inverts all values in the provided column in place, leaving zeros unchanged.
pub(crate) fn invert_column_allow_zeros(column: &mut [Felt]) {
    batch_inversion_par(column);
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_inversion_par_with_zeros() {
        let mut values: Vec<Felt> = (0..2048)
            .map(|i| if i % 7 == 0 { ZERO } else { Felt::new(i as u64 + 1) })
            .collect();

        let expected: Vec<Felt> =
            values.iter().map(|&v| if v == ZERO { ZERO } else { v.inverse() }).collect();

        batch_inversion_par(&mut values);

        assert_eq!(values, expected);
    }

    #[test]
    fn invert_column_allow_zeros_works() {
        let mut column = Vec::from([Felt::new(2), ZERO, Felt::new(4), Felt::new(5)]);
        invert_column_allow_zeros(&mut column);

        assert_eq!(column[0], Felt::new(2).inverse());
        assert_eq!(column[1], ZERO);
        assert_eq!(column[2], Felt::new(4).inverse());
        assert_eq!(column[3], Felt::new(5).inverse());
    }
}
