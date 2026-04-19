//! Serializing stateful sponge.
//!
//! This module provides [`SerializingStatefulSponge`] which serializes field elements
//! to binary before absorption into an inner `StatefulHasher`.

use core::mem::size_of;

use p3_field::Field;

use crate::{Alignable, StatefulHasher};

/// An adapter that serializes field elements to binary and delegates to an inner `StatefulHasher`.
///
/// This mirrors `SerializingHasher`'s conversions from fields to bytes/u32/u64 streams,
/// but implements the `StatefulHasher` interface by delegating to an inner stateful hasher
/// that operates on binary data.
///
/// Unlike `ChainingHasher` (which uses chaining mode `H(state || input)`), this adapter
/// preserves proper sponge absorption semantics by directly calling the inner hasher's
/// `absorb_into` method.
#[derive(Copy, Clone, Debug)]
pub struct SerializingStatefulSponge<Inner> {
    inner: Inner,
}

impl<Inner> SerializingStatefulSponge<Inner> {
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }
}

// -----------------------------------------------------------------------------
// Scalar implementations: F -> [B; OUT]
// The digest type [B; OUT] distinguishes these from parallel implementations.
// -----------------------------------------------------------------------------

// Scalar field -> u8 based inner
impl<F, Inner, const OUT: usize> StatefulHasher<F, [u8; OUT]> for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<u8, [u8; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        self.inner.absorb_into(state, F::into_byte_stream(input));
    }

    fn squeeze(&self, state: &Self::State) -> [u8; OUT] {
        self.inner.squeeze(state)
    }
}

// Scalar field -> u32 based inner
impl<F, Inner, const OUT: usize> StatefulHasher<F, [u32; OUT]> for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<u32, [u32; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        self.inner.absorb_into(state, F::into_u32_stream(input));
    }

    fn squeeze(&self, state: &Self::State) -> [u32; OUT] {
        self.inner.squeeze(state)
    }
}

// Scalar field -> u64 based inner
impl<F, Inner, const OUT: usize> StatefulHasher<F, [u64; OUT]> for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<u64, [u64; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = F>) {
        self.inner.absorb_into(state, F::into_u64_stream(input));
    }

    fn squeeze(&self, state: &Self::State) -> [u64; OUT] {
        self.inner.squeeze(state)
    }
}

// -----------------------------------------------------------------------------
// Parallel implementations: [F; M] -> [[B; M]; OUT]
// The digest type [[B; M]; OUT] is structurally different from [B; OUT],
// which prevents coherence conflicts with scalar implementations.
// -----------------------------------------------------------------------------

// Parallel [F; M] -> [u8; M] based inner
impl<F, Inner, const M: usize, const OUT: usize> StatefulHasher<[F; M], [[u8; M]; OUT]>
    for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<[u8; M], [[u8; M]; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        self.inner.absorb_into(state, F::into_parallel_byte_streams(input));
    }

    fn squeeze(&self, state: &Self::State) -> [[u8; M]; OUT] {
        self.inner.squeeze(state)
    }
}

// Parallel [F; M] -> [u32; M] based inner
impl<F, Inner, const M: usize, const OUT: usize> StatefulHasher<[F; M], [[u32; M]; OUT]>
    for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<[u32; M], [[u32; M]; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        self.inner.absorb_into(state, F::into_parallel_u32_streams(input));
    }

    fn squeeze(&self, state: &Self::State) -> [[u32; M]; OUT] {
        self.inner.squeeze(state)
    }
}

// Parallel [F; M] -> [u64; M] based inner
impl<F, Inner, const M: usize, const OUT: usize> StatefulHasher<[F; M], [[u64; M]; OUT]>
    for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: StatefulHasher<[u64; M], [[u64; M]; OUT]>,
{
    type State = Inner::State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = [F; M]>) {
        self.inner.absorb_into(state, F::into_parallel_u64_streams(input));
    }

    fn squeeze(&self, state: &Self::State) -> [[u64; M]; OUT] {
        self.inner.squeeze(state)
    }
}

// -----------------------------------------------------------------------------
// Alignable implementations for SerializingStatefulSponge
// -----------------------------------------------------------------------------

/// Compute alignment for a serializing wrapper that converts field elements to binary items.
///
/// Given:
/// - `field_bytes`: The field's byte size (`F::NUM_BYTES`)
/// - `item_bytes`: The inner item's byte size (1 for u8, 4 for u32, 8 for u64)
/// - `inner_alignment`: The inner hasher's alignment in items (e.g., sponge rate)
///
/// Returns the alignment in field elements that corresponds to the inner alignment.
///
/// The formula ensures that serializing `alignment` field elements produces exactly
/// `inner_alignment` inner items (or a multiple thereof).
const fn compute_field_alignment(
    field_bytes: usize,
    item_bytes: usize,
    inner_alignment: usize,
) -> usize {
    // We need the smallest number of field elements that, when serialized,
    // produce a byte count divisible by the inner hasher's block size.
    // This is lcm(field_bytes, inner_bytes) / field_bytes.
    //
    // Example: 4-byte field, inner rate = 3 u64s (24 bytes)
    // lcm(4, 24) = 24, so alignment = 24/4 = 6 fields
    // Verify: 6 fields × 4 bytes = 24 bytes = 3 u64s ✓
    //
    // When field_bytes > inner_bytes, alignment is often 1:
    // Example: 32-byte field, inner rate = 2 u64s (16 bytes)
    // lcm(32, 16) = 32, so alignment = 32/32 = 1
    // Each field spans 2 complete blocks, so every field ends aligned.
    let inner_bytes = inner_alignment * item_bytes;

    // gcd via Euclidean algorithm
    let mut a = field_bytes;
    let mut b = inner_bytes;
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    inner_bytes / a
}

impl<F, Inner, T> Alignable<F, T> for SerializingStatefulSponge<Inner>
where
    F: Field,
    Inner: Alignable<T, T>,
{
    const ALIGNMENT: usize =
        compute_field_alignment(F::NUM_BYTES, size_of::<T>(), Inner::ALIGNMENT);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_bn254::Bn254;
    use p3_field::Field;
    use p3_goldilocks::Goldilocks;
    use p3_mersenne_31::Mersenne31;

    use super::*;
    use crate::{StatefulSponge, testing::MockBinaryPermutation};

    /// Verifies implicit zero-padding equals explicit zeros for serialized fields.
    fn test_alignment_semantic<F: Field, const WIDTH: usize, const RATE: usize, const OUT: usize>()
    where
        SerializingStatefulSponge<
            StatefulSponge<MockBinaryPermutation<u64, WIDTH>, WIDTH, RATE, OUT>,
        >: Alignable<F, u64>,
        [u64; WIDTH]: Default,
    {
        let inner = StatefulSponge::<_, WIDTH, RATE, OUT>::new(
            MockBinaryPermutation::<u64, WIDTH>::default(),
        );
        let hasher = SerializingStatefulSponge::new(inner);

        let alignment = <SerializingStatefulSponge<
            StatefulSponge<MockBinaryPermutation<u64, WIDTH>, WIDTH, RATE, OUT>,
        > as Alignable<F, u64>>::ALIGNMENT;

        for input_len in 1..=(alignment * 3) {
            let input: Vec<F> = (1..=input_len).map(|i| F::from_usize(i)).collect();

            let mut state_unpadded = [0u64; WIDTH];
            StatefulHasher::<F, [u64; OUT]>::absorb_into(
                &hasher,
                &mut state_unpadded,
                input.iter().copied(),
            );
            let output_unpadded: [u64; OUT] =
                StatefulHasher::<F, [u64; OUT]>::squeeze(&hasher, &state_unpadded);

            let remainder = input_len % alignment;
            let zeros_needed = if remainder == 0 { 0 } else { alignment - remainder };
            let mut padded_input = input.clone();
            padded_input.extend(core::iter::repeat_n(F::ZERO, zeros_needed));

            let mut state_padded = [0u64; WIDTH];
            StatefulHasher::<F, [u64; OUT]>::absorb_into(
                &hasher,
                &mut state_padded,
                padded_input.iter().copied(),
            );
            let output_padded: [u64; OUT] =
                StatefulHasher::<F, [u64; OUT]>::squeeze(&hasher, &state_padded);

            assert_eq!(output_unpadded, output_padded);
        }
    }

    #[test]
    fn alignment_semantic() {
        // Different field sizes exercise different alignment calculations
        test_alignment_semantic::<Mersenne31, 16, 8, 4>(); // 4 bytes -> alignment 16
        test_alignment_semantic::<Goldilocks, 16, 8, 4>(); // 8 bytes -> alignment 8
        test_alignment_semantic::<Bn254, 16, 8, 4>(); // 32 bytes -> alignment 2
    }

    #[test]
    fn test_compute_field_alignment() {
        // 4-byte field (e.g., Mersenne31) to u32 (4 bytes), inner alignment 8
        // inner_bytes = 32, gcd(4, 32) = 4, alignment = 32/4 = 8
        assert_eq!(compute_field_alignment(4, 4, 8), 8);

        // 4-byte field to u64 (8 bytes), inner alignment 4
        // inner_bytes = 32, gcd(4, 32) = 4, alignment = 32/4 = 8
        assert_eq!(compute_field_alignment(4, 8, 4), 8);

        // 8-byte field (e.g., Goldilocks) to u32 (4 bytes), inner alignment 8
        // inner_bytes = 32, gcd(8, 32) = 8, alignment = 32/8 = 4
        assert_eq!(compute_field_alignment(8, 4, 8), 4);

        // 8-byte field to u64 (8 bytes), inner alignment 4
        // inner_bytes = 32, gcd(8, 32) = 8, alignment = 32/8 = 4
        assert_eq!(compute_field_alignment(8, 8, 4), 4);

        // 32-byte field (e.g., Bn254) to u64 (8 bytes), inner alignment 2
        // inner_bytes = 16, gcd(32, 16) = 16, alignment = 16/16 = 1
        assert_eq!(compute_field_alignment(32, 8, 2), 1);
    }

    #[test]
    fn test_compute_field_alignment_non_power_of_2_rate() {
        // 4-byte field (e.g., Mersenne31) to u64 (8 bytes), rate 3
        // inner_bytes = 24, gcd(4, 24) = 4, alignment = 24/4 = 6
        // Verify: 6 fields * 4 bytes = 24 bytes = 3 u64s ✓
        assert_eq!(compute_field_alignment(4, 8, 3), 6);

        // 8-byte field (e.g., Goldilocks) to u32 (4 bytes), rate 3
        // inner_bytes = 12, gcd(8, 12) = 4, alignment = 12/4 = 3
        // Verify: 3 fields * 8 bytes = 24 bytes = 6 u32s = 2 * rate ✓
        assert_eq!(compute_field_alignment(8, 4, 3), 3);

        // 4-byte field to u32 (4 bytes), rate 7
        // inner_bytes = 28, gcd(4, 28) = 4, alignment = 28/4 = 7
        assert_eq!(compute_field_alignment(4, 4, 7), 7);

        // 8-byte field to u64 (8 bytes), rate 5
        // inner_bytes = 40, gcd(8, 40) = 8, alignment = 40/8 = 5
        assert_eq!(compute_field_alignment(8, 8, 5), 5);
    }
}
