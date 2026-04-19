//! Truncating wrapper for cryptographic hashers.
//!
//! This module provides [`TruncatingHasher`], the hasher analogue of `p3-symmetric`'s
//! [`TruncatedPermutation`](p3_symmetric::TruncatedPermutation).

use p3_symmetric::CryptographicHasher;

/// Hasher analogue of `p3-symmetric`'s `TruncatedPermutation`.
#[derive(Copy, Clone, Debug)]
pub struct TruncatingHasher<Inner, const IN: usize, const OUT: usize> {
    inner: Inner,
}

impl<Inner, const IN: usize, const OUT: usize> TruncatingHasher<Inner, IN, OUT> {
    pub const fn new(inner: Inner) -> Self {
        Self { inner }
    }
}

impl<T, Inner, const IN: usize, const OUT: usize> CryptographicHasher<T, [T; OUT]>
    for TruncatingHasher<Inner, IN, OUT>
where
    T: Clone,
    Inner: CryptographicHasher<T, [T; IN]>,
{
    #[inline]
    fn hash_iter<I>(&self, input: I) -> [T; OUT]
    where
        I: IntoIterator<Item = T>,
    {
        const { assert!(OUT <= IN) }
        let full = self.inner.hash_iter(input);
        core::array::from_fn(|i| full[i].clone())
    }

    #[inline]
    fn hash_iter_slices<'a, I>(&self, input: I) -> [T; OUT]
    where
        I: IntoIterator<Item = &'a [T]>,
        T: 'a,
    {
        const { assert!(OUT <= IN) }
        let full = self.inner.hash_iter_slices(input);
        core::array::from_fn(|i| full[i].clone())
    }

    #[inline]
    fn hash_slice(&self, input: &[T]) -> [T; OUT] {
        const { assert!(OUT <= IN) }
        let full = self.inner.hash_slice(input);
        core::array::from_fn(|i| full[i].clone())
    }

    #[inline]
    fn hash_item(&self, input: T) -> [T; OUT] {
        const { assert!(OUT <= IN) }
        let full = self.inner.hash_item(input);
        core::array::from_fn(|i| full[i].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockBinaryHasher;

    #[test]
    fn truncates_prefix_of_inner_digest() {
        type H = TruncatingHasher<MockBinaryHasher, 4, 2>;
        let h = H::new(MockBinaryHasher);
        let input: [u64; 11] = core::array::from_fn(|i| (i * 13 + 7) as u64);
        let full: [u64; 4] = MockBinaryHasher.hash_iter(input);
        let short = h.hash_iter(input);
        assert_eq!(short, [full[0], full[1]]);
    }

    #[test]
    fn hash_iter_slices_delegates() {
        type H = TruncatingHasher<MockBinaryHasher, 4, 2>;
        let h = H::new(MockBinaryHasher);
        let a = [1u64, 2, 3];
        let b = [4u64, 5];
        let got_slices = h.hash_iter_slices([&a[..], &b[..]]);
        let got_flat = h.hash_iter(a.iter().chain(b.iter()).copied());
        assert_eq!(got_slices, got_flat);
    }

    #[test]
    fn hash_slice_and_hash_item_match_hash_iter() {
        type H = TruncatingHasher<MockBinaryHasher, 4, 2>;
        let h = H::new(MockBinaryHasher);
        let xs = [9u64, 8, 7, 6, 5];
        assert_eq!(h.hash_slice(&xs), h.hash_iter(xs));
        assert_eq!(h.hash_item(42u64), h.hash_iter([42u64]));
    }
}
