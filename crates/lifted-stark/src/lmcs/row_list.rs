//! Flat storage of variable-width rows.

use alloc::vec::Vec;

use crate::util::align::aligned_len;

/// Flat storage of variable-width rows.
///
/// In a STARK proof, each row typically holds one committed matrix's evaluations at a
/// leaf index queried by the verifier as part of the low-degree test (LDT). Matrices
/// have different widths because they encode different sets of constraint polynomials
/// (e.g., main trace vs auxiliary trace).
///
/// Stores all elements contiguously in a single `Vec<T>`, with a separate `Vec<usize>`
/// tracking the width of each row. This avoids N+1 heap allocations compared to
/// `Vec<Vec<T>>` and enables efficient flat iteration.
///
/// Invariant: `widths.iter().sum::<usize>() == elems.len()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowList<T> {
    elems: Vec<T>,
    widths: Vec<usize>,
}

impl<T> RowList<T> {
    /// Create a `RowList` from raw elements and widths.
    ///
    /// # Panics
    ///
    /// Panics if `widths.iter().sum() != elems.len()`.
    pub fn new(elems: Vec<T>, widths: Vec<usize>) -> Self {
        let expected: usize = widths.iter().sum();
        assert_eq!(
            elems.len(),
            expected,
            "RowList invariant violated: {} elems but widths sum to {}",
            elems.len(),
            expected,
        );
        Self { elems, widths }
    }

    /// Build a `RowList` from an iterator of row-like items.
    ///
    /// Accepts anything convertible to `&[T]`: owned `Vec<T>`, `&Vec<T>`, `&[T]`, `Cow`, etc.
    pub fn from_rows<R: AsRef<[T]>>(rows: impl IntoIterator<Item = R>) -> Self
    where
        T: Clone,
    {
        let mut elems = Vec::new();
        let mut widths = Vec::new();
        for row in rows {
            let row = row.as_ref();
            widths.push(row.len());
            elems.extend_from_slice(row);
        }
        Self { elems, widths }
    }

    /// Contiguous element slice.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.elems
    }

    /// Iterate over all elements by value.
    #[inline]
    pub fn iter_values(&self) -> impl DoubleEndedIterator<Item = T> + '_
    where
        T: Copy,
    {
        self.elems.iter().copied()
    }

    /// Number of rows.
    #[inline]
    pub fn num_rows(&self) -> usize {
        self.widths.len()
    }

    /// Iterate over rows as slices.
    pub fn iter_rows(&self) -> impl DoubleEndedIterator<Item = &[T]> {
        RowIter { elems: &self.elems, widths: &self.widths }
    }

    /// Get a single row by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= self.num_rows()`.
    pub fn row(&self, idx: usize) -> &[T] {
        let offset: usize = self.widths[..idx].iter().sum();
        &self.elems[offset..offset + self.widths[idx]]
    }
}

impl<T: Copy + Default> RowList<T> {
    /// Iterate over all elements with each row zero-padded to a multiple of `alignment`.
    ///
    /// Alignment matches the cryptographic sponge's absorption rate. Both prover and
    /// verifier must hash identical padded data for the Merkle commitment to verify,
    /// so OOD evaluations sent over the transcript use the same padding convention.
    ///
    /// Yields the original row elements followed by implicit zeros, without allocating
    /// a padded copy.
    pub fn iter_aligned(&self, alignment: usize) -> impl DoubleEndedIterator<Item = T> + '_ {
        self.iter_rows().flat_map(move |row| {
            let padding = aligned_len(row.len(), alignment) - row.len();
            row.iter().copied().chain(core::iter::repeat_n(T::default(), padding))
        })
    }
}

impl<T: Default + Clone> RowList<T> {
    /// Build a `RowList` from an iterator of row-like items, padding each to `alignment`.
    pub fn from_rows_aligned<R: AsRef<[T]>>(
        rows: impl IntoIterator<Item = R>,
        alignment: usize,
    ) -> Self {
        let mut elems = Vec::new();
        let mut widths = Vec::new();
        for row in rows {
            let row = row.as_ref();
            let padded_len = aligned_len(row.len(), alignment);
            widths.push(padded_len);
            elems.extend_from_slice(row);
            elems.resize(elems.len() + (padded_len - row.len()), T::default());
        }
        Self { elems, widths }
    }
}

/// Double-ended iterator over the rows of a [`RowList`].
struct RowIter<'a, T> {
    elems: &'a [T],
    widths: &'a [usize],
}

impl<'a, T> Iterator for RowIter<'a, T> {
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        let (&width, rest) = self.widths.split_first()?;
        let (row, elems) = self.elems.split_at(width);
        self.widths = rest;
        self.elems = elems;
        Some(row)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.widths.len(), Some(self.widths.len()))
    }
}

impl<T> DoubleEndedIterator for RowIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let (&width, rest) = self.widths.split_last()?;
        let (elems, row) = self.elems.split_at(self.elems.len() - width);
        self.widths = rest;
        self.elems = elems;
        Some(row)
    }
}
