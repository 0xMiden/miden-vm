//! Compressed Sparse Row (CSR) matrix for efficient sparse data storage.
//!
//! This module provides a generic [`CsrMatrix`] type that maps row indices to variable-length
//! data. It's commonly used for storing decorator IDs, assembly operation IDs, and similar
//! sparse mappings in the Miden VM.

use alloc::vec::Vec;

use miden_crypto::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Idx, IndexVec, IndexedVecError};

/// Errors that can occur during CSR validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CsrValidationError {
    /// The indptr array must start at 0.
    #[error("indptr must start at 0, got {0}")]
    IndptrStartNotZero(usize),

    /// The indptr array must be monotonically increasing.
    #[error("indptr not monotonic at index {index}: {prev} > {curr}")]
    IndptrNotMonotonic { index: usize, prev: usize, curr: usize },

    /// The last indptr value must equal data.len().
    #[error("indptr ends at {indptr_end}, but data.len() is {data_len}")]
    IndptrDataMismatch { indptr_end: usize, data_len: usize },

    /// A data value failed domain-specific validation.
    #[error("invalid data value at row {row}, position {position}")]
    InvalidData { row: usize, position: usize },
}

/// Compressed Sparse Row matrix mapping row indices to variable-length data.
///
/// For row `i`, its data is at `data[indptr[i]..indptr[i+1]]`.
///
/// # Type Parameters
///
/// - `I`: The row index type, must implement [`Idx`].
/// - `D`: The data type stored in each row.
///
/// # Example
///
/// ```ignore
/// use miden_utils_indexing::{CsrMatrix, newtype_id};
///
/// newtype_id!(NodeId);
///
/// let mut csr = CsrMatrix::<NodeId, u32>::new();
/// csr.push_row([1, 2, 3]);      // Row 0: [1, 2, 3]
/// csr.push_empty_row();          // Row 1: []
/// csr.push_row([4, 5]);          // Row 2: [4, 5]
///
/// assert_eq!(csr.row(NodeId::from(0)), Some(&[1, 2, 3][..]));
/// assert_eq!(csr.row(NodeId::from(1)), Some(&[][..]));
/// assert_eq!(csr.row(NodeId::from(2)), Some(&[4, 5][..]));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CsrMatrix<I: Idx, D> {
    /// Flat storage of all data values.
    data: Vec<D>,
    /// Row pointers: row i's data is at `data[indptr[i]..indptr[i+1]]`.
    indptr: IndexVec<I, usize>,
}

impl<I: Idx, D> Default for CsrMatrix<I, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Idx, D> CsrMatrix<I, D> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty [`CsrMatrix`].
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            indptr: IndexVec::new(),
        }
    }

    /// Creates a [`CsrMatrix`] with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// - `rows`: Expected number of rows.
    /// - `data`: Expected total number of data elements across all rows.
    pub fn with_capacity(rows: usize, data: usize) -> Self {
        Self {
            data: Vec::with_capacity(data),
            indptr: IndexVec::with_capacity(rows + 1),
        }
    }

    // MUTATION
    // --------------------------------------------------------------------------------------------

    /// Appends a new row with the given data values.
    ///
    /// Rows must be added in sequential order starting from row 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of rows would exceed `u32::MAX`.
    pub fn push_row(&mut self, values: impl IntoIterator<Item = D>) -> Result<I, IndexedVecError> {
        // Initialize indptr with 0 if this is the first row
        if self.indptr.is_empty() {
            self.indptr.push(0)?;
        }

        // The row index is the current number of rows (before adding)
        let row_idx = self.num_rows();

        // Add data
        self.data.extend(values);

        // Add end pointer for this row
        self.indptr.push(self.data.len())?;

        Ok(I::from(row_idx as u32))
    }

    /// Appends an empty row (no data for this row index).
    ///
    /// # Errors
    ///
    /// Returns an error if the number of rows would exceed `u32::MAX`.
    pub fn push_empty_row(&mut self) -> Result<I, IndexedVecError> {
        self.push_row(core::iter::empty())
    }

    /// Appends empty rows to fill gaps up to (but not including) `target_row`.
    ///
    /// If `target_row` is less than or equal to the current number of rows,
    /// this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of rows would exceed `u32::MAX`.
    pub fn fill_to_row(&mut self, target_row: I) -> Result<(), IndexedVecError> {
        let target = target_row.to_usize();
        while self.num_rows() < target {
            self.push_empty_row()?;
        }
        Ok(())
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns `true` if this matrix has no rows.
    pub fn is_empty(&self) -> bool {
        self.indptr.is_empty()
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        if self.indptr.is_empty() {
            0
        } else {
            self.indptr.len() - 1
        }
    }

    /// Returns the total number of data elements across all rows.
    pub fn num_data(&self) -> usize {
        self.data.len()
    }

    /// Returns the data slice for the given row, or `None` if the row doesn't exist.
    pub fn row(&self, row: I) -> Option<&[D]> {
        let row_idx = row.to_usize();
        if row_idx >= self.num_rows() {
            return None;
        }

        let start = self.indptr[row];
        let end = self.indptr[I::from((row_idx + 1) as u32)];
        Some(&self.data[start..end])
    }

    /// Returns the data slice for the given row, panicking if the row doesn't exist.
    ///
    /// # Panics
    ///
    /// Panics if `row` is out of bounds.
    pub fn row_expect(&self, row: I) -> &[D] {
        self.row(row).expect("row index out of bounds")
    }

    /// Returns an iterator over all `(row_index, data_slice)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (I, &[D])> {
        (0..self.num_rows()).map(move |i| {
            let row = I::from(i as u32);
            (row, self.row_expect(row))
        })
    }

    /// Returns an iterator over all data elements with their `(row_index, position_in_row, &data)`.
    pub fn iter_enumerated(&self) -> impl Iterator<Item = (I, usize, &D)> {
        self.iter()
            .flat_map(|(row, data)| data.iter().enumerate().map(move |(pos, d)| (row, pos, d)))
    }

    /// Returns the underlying data slice.
    pub fn data(&self) -> &[D] {
        &self.data
    }

    /// Returns the underlying indptr.
    pub fn indptr(&self) -> &IndexVec<I, usize> {
        &self.indptr
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Validates the CSR structural invariants.
    ///
    /// Checks:
    /// - `indptr` starts at 0 (if non-empty)
    /// - `indptr` is monotonically increasing
    /// - `indptr` ends at `data.len()`
    ///
    /// For domain-specific validation of data values, use [`validate_with`](Self::validate_with).
    pub fn validate(&self) -> Result<(), CsrValidationError> {
        self.validate_with(|_| true)
    }

    /// Validates structural invariants plus domain-specific data constraints.
    ///
    /// The callback is invoked for each data element. Return `false` to indicate
    /// an invalid value.
    ///
    /// # Arguments
    ///
    /// - `f`: A function that returns `true` if the data value is valid.
    pub fn validate_with<F>(&self, f: F) -> Result<(), CsrValidationError>
    where
        F: Fn(&D) -> bool,
    {
        let indptr = self.indptr.as_slice();

        // Empty matrix is valid
        if indptr.is_empty() {
            return Ok(());
        }

        // Check indptr starts at 0
        if indptr[0] != 0 {
            return Err(CsrValidationError::IndptrStartNotZero(indptr[0]));
        }

        // Check indptr is monotonic
        for i in 1..indptr.len() {
            if indptr[i - 1] > indptr[i] {
                return Err(CsrValidationError::IndptrNotMonotonic {
                    index: i,
                    prev: indptr[i - 1],
                    curr: indptr[i],
                });
            }
        }

        // Check indptr ends at data.len()
        let last = *indptr.last().expect("indptr is non-empty");
        if last != self.data.len() {
            return Err(CsrValidationError::IndptrDataMismatch {
                indptr_end: last,
                data_len: self.data.len(),
            });
        }

        // Validate data values
        for (row, data) in self.iter() {
            for (pos, d) in data.iter().enumerate() {
                if !f(d) {
                    return Err(CsrValidationError::InvalidData {
                        row: row.to_usize(),
                        position: pos,
                    });
                }
            }
        }

        Ok(())
    }
}

// SERIALIZATION
// ================================================================================================

impl<I, D> Serializable for CsrMatrix<I, D>
where
    I: Idx,
    D: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write data
        target.write_usize(self.data.len());
        for item in &self.data {
            item.write_into(target);
        }

        // Write indptr
        target.write_usize(self.indptr.len());
        for &ptr in self.indptr.as_slice() {
            target.write_usize(ptr);
        }
    }
}

impl<I, D> Deserializable for CsrMatrix<I, D>
where
    I: Idx,
    D: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read data
        let data_len = source.read_usize()?;
        let mut data = Vec::with_capacity(data_len);
        for _ in 0..data_len {
            data.push(D::read_from(source)?);
        }

        // Read indptr
        let indptr_len = source.read_usize()?;
        let mut indptr_vec = Vec::with_capacity(indptr_len);
        for _ in 0..indptr_len {
            indptr_vec.push(source.read_usize()?);
        }
        let indptr = IndexVec::try_from(indptr_vec).map_err(|_| {
            DeserializationError::InvalidValue("indptr too large for IndexVec".into())
        })?;

        Ok(Self { data, indptr })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::newtype_id;

    newtype_id!(TestRowId);

    #[test]
    fn test_new_is_empty() {
        let csr = CsrMatrix::<TestRowId, u32>::new();
        assert!(csr.is_empty());
        assert_eq!(csr.num_rows(), 0);
        assert_eq!(csr.num_data(), 0);
    }

    #[test]
    fn test_push_row() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();

        let id0 = csr.push_row([1, 2, 3]).unwrap();
        assert_eq!(id0, TestRowId::from(0));
        assert_eq!(csr.num_rows(), 1);
        assert_eq!(csr.num_data(), 3);
        assert_eq!(csr.row(TestRowId::from(0)), Some(&[1, 2, 3][..]));

        let id1 = csr.push_row([4, 5]).unwrap();
        assert_eq!(id1, TestRowId::from(1));
        assert_eq!(csr.num_rows(), 2);
        assert_eq!(csr.num_data(), 5);
        assert_eq!(csr.row(TestRowId::from(1)), Some(&[4, 5][..]));
    }

    #[test]
    fn test_push_empty_row() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();

        csr.push_row([1, 2]).unwrap();
        csr.push_empty_row().unwrap();
        csr.push_row([3]).unwrap();

        assert_eq!(csr.num_rows(), 3);
        assert_eq!(csr.row(TestRowId::from(0)), Some(&[1, 2][..]));
        assert_eq!(csr.row(TestRowId::from(1)), Some(&[][..]));
        assert_eq!(csr.row(TestRowId::from(2)), Some(&[3][..]));
    }

    #[test]
    fn test_fill_to_row() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();

        csr.push_row([1]).unwrap();
        csr.fill_to_row(TestRowId::from(3)).unwrap();
        csr.push_row([2]).unwrap();

        assert_eq!(csr.num_rows(), 4);
        assert_eq!(csr.row(TestRowId::from(0)), Some(&[1][..]));
        assert_eq!(csr.row(TestRowId::from(1)), Some(&[][..]));
        assert_eq!(csr.row(TestRowId::from(2)), Some(&[][..]));
        assert_eq!(csr.row(TestRowId::from(3)), Some(&[2][..]));
    }

    #[test]
    fn test_row_out_of_bounds() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([1]).unwrap();

        assert_eq!(csr.row(TestRowId::from(0)), Some(&[1][..]));
        assert_eq!(csr.row(TestRowId::from(1)), None);
        assert_eq!(csr.row(TestRowId::from(100)), None);
    }

    #[test]
    fn test_iter() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([1, 2]).unwrap();
        csr.push_empty_row().unwrap();
        csr.push_row([3]).unwrap();

        let items: alloc::vec::Vec<_> = csr.iter().collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], (TestRowId::from(0), &[1, 2][..]));
        assert_eq!(items[1], (TestRowId::from(1), &[][..]));
        assert_eq!(items[2], (TestRowId::from(2), &[3][..]));
    }

    #[test]
    fn test_iter_enumerated() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([10, 20]).unwrap();
        csr.push_row([30]).unwrap();

        let items: alloc::vec::Vec<_> = csr.iter_enumerated().collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], (TestRowId::from(0), 0, &10));
        assert_eq!(items[1], (TestRowId::from(0), 1, &20));
        assert_eq!(items[2], (TestRowId::from(1), 0, &30));
    }

    #[test]
    fn test_validate_empty() {
        let csr = CsrMatrix::<TestRowId, u32>::new();
        assert!(csr.validate().is_ok());
    }

    #[test]
    fn test_validate_valid() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([1, 2, 3]).unwrap();
        csr.push_empty_row().unwrap();
        csr.push_row([4]).unwrap();

        assert!(csr.validate().is_ok());
    }

    #[test]
    fn test_validate_with_callback() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([1, 2, 3]).unwrap();
        csr.push_row([4, 5]).unwrap();

        // All values < 10: valid
        assert!(csr.validate_with(|&v| v < 10).is_ok());

        // All values < 4: invalid (first failure is 4 at row 1, position 0)
        let result = csr.validate_with(|&v| v < 4);
        assert!(matches!(result, Err(CsrValidationError::InvalidData { row: 1, position: 0 })));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut csr = CsrMatrix::<TestRowId, u32>::new();
        csr.push_row([1, 2, 3]).unwrap();
        csr.push_empty_row().unwrap();
        csr.push_row([4, 5]).unwrap();

        // Serialize
        let mut bytes = vec![];
        csr.write_into(&mut bytes);

        // Deserialize
        let mut reader = miden_crypto::utils::SliceReader::new(&bytes);
        let restored: CsrMatrix<TestRowId, u32> = CsrMatrix::read_from(&mut reader).unwrap();

        assert_eq!(csr, restored);
    }
}
