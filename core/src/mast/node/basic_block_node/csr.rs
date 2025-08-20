use alloc::vec::Vec;
use core::ops::Index;

use num_traits::Euclid;
use thiserror::Error;

/// Compressed Sparse Row (CSR) format sparse matrix with the constraint that each row
/// has an initial dense prefix followed by a zero suffix. This optimization assumes
/// non-zero elements are stored contiguously at the start of each row.
///
/// Uses scipy-style naming convention:
/// - `data`: Non-zero values in row-major order
/// - `indptr`: Row pointers indicating where each row starts in `data`
/// - `cols`: Number of columns in the matrix
/// - `clobbering_mode`: Whether to ignore insertion of F::default() values
///
/// This format is optimized for matrices where non-zero elements appear
/// contiguously in the first columns of each row.
// To represent an OpBatch, should be used with # cols = GROUP_SIZE, # rows = BATCH_SIZE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix<F: Default> {
    /// Non-zero values in row-major order
    pub data: Vec<F>,
    /// Row pointers: `indptr[i]` is the starting index of row `i` in `data`,
    /// and `indptr[i+1]` is the ending index (exclusive). Row `i`'s data spans
    /// `data[indptr[i]..indptr[i+1]]`.
    // should be serialized as [u8; BATCH_SIZE + 1] since the max value is 72
    pub indptr: Vec<usize>,
    /// Number of columns in the matrix
    pub cols: usize,
    /// If true, insertion of F::default() values is ignored. If false, all values
    /// are inserted regardless of whether they are the default value.
    pub clobbering_mode: bool,
    #[doc(hidden)]
    /// A copy of F::default (for the Index trait)
    _default: F,
}

#[derive(Error, Debug)]
pub enum SparseMatrixError {
    #[error("Cannot insert at row {0}, row is full.")]
    FullRow(usize),
}

impl<F: Default> SparseMatrix<F> {
    /// Creates a new empty 0x0 matrix with specified clobbering mode
    pub fn empty(clobbering_mode: bool) -> Self {
        Self {
            data: vec![],
            indptr: vec![0],
            cols: 0,
            clobbering_mode,
            _default: F::default(),
        }
    }

    /// Creates a new matrix with specified clobbering mode
    pub fn new(data: Vec<F>, indptr: Vec<usize>, cols: usize, clobbering_mode: bool) -> Self {
        Self {
            data,
            indptr,
            cols,
            clobbering_mode,
            _default: F::default(),
        }
    }

    /// Creates a new matrix with specified clobbering mode
    pub fn with_clobbering_mode(
        data: Vec<F>,
        indptr: Vec<usize>,
        cols: usize,
        clobbering_mode: bool,
    ) -> Self {
        Self {
            data,
            indptr,
            cols,
            clobbering_mode,
            _default: F::default(),
        }
    }

    /// Adds a new empty row to the matrix
    pub(crate) fn add_row(&mut self) {
        let current_len = self.data.len();
        self.indptr.push(current_len);
    }

    /// Returns the number of non-zero entries
    pub fn len(&self) -> usize {
        *self.indptr.last().unwrap()
    }

    /// Returns `true` if the matrix is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of rows in the matrix
    pub fn num_rows(&self) -> usize {
        self.indptr.len() - 1
    }

    /// Returns the number of columns in the matrix
    pub fn num_cols(&self) -> usize {
        self.cols
    }
}

impl<F: Default + Copy> SparseMatrix<F> {
    /// Returns the element at `(row, col)`, or `F::default()` if the element is zero
    ///
    /// For a given row, elements with `col < row_dense_len` are stored in `data`,
    /// while elements with `col >= row_dense_len` implicitly return the default value.
    pub fn get(&self, row: usize, col: usize) -> F {
        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];
        let row_dense_len = row_end - row_start;

        if col >= row_dense_len {
            // lookup in the zero suffix
            F::default()
        } else {
            self.data[row_start + col]
        }
    }
}
impl<F: Default + PartialEq + Copy> SparseMatrix<F> {
    /// Inserts a value at the dense end of a specified row
    ///
    /// Returns the column index where the element was inserted, or `SparseMatrixError::FullRow`
    /// if the row has no more space for non-zero elements.
    ///
    /// Zero values are not stored in the matrix but still consume a column position.
    pub fn insert(&mut self, row: usize, value: F) -> Result<usize, SparseMatrixError> {
        // Ensure we have enough rows
        while self.num_rows() <= row {
            self.add_row();
        }

        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];
        let row_dense_len = row_end - row_start;

        if row_dense_len == self.num_cols() {
            return Err(SparseMatrixError::FullRow(row));
        }
        // Add new element if not zero or if clobbering mode is disabled
        if value != F::default() || !self.clobbering_mode {
            self.insert_element_at(row, row_end, value);
        }
        Ok(row_dense_len)
    }

    // Inserts a non-zero element at the specified absolute position in the data vector
    fn insert_element_at(&mut self, row: usize, abs_pos: usize, value: F) {
        // check we insert in the correct row, or extend it
        debug_assert!(self.indptr[row] <= abs_pos);
        debug_assert!(self.indptr[row + 1] >= abs_pos);

        // Insert into data and indices
        self.data.insert(abs_pos, value);

        // Update indptr for all subsequent rows
        for i in (row + 1)..self.indptr.len() {
            self.indptr[i] += 1;
        }
    }

    /// Returns an iterator over non-zero elements as `(row, col, value)` tuples
    pub fn iter_nonzero(&self) -> NonZeroIter<'_, F> {
        NonZeroIter {
            matrix: self,
            row: 0,
            i: 0,
            nnz: *self.indptr.last().unwrap(),
        }
    }

    /// Returns an iterator over all matrix elements (including zeros) in row-major order
    pub fn iter_dense(&self) -> DenseIter<'_, F> {
        DenseIter::new(self)
    }
}

/// Iterator for dense matrix elements (including zeros) in row-major order
#[derive(Debug)]
pub struct DenseIter<'a, F: Default> {
    matrix: &'a SparseMatrix<F>,
    row: usize,
    col: usize,
    row_start: usize,
    row_end: usize,
    current_idx: usize,
}

impl<'a, F: Default> DenseIter<'a, F> {
    fn new(matrix: &'a SparseMatrix<F>) -> Self {
        let row_start = if matrix.num_rows() > 0 { matrix.indptr[0] } else { 0 };
        let row_end = if matrix.num_rows() > 0 { matrix.indptr[1] } else { 0 };
        DenseIter {
            matrix,
            row: 0,
            col: 0,
            row_start,
            row_end,
            current_idx: row_start,
        }
    }
}

impl<'a, F: Copy + Default> Iterator for DenseIter<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.matrix.num_rows() {
            return None;
        }

        let value = if self.current_idx < self.row_end {
            // Found the element we're looking for
            let result = self.matrix.data[self.current_idx];
            self.current_idx += 1;
            self.col += 1;
            result
        } else {
            // No more elements in this row, return default
            self.col += 1;
            F::default()
        };

        // Move to next row if we've finished this row
        if self.col >= self.matrix.num_cols() {
            self.col = 0;
            self.row += 1;

            // Update row pointers for the new row
            if self.row < self.matrix.num_rows() {
                self.row_start = self.matrix.indptr[self.row];
                self.row_end = self.matrix.indptr[self.row + 1];
                self.current_idx = self.row_start;
            }
        }

        Some(value)
    }
}

/// Iterator for sparse matrix (non-zero elements with row/column indices, i.e. COO format)
#[derive(Debug)]
pub struct NonZeroIter<'a, F: Default> {
    matrix: &'a SparseMatrix<F>,
    row: usize,
    i: usize,
    nnz: usize,
}

impl<'a, F: Copy + Default> Iterator for NonZeroIter<'a, F> {
    type Item = (usize, usize, F);

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.nnz {
            return None;
        }
        let row = self.row;
        let val = self.matrix.data[self.i];
        let row_start = self.matrix.indptr[self.row];
        let col = self.i - row_start;

        self.i += 1;

        // Advance to the next row if we've moved past the current row's data
        while self.row < self.matrix.num_rows() - 1 && self.i >= self.matrix.indptr[self.row + 1] {
            self.row += 1;
        }

        Some((row, col, val))
    }
}

impl<F: Default + PartialEq> Index<usize> for SparseMatrix<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        // Calculate row and col from the linear index (row-major order)
        let rows = self.num_rows();
        let cols = self.num_cols();

        if rows == 0 || cols == 0 {
            return &self._default;
        }
        let (row, col) = index.div_rem_euclid(&cols);

        // Handle case where index is out of bounds
        if row >= rows {
            return &self._default;
        }

        // Get the element at (row, col), returning default if not found
        // Use the same logic as the get method but more efficient for single access
        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];

        if col >= row_end - row_start {
            return &self._default;
        }

        &self.data[row_start + col]
    }
}
