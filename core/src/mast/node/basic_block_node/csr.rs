use alloc::vec::Vec;
use core::ops::Index;

/// CSR format sparse matrix, We follow the names used by scipy.
/// Detailed explanation here: <https://stackoverflow.com/questions/52299420/scipy-csr-matrix-understand-indptr>
#[derive(Debug)]
pub struct SparseMatrix<F: Copy + Default> {
    /// all non-zero values in the matrix
    pub data: Vec<F>,
    /// column indices
    pub indices: Vec<usize>,
    /// row information
    pub indptr: Vec<usize>,
    /// number of columns
    pub cols: usize,
    /// default value for sparse elements (required for Index trait)
    pub default: F,
}

impl<F: Copy + Default + PartialEq> SparseMatrix<F> {
    /// 0x0 empty matrix
    pub fn empty() -> Self {
        Self {
            data: vec![],
            indices: vec![],
            indptr: vec![0],
            cols: 0,
            default: F::default(),
        }
    }

    /// Add a new empty row to the matrix
    fn add_row(&mut self) {
        let current_len = self.data.len();
        self.indptr.push(current_len);
    }

    /// number of non-zero entries
    pub fn len(&self) -> usize {
        *self.indptr.last().unwrap()
    }

    /// empty matrix
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn num_rows(&self) -> usize {
        self.indptr.len() - 1
    }

    pub fn num_cols(&self) -> usize {
        self.cols
    }

    /// returns a custom iterator over non-zero values
    pub fn iter(&self) -> NonZeroIter<'_, F> {
        NonZeroIter {
            matrix: self,
            row: 0,
            i: 0,
            nnz: *self.indptr.last().unwrap(),
        }
    }

    /// Get the element at (row, col), returning F::default() if not found
    pub fn get(&self, row: usize, col: usize) -> F {
        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];

        // Handle empty rows
        if row_start == row_end {
            return F::default();
        }

        // Binary search for the column index
        let slice = &self.indices[row_start..row_end];
        match slice.binary_search(&col) {
            Ok(pos) => self.data[row_start + pos],
            Err(_) => F::default(),
        }
    }

    /// Set the element at (row, col) - returns the old value or None if was zero
    pub fn set(&mut self, row: usize, col: usize, value: F) -> Option<F> {
        // Ensure we have enough rows
        while self.num_rows() <= row {
            self.add_row();
        }

        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];

        // Handle empty rows
        if row_start == row_end {
            // Element not found, need to insert
            if value != F::default() {
                self.insert_element_at(row, row_start, col, value);
            }
            return None;
        }

        // Binary search for the column index
        let slice = &self.indices[row_start..row_end];
        match slice.binary_search(&col) {
            Ok(pos) => {
                let abs_pos = row_start + pos;
                let old_value = self.data[abs_pos];
                // If setting to zero, remove the element
                if value == F::default() {
                    self.remove_element_at(row, abs_pos);
                    Some(old_value)
                } else {
                    self.data[abs_pos] = value;
                    Some(old_value)
                }
            },
            Err(insert_pos) => {
                // Add new element if not zero
                if value != F::default() {
                    self.insert_element_at(row, row_start + insert_pos, col, value);
                    None
                } else {
                    None
                }
            },
        }
    }

    /// Remove an element at the specified absolute position
    fn remove_element_at(&mut self, row: usize, abs_pos: usize) {
        // Remove from data and indices
        self.data.remove(abs_pos);
        self.indices.remove(abs_pos);

        // Update indptr for all subsequent rows
        for i in (row + 1)..self.indptr.len() {
            self.indptr[i] -= 1;
        }
    }

    /// Insert a new element at the specified absolute position
    fn insert_element_at(&mut self, row: usize, abs_pos: usize, col: usize, value: F) {
        // Insert into data and indices
        self.data.insert(abs_pos, value);
        self.indices.insert(abs_pos, col);

        // Update indptr for all subsequent rows
        for i in (row + 1)..self.indptr.len() {
            self.indptr[i] += 1;
        }
    }

    /// Iterator over all matrix elements (including zeros) in row-major order
    pub fn iter_dense(&self) -> DenseIter<'_, F> {
        DenseIter::new(self)
    }

    /// Iterator over non-zero elements with (row, col, value)
    pub fn iter_nonzero(&self) -> NonZeroIter<'_, F> {
        self.iter()
    }
}

/// Iterator for dense matrix elements (including zeros) in row-major order
#[derive(Debug)]
pub struct DenseIter<'a, F: Copy + Default + PartialEq> {
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
            current_idx: row_start 
        }
    }
}

impl<'a, F: Copy + Default + PartialEq> Iterator for DenseIter<'a, F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.matrix.num_rows() {
            return None;
        }

        let value = if self.current_idx < self.row_end {
            let actual_col = self.matrix.indices[self.current_idx];
            
            if actual_col == self.col {
                // Found the element we're looking for
                let result = self.matrix.data[self.current_idx];
                self.current_idx += 1;
                self.col += 1;
                result
            } else if actual_col > self.col {
                // No element at this column position, return default
                self.col += 1;
                F::default()
            } else {
                // This shouldn't happen due to CSR ordering - indices should be sorted
                self.current_idx += 1;
                self.col += 1;
                F::default()
            }
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

/// Iterator for sparse matrix (non-zero elements with row/column indices)
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
        let col = self.matrix.indices[self.i];
        let val = self.matrix.data[self.i];

        self.i += 1;

        // Advance to the next row if we've moved past the current row's data
        while self.row < self.matrix.num_rows() - 1 && self.i >= self.matrix.indptr[self.row + 1] {
            self.row += 1;
        }

        Some((row, col, val))
    }
}

impl<F: Copy + Default + PartialEq> std::ops::Index<usize> for SparseMatrix<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        // Calculate row and col from the linear index (row-major order)
        let rows = self.num_rows();
        let cols = self.num_cols();
        
        if rows == 0 || cols == 0 {
            return &self.default;
        }
        
        let row = index / cols;
        let col = index % cols;
        
        // Handle case where index is out of bounds
        if row >= rows {
            return &self.default;
        }
        
        // Get the element at (row, col), returning default if not found
        // Use the same logic as the get method but more efficient for single access
        let row_start = self.indptr[row];
        let row_end = self.indptr[row + 1];

        // Handle empty rows
        if row_start == row_end {
            return &self.default;
        }

        // Binary search for the column index
        let slice = &self.indices[row_start..row_end];
        match slice.binary_search(&col) {
            Ok(pos) => &self.data[row_start + pos],
            Err(_) => &self.default,
        }
    }
}
