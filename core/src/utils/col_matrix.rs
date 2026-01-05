use alloc::vec::Vec;

#[derive(Debug)]
pub struct ColMatrix<E> {
    columns: Vec<Vec<E>>,
}

impl<E: Clone + Copy> ColMatrix<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [ColMatrix] instantiated with the data from the specified columns.
    ///
    /// # Panics
    /// Panics if:
    /// * The provided vector of columns is empty.
    /// * Not all of the columns have the same number of elements.
    /// * Number of rows is smaller than or equal to 1.
    /// * Number of rows is not a power of two.
    pub fn new(columns: Vec<Vec<E>>) -> Self {
        assert!(!columns.is_empty(), "a matrix must contain at least one column");
        let num_rows = columns[0].len();
        assert!(num_rows > 1, "number of rows in a matrix must be greater than one");
        assert!(num_rows.is_power_of_two(), "number of rows in a matrix must be a power of 2");
        for column in columns.iter().skip(1) {
            assert_eq!(column.len(), num_rows, "all matrix columns must have the same length");
        }

        Self { columns }
    }
    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.columns.len()
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.columns[0].len()
    }

    /// Returns the element located at the specified column and row indexes in this matrix.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.columns[col_idx][row_idx]
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column(&self, col_idx: usize) -> &[E] {
        &self.columns[col_idx]
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column_mut(&mut self, col_idx: usize) -> &mut [E] {
        &mut self.columns[col_idx]
    }

    /// Returns an iterator over all columns in this matrix.
    pub fn columns(&self) -> impl Iterator<Item = &[E]> {
        self.columns.iter().map(|col| col.as_slice())
    }

    /// Copies values of all columns at the specified row into the specified row slice.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn read_row_into(&self, row_idx: usize, row: &mut [E]) {
        for (column, value) in self.columns.iter().zip(row.iter_mut()) {
            *value = column[row_idx];
        }
    }

    /// Updates a row in this matrix at the specified index to the provided data.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn update_row(&mut self, row_idx: usize, row: &[E]) {
        for (column, &value) in self.columns.iter_mut().zip(row) {
            column[row_idx] = value;
        }
    }

    /// Merges a column to the end of the matrix provided its length matches the matrix.
    ///
    /// # Panics
    /// Panics if the column has a different length to other columns in the matrix.
    pub fn merge_column(&mut self, column: Vec<E>) {
        if let Some(first_column) = self.columns.first() {
            assert_eq!(first_column.len(), column.len());
        }
        self.columns.push(column);
    }

    /// Removes a column of the matrix given its index.
    ///
    /// # Panics
    /// Panics if the column index is out of range.
    pub fn remove_column(&mut self, index: usize) -> Vec<E> {
        assert!(index < self.num_cols(), "column index out of range");
        self.columns.remove(index)
    }
}
