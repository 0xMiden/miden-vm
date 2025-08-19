use std::vec::Vec;

use crate::mast::node::basic_block_node::csr::{SparseMatrix, SparseMatrixError};

#[test]
fn test_empty_matrix() {
    // Verify that an empty matrix has zero dimensions and is marked as empty
    let matrix = SparseMatrix::<i32>::empty();
    assert_eq!(matrix.num_rows(), 0);
    assert_eq!(matrix.num_cols(), 0);
    assert!(matrix.is_empty());
    assert_eq!(matrix.len(), 0);
}

#[test]
fn test_matrix_creation() {
    // Verify that a matrix created with data has correct dimensions and contains all elements
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4]; // 2 rows, with 2 elements each
    let matrix = SparseMatrix::new(data, indptr, 4);

    assert_eq!(matrix.num_rows(), 2);
    assert_eq!(matrix.num_cols(), 4);
    assert_eq!(matrix.len(), 4);
    assert!(!matrix.is_empty());
}

#[test]
fn test_get_existing_element() {
    // Verify that existing elements can be retrieved correctly
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix::new(data, indptr, 4);

    assert_eq!(matrix.get(0, 0), 1);
    assert_eq!(matrix.get(0, 1), 2);
    assert_eq!(matrix.get(1, 0), 3);
    assert_eq!(matrix.get(1, 1), 4);
}

#[test]
fn test_get_missing_element() {
    // Verify that missing elements return the default value (0 for i32)
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix::new(data, indptr, 4);

    assert_eq!(matrix.get(0, 2), 0);
    assert_eq!(matrix.get(0, 3), 0);
    assert_eq!(matrix.get(1, 2), 0);
}

#[test]
fn test_insert() {
    // Verify that insertions work correctly and update data/indptr appropriately
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let mut matrix = SparseMatrix::new(data, indptr, 4);

    assert_eq!(matrix.insert(0, 5).unwrap(), 2);
    assert_eq!(matrix.data, vec![1, 2, 5, 3, 4]);
    assert_eq!(matrix.indptr, vec![0, 3, 5]);

    assert_eq!(matrix.insert(1, 8).unwrap(), 2);
    assert_eq!(matrix.data, vec![1, 2, 5, 3, 4, 8]);
    assert_eq!(matrix.indptr, vec![0, 3, 6]);
}

#[test]
fn test_insert_full() {
    // Verify that inserting into a full row returns the appropriate error
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 4];
    let mut matrix = SparseMatrix::new(data, indptr, 4);

    assert_matches!(matrix.insert(0, 5).unwrap_err(), SparseMatrixError::FullRow(0));
}

#[test]
fn test_iter_nonzero() {
    // Verify that the non-zero iterator returns all elements in row-major order
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix::new(data, indptr, 4);

    let mut iter = matrix.iter_nonzero();
    assert_eq!(iter.next(), Some((0, 0, 1)));
    assert_eq!(iter.next(), Some((0, 1, 2)));
    assert_eq!(iter.next(), Some((1, 0, 3)));
    assert_eq!(iter.next(), Some((1, 1, 4)));
    assert_eq!(iter.next(), None);
}

#[test]
fn test_iter_dense() {
    // Verify that the dense iterator returns all elements including zeros in row-major order
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix::new(data, indptr, 4);

    let mut iter = matrix.iter_dense();
    assert_eq!(iter.next(), Some(1)); // row 0, col 0
    assert_eq!(iter.next(), Some(2)); // row 0, col 1
    assert_eq!(iter.next(), Some(0)); // row 0, col 2 (missing, default)
    assert_eq!(iter.next(), Some(0)); // row 0, col 3 (missing, default)
    assert_eq!(iter.next(), Some(3)); // row 1, col 0
    assert_eq!(iter.next(), Some(4)); // row 1, col 1
    assert_eq!(iter.next(), Some(0)); // row 1, col 2 (missing, default)
    assert_eq!(iter.next(), Some(0)); // row 1, col 3 (missing, default)
    assert_eq!(iter.next(), None);
}

#[test]
fn test_sparse_matrix_with_non_default_zero() {
    // Verify that matrices with non-default zero values work correctly
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    struct TestStruct(i32);

    impl Default for TestStruct {
        fn default() -> Self {
            TestStruct(-999)
        }
    }

    let data = vec![TestStruct(1), TestStruct(2)];
    let indptr = vec![0, 2]; // 1 row only
    let matrix = SparseMatrix::new(data, indptr, 2);

    assert_eq!(matrix.num_rows(), 1);
    assert_eq!(matrix.get(0, 0), TestStruct(1));
    assert_eq!(matrix.get(0, 1), TestStruct(2));
}

#[test]
fn test_sparse_matrix_large() {
    // Verify that larger matrices work correctly with sparse insertion and iteration
    let mut matrix = SparseMatrix::<i32>::empty();
    matrix.cols = 10;
    matrix.indptr = vec![0; 11]; // 10 rows + 1

    // Insert elements at various rows
    assert_eq!(matrix.insert(0, 1).unwrap(), 0);
    assert_eq!(matrix.insert(0, 2).unwrap(), 1);
    assert_eq!(matrix.insert(3, 3).unwrap(), 0);
    assert_eq!(matrix.insert(5, 4).unwrap(), 0);
    assert_eq!(matrix.insert(7, 5).unwrap(), 0);
    assert_eq!(matrix.insert(9, 6).unwrap(), 0);

    assert_eq!(matrix.num_rows(), 10);
    assert_eq!(matrix.num_cols(), 10);
    assert_eq!(matrix.len(), 6);

    // Test element access
    assert_eq!(matrix.get(0, 0), 1);
    assert_eq!(matrix.get(0, 1), 2);
    assert_eq!(matrix.get(3, 0), 3);
    assert_eq!(matrix.get(5, 0), 4);
    assert_eq!(matrix.get(7, 0), 5);
    assert_eq!(matrix.get(9, 0), 6);
    assert_eq!(matrix.get(0, 2), 0); // missing
    assert_eq!(matrix.get(2, 0), 0); // missing
    assert_eq!(matrix.get(4, 0), 0); // missing

    // Test dense iteration
    let elements: Vec<_> = matrix.iter_dense().collect();
    assert_eq!(elements.len(), 100);

    // Verify specific positions in row-major order
    assert_eq!(elements[0], 1); // row 0, col 0
    assert_eq!(elements[1], 2); // row 0, col 1
    assert_eq!(elements[25], 0); // row 2, col 5
    assert_eq!(elements[30], 3); // row 3, col 0
    assert_eq!(elements[50], 4); // row 5, col 0
    assert_eq!(elements[87], 0); // row 8, col 7
    assert_eq!(elements[98], 0); // row 9, col 8
    assert_eq!(elements[90], 6); // row 9, col 0
}

#[test]
fn test_index_trait() {
    // Verify that Index trait implementation matches dense iteration in row-major order
    let data = vec![1, 2, 3, 4];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix::new(data, indptr, 4);

    let dense_elements: Vec<_> = matrix.iter_dense().collect();

    // Index should match dense iteration for all positions
    for i in 0..matrix.num_rows() * matrix.num_cols() {
        assert_eq!(matrix[i], dense_elements[i]);
    }

    // Test specific index positions
    assert_eq!(matrix[0], 1); // row 0, col 0
    assert_eq!(matrix[1], 2); // row 0, col 1
    assert_eq!(matrix[2], 0); // row 0, col 2 (missing)
    assert_eq!(matrix[3], 0); // row 0, col 3 (missing)
    assert_eq!(matrix[4], 3); // row 1, col 0
    assert_eq!(matrix[5], 4); // row 1, col 1
    assert_eq!(matrix[6], 0); // row 1, col 2 (missing)
    assert_eq!(matrix[7], 0); // row 1, col 3 (missing)

    // Test out of bounds access
    assert_eq!(matrix[8], 0); // beyond matrix bounds
}

#[test]
fn test_index_trait_non_default() {
    // Verify that Index trait works correctly with non-default zero values
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    struct TestStruct(i32);

    impl Default for TestStruct {
        fn default() -> Self {
            TestStruct(-999)
        }
    }

    let data = vec![TestStruct(1), TestStruct(2)];
    let indptr = vec![0, 2];
    let matrix = SparseMatrix::new(data, indptr, 2);

    assert_eq!(matrix[0], TestStruct(1)); // row 0, col 0
    assert_eq!(matrix[1], TestStruct(2)); // row 0, col 1
    assert_eq!(matrix[2], TestStruct(-999)); // row 1, col 0 (missing)
    assert_eq!(matrix[3], TestStruct(-999)); // row 1, col 1 (missing)
}
