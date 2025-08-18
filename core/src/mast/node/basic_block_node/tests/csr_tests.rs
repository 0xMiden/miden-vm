use std::vec::Vec;

use crate::mast::node::basic_block_node::csr::SparseMatrix;

#[test]
fn test_empty_matrix() {
    let matrix = SparseMatrix::<i32>::empty();
    assert_eq!(matrix.num_rows(), 0);
    assert_eq!(matrix.num_cols(), 0);
    assert!(matrix.is_empty());
    assert_eq!(matrix.len(), 0);
}

#[test]
fn test_matrix_creation() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4]; // 2 rows, with 2 elements each
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.num_rows(), 2);
    assert_eq!(matrix.num_cols(), 4);
    assert_eq!(matrix.len(), 4);
    assert!(!matrix.is_empty());
}

#[test]
fn test_get_existing_element() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.get(0, 0), 1);
    assert_eq!(matrix.get(0, 2), 2);
    assert_eq!(matrix.get(1, 1), 3);
    assert_eq!(matrix.get(1, 3), 4);
}

#[test]
fn test_get_missing_element() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.get(0, 1), 0);
    assert_eq!(matrix.get(0, 3), 0);
    assert_eq!(matrix.get(1, 0), 0);
    assert_eq!(matrix.get(1, 2), 0);
}

#[test]
fn test_set_existing_element() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let mut matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.set(0, 0, 5), Some(1));
    assert_eq!(matrix.get(0, 0), 5);
    assert_eq!(matrix.set(1, 3, 6), Some(4));
    assert_eq!(matrix.get(1, 3), 6);
}

#[test]
fn test_set_new_element() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let mut matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.set(0, 1, 10), None);
    assert_eq!(matrix.get(0, 1), 10);
    assert_eq!(matrix.len(), 5);

    // Check that data and indices are updated correctly
    assert_eq!(matrix.data, vec![1, 10, 2, 3, 4]);
    assert_eq!(matrix.indices, vec![0, 1, 2, 1, 3]);
    assert_eq!(matrix.indptr, vec![0, 3, 5]);
}

#[test]
fn test_set_to_zero() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let mut matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    assert_eq!(matrix.set(0, 0, 0), Some(1));
    assert_eq!(matrix.get(0, 0), 0);
    // The length should decrease by 1 when we set an element to zero
    assert_eq!(matrix.len(), 3);

    // Check that element was removed
    // With binary search and proper removal, the indptr should be updated correctly
    assert_eq!(matrix.data, vec![2, 3, 4]);
    assert_eq!(matrix.indices, vec![2, 1, 3]);
    assert_eq!(matrix.indptr, vec![0, 1, 3]);
}

#[test]
fn test_iter_nonzero() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    let mut iter = matrix.iter();
    assert_eq!(iter.next(), Some((0, 0, 1)));
    assert_eq!(iter.next(), Some((0, 2, 2)));
    assert_eq!(iter.next(), Some((1, 1, 3)));
    assert_eq!(iter.next(), Some((1, 3, 4)));
    assert_eq!(iter.next(), None);
}

#[test]
fn test_iter_dense() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    let mut iter = matrix.iter_dense();
    assert_eq!(iter.next(), Some(1)); // row 0, col 0
    assert_eq!(iter.next(), Some(0)); // row 0, col 1 (missing, default)zz
    assert_eq!(iter.next(), Some(2)); // row 0, col 2
    assert_eq!(iter.next(), Some(0)); // row 0, col 3 (missing, default)
    assert_eq!(iter.next(), Some(0)); // row 1, col 0 (missing, default)
    assert_eq!(iter.next(), Some(3)); // row 1, col 1
    assert_eq!(iter.next(), Some(0)); // row 1, col 2 (missing, default)
    assert_eq!(iter.next(), Some(4)); // row 1, col 3
    assert_eq!(iter.next(), None);
}

#[test]
fn test_sparse_matrix_with_non_default_zero() {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    struct TestStruct(i32);

    impl Default for TestStruct {
        fn default() -> Self {
            TestStruct(-999)
        }
    }

    let data = vec![TestStruct(1), TestStruct(2)];
    let indices = vec![0, 1];
    let indptr = vec![0, 2]; // 1 row only
    let matrix = SparseMatrix { data, indices, indptr, cols: 2, default: TestStruct(-999) };

    assert_eq!(matrix.num_rows(), 1);
    assert_eq!(matrix.get(0, 0), TestStruct(1));
    assert_eq!(matrix.get(0, 1), TestStruct(2));

    // Test out of bounds rows should also return default
    // Note: This should work as long as we don't panic on invalid row access
    // The matrix has 1 row, but we can still query row 1 (which will be empty)
}

#[test]
fn test_sparse_matrix_large() {
    let mut matrix = SparseMatrix::<i32>::empty();
    // Set up for a 10x10 matrix
    matrix.cols = 10;

    // Initialize indptr for 10 rows
    matrix.indptr = vec![0; 11]; // 10 rows + 1
    matrix.default = 0;

    // Create a 10x10 matrix with some elements
    matrix.set(0, 0, 1);
    matrix.set(0, 5, 2);
    matrix.set(3, 3, 3);
    matrix.set(5, 1, 4);
    matrix.set(7, 8, 5);
    matrix.set(9, 9, 6);

    assert_eq!(matrix.num_rows(), 10);
    assert_eq!(matrix.num_cols(), 10);
    assert_eq!(matrix.len(), 6);

    // Test some elements
    assert_eq!(matrix.get(0, 0), 1);
    assert_eq!(matrix.get(0, 5), 2);
    assert_eq!(matrix.get(3, 3), 3);
    assert_eq!(matrix.get(5, 1), 4);
    assert_eq!(matrix.get(7, 8), 5);
    assert_eq!(matrix.get(9, 9), 6);

    // Test missing elements
    assert_eq!(matrix.get(0, 1), 0);
    assert_eq!(matrix.get(2, 2), 0);
    assert_eq!(matrix.get(4, 4), 0);

    // Test dense iteration
    let elements: Vec<_> = matrix.iter_dense().collect();
    assert_eq!(elements.len(), 100);

    // Check some specific positions
    assert_eq!(elements[0], 1); // row 0, col 0
    assert_eq!(elements[5], 2); // row 0, col 5
    assert_eq!(elements[35], 0); // row 3, col 5 (should be 0)
    assert_eq!(elements[33], 3); // row 3, col 3
    assert_eq!(elements[51], 4); // row 5, col 1
    assert_eq!(elements[87], 0); // row 8, col 7 (should be 0)
    assert_eq!(elements[98], 0); // row 9, col 8 (should be 0)
    assert_eq!(elements[99], 6); // row 9, col 9
}

#[test]
fn test_index_trait() {
    let data = vec![1, 2, 3, 4];
    let indices = vec![0, 2, 1, 3];
    let indptr = vec![0, 2, 4];
    let matrix = SparseMatrix { data, indices, indptr, cols: 4, default: 0 };

    // Test that Index returns the same values as DenseIter in row-major order
    let dense_elements: Vec<_> = matrix.iter_dense().collect();
    
    for i in 0..matrix.num_rows() * matrix.num_cols() {
        assert_eq!(matrix[i], dense_elements[i]);
    }
    
    // Test specific elements
    assert_eq!(matrix[0], 1);  // row 0, col 0
    assert_eq!(matrix[1], 0);  // row 0, col 1 (missing)
    assert_eq!(matrix[2], 2);  // row 0, col 2
    assert_eq!(matrix[3], 0);  // row 0, col 3 (missing)
    assert_eq!(matrix[4], 0);  // row 1, col 0 (missing)
    assert_eq!(matrix[5], 3);  // row 1, col 1
    assert_eq!(matrix[6], 0);  // row 1, col 2 (missing)
    assert_eq!(matrix[7], 4);  // row 1, col 3
    
    // Test out of bounds
    assert_eq!(matrix[8], 0);  // beyond matrix bounds
}

#[test]
fn test_index_trait_non_default() {
    #[derive(Debug, PartialEq, Eq, Copy, Clone)]
    struct TestStruct(i32);

    impl Default for TestStruct {
        fn default() -> Self {
            TestStruct(-999)
        }
    }

    let data = vec![TestStruct(1), TestStruct(2)];
    let indices = vec![0, 1];
    let indptr = vec![0, 2];
    let matrix = SparseMatrix { data, indices, indptr, cols: 2, default: TestStruct(-999) };

    // Test Index with non-default values
    assert_eq!(matrix[0], TestStruct(1));  // row 0, col 0
    assert_eq!(matrix[1], TestStruct(2));  // row 0, col 1
    assert_eq!(matrix[2], TestStruct(-999));  // row 1, col 0 (missing)
    assert_eq!(matrix[3], TestStruct(-999));  // row 1, col 1 (missing)
}
