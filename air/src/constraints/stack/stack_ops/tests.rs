//! Tests for stack manipulation constraints.

use super::NUM_CONSTRAINTS;

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_CONSTRAINTS, 80);
}
