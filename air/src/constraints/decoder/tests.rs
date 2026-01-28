//! Tests for decoder constraints.

use super::{CONSTRAINT_DEGREES, NUM_CONSTRAINTS};

// CONSTRAINT COUNT TEST
// ================================================================================================

#[test]
fn test_array_sizes() {
    // 7 op bits binary + 2 extra columns + 3 op-bit group constraints + 3 batch flags
    // + 14 general constraints
    // + 1 sp binary + 2 sp transitions + 5 group count constraints
    // + 2 op group decoding + 4 op index constraints + 9 batch flag constraints
    // + 3 block address constraints + 1 control flow constraint
    assert_eq!(NUM_CONSTRAINTS, 56);
    assert_eq!(CONSTRAINT_DEGREES.len(), NUM_CONSTRAINTS);
}
