//! Tests for operation flags.

use miden_core::{Felt, ONE, Operation, ZERO, field::PrimeCharacteristicRing};

use super::{
    DEGREE_4_OPCODE_ENDS, DEGREE_4_OPCODE_STARTS, DEGREE_5_OPCODE_ENDS, DEGREE_5_OPCODE_STARTS,
    DEGREE_6_OPCODE_ENDS, DEGREE_6_OPCODE_STARTS, DEGREE_7_OPCODE_ENDS, DEGREE_7_OPCODE_STARTS,
    NUM_DEGREE_4_OPS, NUM_DEGREE_5_OPS, NUM_DEGREE_6_OPS, NUM_DEGREE_7_OPS, OpFlags,
    generate_test_row, get_op_index,
};
use crate::trace::decoder::IS_LOOP_FLAG_COL_IDX;

// HELPER
// ================================================================================================

/// Creates OpFlags from an opcode using a generated test row.
fn op_flags_for_opcode(opcode: usize) -> OpFlags<Felt> {
    let row = generate_test_row(opcode);
    OpFlags::new(&row)
}

// BASIC INDEX TESTS
// ================================================================================================

#[test]
fn test_get_op_index_degree7() {
    // Degree 7 operations have opcodes 0-63, index maps directly
    assert_eq!(get_op_index(Operation::Noop.op_code()), 0);
    assert_eq!(get_op_index(Operation::Swap.op_code()), Operation::Swap.op_code() as usize);
    assert_eq!(get_op_index(Operation::Pad.op_code()), Operation::Pad.op_code() as usize);
}

#[test]
fn test_get_op_index_degree6() {
    // Degree 6 operations have opcodes 64-79, but only even opcodes are used
    assert_eq!(get_op_index(Operation::U32add.op_code()), 0);
    assert_eq!(get_op_index(Operation::U32sub.op_code()), 1);
    assert_eq!(get_op_index(Operation::U32mul.op_code()), 2);
    assert_eq!(get_op_index(Operation::U32div.op_code()), 3);
    assert_eq!(get_op_index(Operation::U32split.op_code()), 4);
    assert_eq!(get_op_index(Operation::U32assert2(Felt::ZERO).op_code()), 5);
    assert_eq!(get_op_index(Operation::U32add3.op_code()), 6);
    assert_eq!(get_op_index(Operation::U32madd.op_code()), 7);
}

#[test]
fn test_get_op_index_degree5() {
    // Degree 5 operations have opcodes 80-95
    assert_eq!(get_op_index(Operation::HPerm.op_code()), 0);
    assert_eq!(get_op_index(Operation::MpVerify(Felt::ZERO).op_code()), 1);
    assert_eq!(get_op_index(Operation::Split.op_code()), 4);
    assert_eq!(get_op_index(Operation::Loop.op_code()), 5);
    assert_eq!(get_op_index(Operation::Span.op_code()), 6);
    assert_eq!(get_op_index(Operation::Join.op_code()), 7);
    assert_eq!(get_op_index(Operation::Push(Felt::ONE).op_code()), 11);
}

#[test]
fn test_get_op_index_degree4() {
    // Degree 4 operations have opcodes 96-127, only every 4th opcode is used
    assert_eq!(get_op_index(Operation::MrUpdate.op_code()), 0);
    assert_eq!(get_op_index(Operation::CryptoStream.op_code()), 1);
    assert_eq!(get_op_index(Operation::SysCall.op_code()), 2);
    assert_eq!(get_op_index(Operation::Call.op_code()), 3);
    assert_eq!(get_op_index(Operation::End.op_code()), 4);
    assert_eq!(get_op_index(Operation::Repeat.op_code()), 5);
    assert_eq!(get_op_index(Operation::Respan.op_code()), 6);
    assert_eq!(get_op_index(Operation::Halt.op_code()), 7);
}

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_DEGREE_7_OPS, 64);
    assert_eq!(NUM_DEGREE_6_OPS, 8);
    assert_eq!(NUM_DEGREE_5_OPS, 16);
    assert_eq!(NUM_DEGREE_4_OPS, 8);
}

// DEGREE 7 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 7 opcode, exactly one flag is set to ONE.
#[test]
fn degree_7_op_flags() {
    for opcode in DEGREE_7_OPCODE_STARTS..=DEGREE_7_OPCODE_ENDS {
        let op_flags = op_flags_for_opcode(opcode);

        // Expected index in the degree 7 flags array
        let expected_idx = get_op_index(opcode as u8);

        // Check degree 7 flags: exactly one should be ONE
        for (i, &flag) in op_flags.degree7_op_flags().iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 7 flag {} should be ONE for opcode {}", i, opcode);
            } else {
                assert_eq!(flag, ZERO, "Degree 7 flag {} should be ZERO for opcode {}", i, opcode);
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree6_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 6 flag {} should be ZERO for degree 7 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree5_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 5 flag {} should be ZERO for degree 7 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree4_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 4 flag {} should be ZERO for degree 7 opcode {}",
                i, opcode
            );
        }
    }
}

// DEGREE 6 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 6 opcode, exactly one flag is set to ONE.
#[test]
fn degree_6_op_flags() {
    // Degree 6 uses even opcodes only (64, 66, 68, ...)
    for opcode in (DEGREE_6_OPCODE_STARTS..=DEGREE_6_OPCODE_ENDS).step_by(2) {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 6 flags
        for (i, &flag) in op_flags.degree6_op_flags().iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 6 flag {} should be ONE for opcode {}", i, opcode);
            } else {
                assert_eq!(flag, ZERO, "Degree 6 flag {} should be ZERO for opcode {}", i, opcode);
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 7 flag {} should be ZERO for degree 6 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree5_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 5 flag {} should be ZERO for degree 6 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree4_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 4 flag {} should be ZERO for degree 6 opcode {}",
                i, opcode
            );
        }
    }
}

// DEGREE 5 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 5 opcode, exactly one flag is set to ONE.
#[test]
fn degree_5_op_flags() {
    for opcode in DEGREE_5_OPCODE_STARTS..=DEGREE_5_OPCODE_ENDS {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 5 flags
        for (i, &flag) in op_flags.degree5_op_flags().iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 5 flag {} should be ONE for opcode {}", i, opcode);
            } else {
                assert_eq!(flag, ZERO, "Degree 5 flag {} should be ZERO for opcode {}", i, opcode);
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 7 flag {} should be ZERO for degree 5 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree6_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 6 flag {} should be ZERO for degree 5 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree4_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 4 flag {} should be ZERO for degree 5 opcode {}",
                i, opcode
            );
        }
    }
}

// DEGREE 4 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 4 opcode, exactly one flag is set to ONE.
#[test]
fn degree_4_op_flags() {
    // Degree 4 uses every 4th opcode (96, 100, 104, ...)
    for opcode in (DEGREE_4_OPCODE_STARTS..=DEGREE_4_OPCODE_ENDS).step_by(4) {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 4 flags
        for (i, &flag) in op_flags.degree4_op_flags().iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 4 flag {} should be ONE for opcode {}", i, opcode);
            } else {
                assert_eq!(flag, ZERO, "Degree 4 flag {} should be ZERO for opcode {}", i, opcode);
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 7 flag {} should be ZERO for degree 4 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree6_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 6 flag {} should be ZERO for degree 4 opcode {}",
                i, opcode
            );
        }
        for (i, &flag) in op_flags.degree5_op_flags().iter().enumerate() {
            assert_eq!(
                flag, ZERO,
                "Degree 5 flag {} should be ZERO for degree 4 opcode {}",
                i, opcode
            );
        }
    }
}

// COMPOSITE FLAG TESTS
// ================================================================================================

/// Tests no_shift composite flags for operations that don't shift the stack.
#[test]
fn composite_no_shift_flags() {
    // Operations where all 16 positions remain unchanged
    let no_shift_ops =
        [Operation::MpVerify(ZERO), Operation::Span, Operation::Halt, Operation::Emit];

    for op in no_shift_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());

        // All positions should have no_shift = ONE
        for i in 0..16 {
            assert_eq!(
                op_flags.no_shift_at(i),
                ONE,
                "no_shift_at({}) should be ONE for {:?}",
                i,
                op
            );
        }

        // No shifts
        assert_eq!(op_flags.right_shift(), ZERO);
        assert_eq!(op_flags.left_shift(), ZERO);
    }
}

/// Tests composite flags for INCR (no shift from position 1 onwards).
#[test]
fn composite_incr_flags() {
    let op_flags = op_flags_for_opcode(Operation::Incr.op_code().into());

    // Position 0 changes, positions 1-15 don't
    assert_eq!(op_flags.no_shift_at(0), ZERO);
    for i in 1..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({}) should be ONE for INCR", i);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests composite flags for SWAP (no shift from position 2 onwards).
#[test]
fn composite_swap_flags() {
    let op_flags = op_flags_for_opcode(Operation::Swap.op_code().into());

    assert_eq!(op_flags.no_shift_at(0), ZERO);
    assert_eq!(op_flags.no_shift_at(1), ZERO);
    for i in 2..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({}) should be ONE for SWAP", i);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests composite flags for HPERM (no shift from position 12 onwards).
#[test]
fn composite_hperm_flags() {
    let op_flags = op_flags_for_opcode(Operation::HPerm.op_code().into());

    for i in 0..12 {
        assert_eq!(op_flags.no_shift_at(i), ZERO, "no_shift_at({}) should be ZERO for HPERM", i);
    }
    for i in 12..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({}) should be ONE for HPERM", i);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests left shift composite flags for LOOP operation.
#[test]
fn composite_loop_left_shift() {
    let op_flags = op_flags_for_opcode(Operation::Loop.op_code().into());

    // LOOP shifts the stack left
    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE, "left_shift_at({}) should be ONE for LOOP", i);
    }
    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ONE);
}

/// Tests left shift composite flags for AND operation (shifts from position 2).
#[test]
fn composite_and_left_shift() {
    let op_flags = op_flags_for_opcode(Operation::And.op_code().into());

    // AND shifts left from position 2
    assert_eq!(op_flags.left_shift_at(1), ZERO);
    for i in 2..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE, "left_shift_at({}) should be ONE for AND", i);
    }

    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.right_shift(), ZERO);
}

/// Tests right shift flags for DUP1.
#[test]
fn composite_dup1_right_shift() {
    let op_flags = op_flags_for_opcode(Operation::Dup1.op_code().into());

    // DUP1 shifts the entire stack right
    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ONE, "right_shift_at({}) should be ONE for DUP1", i);
    }
    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ONE);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests right shift flags for PUSH.
#[test]
fn composite_push_right_shift() {
    let op_flags = op_flags_for_opcode(Operation::Push(ONE).op_code().into());

    // PUSH shifts the entire stack right
    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ONE, "right_shift_at({}) should be ONE for PUSH", i);
    }

    assert_eq!(op_flags.right_shift(), ONE);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests END operation with and without loop flag.
#[test]
fn composite_end_flags() {
    // END without loop flag: no shift
    let op_flags = op_flags_for_opcode(Operation::End.op_code().into());

    for i in 0..16 {
        assert_eq!(
            op_flags.no_shift_at(i),
            ONE,
            "no_shift_at({}) should be ONE for END (no loop)",
            i
        );
    }
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ONE);

    // END with loop flag: left shift (need to modify the row)
    let mut row = generate_test_row(Operation::End.op_code().into());
    row.decoder[IS_LOOP_FLAG_COL_IDX] = ONE;
    let op_flags_loop = OpFlags::new(&row);

    for i in 0..16 {
        assert_eq!(
            op_flags_loop.no_shift_at(i),
            ZERO,
            "no_shift_at({}) should be ZERO for END (with loop)",
            i
        );
    }
    for i in 1..16 {
        assert_eq!(
            op_flags_loop.left_shift_at(i),
            ONE,
            "left_shift_at({}) should be ONE for END (with loop)",
            i
        );
    }
    assert_eq!(op_flags_loop.left_shift(), ONE);
    assert_eq!(op_flags_loop.control_flow(), ONE);
}

/// Tests SWAPW2 flags (positions 4-7 and 12-15 remain, others swap).
#[test]
fn composite_swapw2_flags() {
    let op_flags = op_flags_for_opcode(Operation::SwapW2.op_code().into());

    // Positions 4-7 and 12-15 should be no_shift (words that stay in place)
    for i in [0, 1, 2, 3, 8, 9, 10, 11] {
        assert_eq!(op_flags.no_shift_at(i), ZERO, "no_shift_at({}) should be ZERO for SWAPW2", i);
    }
    for i in [4, 5, 6, 7, 12, 13, 14, 15] {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({}) should be ONE for SWAPW2", i);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests control flow flag.
#[test]
fn control_flow_flag() {
    // Control flow operations
    let cf_ops = [
        Operation::Span,
        Operation::Join,
        Operation::Split,
        Operation::Loop,
        Operation::End,
        Operation::Repeat,
        Operation::Respan,
        Operation::Halt,
        Operation::Call,
        Operation::SysCall,
    ];

    for op in cf_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());
        assert_eq!(op_flags.control_flow(), ONE, "control_flow should be ONE for {:?}", op);
    }

    // Non-control flow operations
    let non_cf_ops = [
        Operation::Add,
        Operation::Mul,
        Operation::Swap,
        Operation::Dup0,
        Operation::U32add,
        Operation::HPerm,
        Operation::MpVerify(ZERO),
    ];

    for op in non_cf_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());
        assert_eq!(op_flags.control_flow(), ZERO, "control_flow should be ZERO for {:?}", op);
    }
}

/// Tests u32_rc_op flag for u32 operations.
#[test]
fn u32_rc_op_flag() {
    // U32 operations that require range checks (degree 6)
    let u32_ops = [
        Operation::U32add,
        Operation::U32sub,
        Operation::U32mul,
        Operation::U32div,
        Operation::U32split,
        Operation::U32assert2(ZERO),
        Operation::U32add3,
        Operation::U32madd,
    ];

    for op in u32_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());
        assert_eq!(op_flags.u32_rc_op(), ONE, "u32_rc_op should be ONE for {:?}", op);
    }

    // Non-u32 operations
    let non_u32_ops = [
        Operation::Add,
        Operation::Mul,
        Operation::And, // Bitwise AND is degree 7, not u32
    ];

    for op in non_u32_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());
        assert_eq!(op_flags.u32_rc_op(), ZERO, "u32_rc_op should be ZERO for {:?}", op);
    }
}
