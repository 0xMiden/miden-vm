use miden_core::{ONE, Operation, ZERO};

use super::{
    DECODER_TRACE_OFFSET, DEGREE_4_OPCODE_ENDS, DEGREE_4_OPCODE_STARTS, DEGREE_6_OPCODE_ENDS,
    DEGREE_6_OPCODE_STARTS, DEGREE_7_OPCODE_ENDS, DEGREE_7_OPCODE_STARTS, NUM_DEGREE_4_OPS,
    NUM_DEGREE_5_OPS, NUM_DEGREE_6_OPS, NUM_DEGREE_7_OPS, OpFlags, generate_evaluation_frame,
};
use crate::{stack::op_flags::get_op_index, trace::decoder::IS_LOOP_FLAG_COL_IDX};

/// Asserts the op flag to ONE for degree 7 operation which is being executed in the current
/// frame; assert all the other operation flags to ZERO as they are not present in the current
/// trace.
#[test]
fn degree_7_op_flags() {
    for i in DEGREE_7_OPCODE_STARTS..=DEGREE_7_OPCODE_ENDS {
        // frame initialized with a degree 7 operation using it's unique opcode.
        let frame = generate_evaluation_frame(i);

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        // index of the operation flag in the op_flag's degree seven array.
        let idx_in_degree7_flags = get_op_index(i as u8);

        // Asserts operation flag of degree 7 operation being executed to ONE.
        assert_eq!(op_flags.degree7_op_flags[idx_in_degree7_flags], ONE);

        // Asserts operation flags not present in the trace to ZERO.
        for i in 0..NUM_DEGREE_7_OPS {
            if i != idx_in_degree7_flags {
                assert_eq!(op_flags.degree7_op_flags[i], ZERO)
            }
        }

        // Asserts all degree 6 operation flags to ZERO as the input operation is of degree 7.
        for i in 0..NUM_DEGREE_6_OPS {
            assert_eq!(op_flags.degree6_op_flags[i], ZERO)
        }

        // Asserts all degree 5 operation flags to ZERO as the input operation is of degree 7.
        for i in 0..NUM_DEGREE_5_OPS {
            assert_eq!(op_flags.degree5_op_flags[i], ZERO)
        }

        // Asserts all degree 4 operation flags to ZERO as the input operation is of degree 7.
        for i in 0..NUM_DEGREE_4_OPS {
            assert_eq!(op_flags.degree4_op_flags[i], ZERO)
        }
    }
}

/// Asserts the op flag to ONE for degree 6 operation which is being executed in the current
/// frame; assert all the other operation flags to ZERO as they are not present in the current
/// trace.
#[test]
fn degree_6_op_flags() {
    for i in (DEGREE_6_OPCODE_STARTS..=DEGREE_6_OPCODE_ENDS).step_by(2) {
        // frame initialised with a degree 6 operation using it's unique opcode.
        let frame = generate_evaluation_frame(i);

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        // index of the operation flag in the op_flag's degree six array.
        let idx_in_degree6_flags = get_op_index(i as u8);

        // Asserts operation flag of degree 6 operation being executed to ONE.
        assert_eq!(op_flags.degree6_op_flags[idx_in_degree6_flags], ONE);

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 6.
        for i in 0..NUM_DEGREE_7_OPS {
            assert_eq!(op_flags.degree7_op_flags[i], ZERO)
        }

        // Except the operation being executed, all the degree 6 operation flag should be ZERO.
        for i in 0..NUM_DEGREE_6_OPS {
            if i != idx_in_degree6_flags {
                assert_eq!(op_flags.degree6_op_flags[i], ZERO)
            }
        }

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 6.
        for i in 0..NUM_DEGREE_5_OPS {
            assert_eq!(op_flags.degree5_op_flags[i], ZERO)
        }

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 6.
        for i in 0..NUM_DEGREE_4_OPS {
            assert_eq!(op_flags.degree4_op_flags[i], ZERO)
        }
    }
}

/// Asserts the op flag to ONE for degree 4 operation which is being executed in the current
/// frame; assert all the other operation flags to ZERO as they are not present in the current
/// trace.
#[test]
fn degree_4_op_flags() {
    for i in (DEGREE_4_OPCODE_STARTS..=DEGREE_4_OPCODE_ENDS).step_by(4) {
        // frame initialised with a degree 4 operation using it's unique opcode.
        let frame = generate_evaluation_frame(i);

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        // index of the operation flag in the op_flag's degree four array.
        let idx_in_degree4_flags = get_op_index(i as u8);

        // Asserts that the operation flag of the degree 4 operation being executed is ONE.
        assert_eq!(op_flags.degree4_op_flags[idx_in_degree4_flags], ONE);

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 4.
        for i in 0..NUM_DEGREE_7_OPS {
            assert_eq!(op_flags.degree7_op_flags[i], ZERO)
        }

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 4.
        for i in 0..NUM_DEGREE_6_OPS {
            assert_eq!(op_flags.degree6_op_flags[i], ZERO)
        }

        // Assert operation flags not present in the trace to ZERO as the operation being executed
        // is of degree 4.
        for i in 0..NUM_DEGREE_5_OPS {
            assert_eq!(op_flags.degree5_op_flags[i], ZERO)
        }

        // Except the operation being executed, all the degree 4 operation flags should be ZERO.
        for i in 0..NUM_DEGREE_4_OPS {
            if i != idx_in_degree4_flags {
                assert_eq!(op_flags.degree4_op_flags[i], ZERO)
            }
        }
    }
}

/// Composite flag unit tests.
#[test]
fn composite_flags() {
    // ------ no change 0 ---------------------------------------------------------------------

    let op_no_change_0 =
        [Operation::MpVerify(ZERO), Operation::Span, Operation::Halt, Operation::Emit];
    for op in op_no_change_0 {
        // frame initialised with an op operation.
        let frame = generate_evaluation_frame(op.op_code().into());

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        for i in 0..16 {
            assert_eq!(op_flags.no_shift_at(i), ONE);
        }

        for i in 1..16 {
            assert_eq!(op_flags.left_shift_at(i), ZERO);
        }

        for i in 0..15 {
            assert_eq!(op_flags.right_shift_at(i), ZERO);
        }

        assert_eq!(op_flags.right_shift(), ZERO);
        assert_eq!(op_flags.left_shift(), ZERO);
        assert_eq!(op_flags.top_binary(), ZERO);

        if op == Operation::MpVerify(ZERO) || op == Operation::Emit {
            assert_eq!(op_flags.control_flow(), ZERO);
        } else if op == Operation::Span || op == Operation::Halt {
            assert_eq!(op_flags.control_flow(), ONE);
        } else {
            unreachable!("unexpected op");
        }
    }

    // ------ No change 1 ---------------------------------------------------------------------

    let op = Operation::Incr;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    assert_eq!(op_flags.no_shift_at(0), ZERO);
    for i in 1..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ no change 2 ---------------------------------------------------------------------

    let op_no_change_2 = [Operation::Swap, Operation::U32div];
    for op in op_no_change_2 {
        // frame initialised with an op operation.
        let frame = generate_evaluation_frame(op.op_code().into());

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        assert_eq!(op_flags.no_shift_at(0), ZERO);
        assert_eq!(op_flags.no_shift_at(1), ZERO);
        for i in 2..16 {
            assert_eq!(op_flags.no_shift_at(i), ONE);
        }

        for i in 1..16 {
            assert_eq!(op_flags.left_shift_at(i), ZERO);
        }

        for i in 0..15 {
            assert_eq!(op_flags.right_shift_at(i), ZERO);
        }

        assert_eq!(op_flags.right_shift(), ZERO);
        assert_eq!(op_flags.left_shift(), ZERO);
        assert_eq!(op_flags.control_flow(), ZERO);
        assert_eq!(op_flags.top_binary(), ZERO);
    }

    // ------ no change 4 ---------------------------------------------------------------------

    let op_no_change_4 = [Operation::MrUpdate, Operation::AdvPopW, Operation::Ext2Mul];
    for op in op_no_change_4 {
        // frame initialised with an op operation.
        let frame = generate_evaluation_frame(op.op_code().into());

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        for i in 0..4 {
            assert_eq!(op_flags.no_shift_at(i), ZERO);
        }

        for i in 4..16 {
            assert_eq!(op_flags.no_shift_at(i), ONE);
        }

        for i in 1..16 {
            assert_eq!(op_flags.left_shift_at(i), ZERO);
        }

        for i in 0..15 {
            assert_eq!(op_flags.right_shift_at(i), ZERO);
        }

        assert_eq!(op_flags.right_shift(), ZERO);
        assert_eq!(op_flags.left_shift(), ZERO);
        assert_eq!(op_flags.control_flow(), ZERO);
        assert_eq!(op_flags.top_binary(), ZERO);
    }

    // ------ No change 12 ---------------------------------------------------------------------

    let op = Operation::HPerm;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    assert_eq!(op_flags.no_shift_at(12), ONE);
    for i in 0..12 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ Left shift 1 ---------------------------------------------------------------------

    let op = Operation::Loop;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE);
    }

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.control_flow(), ONE);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ Left shift 2 ---------------------------------------------------------------------

    let op = Operation::And;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    assert_eq!(op_flags.left_shift_at(1), ZERO);
    for i in 2..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE);
    }

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ONE);

    // ------ Left shift 3 ---------------------------------------------------------------------

    let op = Operation::U32add3;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    assert_eq!(op_flags.left_shift_at(1), ZERO);
    assert_eq!(op_flags.left_shift_at(2), ZERO);
    for i in 3..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE);
    }

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ Left shift 5 ---------------------------------------------------------------------

    let op = Operation::MLoadW;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in 0..5 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 5..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE);
    }

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ Right shift 0 ---------------------------------------------------------------------

    let op_no_change_0 = [Operation::MovUp2, Operation::Dup1, Operation::Push(ONE)];
    for op in op_no_change_0 {
        // frame initialised with an op operation.
        let frame = generate_evaluation_frame(op.op_code().into());

        // All the operation flags are generated for the given frame.
        let op_flags = OpFlags::new(&frame);

        for i in 0..14 {
            if op == Operation::MovUp2 {
                if i < 2 {
                    assert_eq!(op_flags.right_shift_at(i), ONE);
                } else {
                    assert_eq!(op_flags.right_shift_at(i), ZERO);
                }
            } else {
                assert_eq!(op_flags.right_shift_at(i), ONE);
            }
        }

        for i in 1..16 {
            assert_eq!(op_flags.left_shift_at(i), ZERO);
        }

        if op == Operation::MovUp2 {
            assert_eq!(op_flags.no_shift_at(0), ZERO);
            assert_eq!(op_flags.no_shift_at(1), ZERO);
            assert_eq!(op_flags.no_shift_at(2), ZERO);

            for i in 3..16 {
                assert_eq!(op_flags.no_shift_at(i), ONE);
            }

            assert_eq!(op_flags.right_shift(), ZERO);
            assert_eq!(op_flags.left_shift(), ZERO);
            assert_eq!(op_flags.control_flow(), ZERO);
        } else {
            for i in 0..16 {
                assert_eq!(op_flags.no_shift_at(i), ZERO);
            }
            assert_eq!(op_flags.right_shift(), ONE);
            assert_eq!(op_flags.left_shift(), ZERO);
            assert_eq!(op_flags.control_flow(), ZERO);
        }
        assert_eq!(op_flags.top_binary(), ZERO);
    }

    // ------ SWAPDX ---------------------------------------------------------------------

    let op = Operation::SwapDW;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ SWAPW2 ---------------------------------------------------------------------

    let op = Operation::SwapW2;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in [0, 1, 2, 3, 8, 9, 10, 11] {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in [4, 5, 6, 7, 12, 13, 14, 15] {
        assert_eq!(op_flags.no_shift_at(i), ONE);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ SWAPW3 ---------------------------------------------------------------------

    let op = Operation::SwapW3;
    // frame initialised with an op operation.
    let frame = generate_evaluation_frame(op.op_code().into());

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in [0, 1, 2, 3, 12, 13, 14, 15] {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 4..12 {
        assert_eq!(op_flags.no_shift_at(i), ONE);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ZERO);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ------ END operation -----------------------------------------------------------------------

    let op = Operation::End;
    // frame initialised with an op operation.
    let mut frame = generate_evaluation_frame(op.op_code().into());

    // ----------------------------------- no shift -----------------------------------------------

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ONE);
    assert_eq!(op_flags.top_binary(), ZERO);

    // ----------------------------------- left shift ---------------------------------------------

    frame.current_mut()[DECODER_TRACE_OFFSET + IS_LOOP_FLAG_COL_IDX] = ONE;

    // All the operation flags are generated for the given frame.
    let op_flags = OpFlags::new(&frame);

    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    for i in 1..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE);
    }

    for i in 0..15 {
        assert_eq!(op_flags.right_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.control_flow(), ONE);
    assert_eq!(op_flags.top_binary(), ZERO);
}
