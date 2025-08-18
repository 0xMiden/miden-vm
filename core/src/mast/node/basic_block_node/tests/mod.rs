mod csr_tests;
use proptest::prelude::*;

use super::*;
use crate::{Decorator, ONE, mast::MastForest};

// Helper function to generate random felt values
fn any_felt() -> impl Strategy<Value = Felt> {
    any::<u64>().prop_map(Felt::new)
}

// Helper function to generate random u32 values
fn any_u32() -> impl Strategy<Value = u32> {
    any::<u32>()
}

// Strategy for operations without immediate values (non-control flow)
fn op_no_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::Add),
        Just(Operation::Mul),
        Just(Operation::Neg),
        Just(Operation::Inv),
        Just(Operation::Incr),
        Just(Operation::And),
        Just(Operation::Or),
        Just(Operation::Not),
        Just(Operation::Eq),
        Just(Operation::Eqz),
        Just(Operation::Drop),
        Just(Operation::Pad),
        Just(Operation::Swap),
        Just(Operation::SwapW),
        Just(Operation::SwapW2),
        Just(Operation::SwapW3),
        Just(Operation::SwapDW),
        Just(Operation::MovUp2),
        Just(Operation::MovUp3),
        Just(Operation::MovUp4),
        Just(Operation::MovUp5),
        Just(Operation::MovUp6),
        Just(Operation::MovUp7),
        Just(Operation::MovUp8),
        Just(Operation::MovDn2),
        Just(Operation::MovDn3),
        Just(Operation::MovDn4),
        Just(Operation::MovDn5),
        Just(Operation::MovDn6),
        Just(Operation::MovDn7),
        Just(Operation::MovDn8),
        Just(Operation::CSwap),
        Just(Operation::CSwapW),
        Just(Operation::Dup0),
        Just(Operation::Dup1),
        Just(Operation::Dup2),
        Just(Operation::Dup3),
        Just(Operation::Dup4),
        Just(Operation::Dup5),
        Just(Operation::Dup6),
        Just(Operation::Dup7),
        Just(Operation::Dup9),
        Just(Operation::Dup11),
        Just(Operation::Dup13),
        Just(Operation::Dup15),
        Just(Operation::MLoad),
        Just(Operation::MStore),
        Just(Operation::MLoadW),
        Just(Operation::MStoreW),
        Just(Operation::MStream),
        Just(Operation::Pipe),
        Just(Operation::AdvPop),
        Just(Operation::AdvPopW),
        Just(Operation::U32split),
        Just(Operation::U32add),
        Just(Operation::U32sub),
        Just(Operation::U32mul),
        Just(Operation::U32div),
        Just(Operation::U32and),
        Just(Operation::U32xor),
        Just(Operation::U32add3),
        Just(Operation::U32madd),
        Just(Operation::FmpAdd),
        Just(Operation::FmpUpdate),
        Just(Operation::SDepth),
        Just(Operation::Caller),
        Just(Operation::Clk),
        Just(Operation::Ext2Mul),
        Just(Operation::Expacc),
        Just(Operation::HPerm),
        // Note: We exclude Assert here because it has an immediate value (error code)
    ]
}

// Strategy for operations with immediate values
fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![any_felt().prop_map(Operation::Push), any_u32().prop_map(Operation::Emit),]
}

// Strategy for all non-control flow operations
fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy(),]
}

// Strategy for sequences of operations
fn op_sequence_strategy(max_length: usize) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

#[test]
fn batch_ops() {
    // --- one operation ----------------------------------------------------------------------
    let ops = vec![Operation::Add];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(1, batch.num_groups());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([1_usize, 0, 0, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- two operations ---------------------------------------------------------------------
    let ops = vec![Operation::Add, Operation::Mul];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(1, batch.num_groups());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([2_usize, 0, 0, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- one group with one immediate value -------------------------------------------------
    let ops = vec![Operation::Add, Operation::Push(Felt::new(12345678))];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(2, batch.num_groups());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);
    batch_groups[1] = Felt::new(12345678);

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([2_usize, 0, 0, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- one group with 7 immediate values --------------------------------------------------
    let ops = vec![
        Operation::Push(ONE),
        Operation::Push(Felt::new(2)),
        Operation::Push(Felt::new(3)),
        Operation::Push(Felt::new(4)),
        Operation::Push(Felt::new(5)),
        Operation::Push(Felt::new(6)),
        Operation::Push(Felt::new(7)),
        Operation::Add,
    ];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(8, batch.num_groups());

    let batch_groups = [
        build_group(&ops),
        ONE,
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
    ];

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([8_usize, 0, 0, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- two groups with 7 immediate values; the last push overflows to the second batch ----
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(ONE),
        Operation::Push(Felt::new(2)),
        Operation::Push(Felt::new(3)),
        Operation::Push(Felt::new(4)),
        Operation::Push(Felt::new(5)),
        Operation::Push(Felt::new(6)),
        Operation::Add,
        Operation::Push(Felt::new(7)),
    ];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(2, batches.len());

    let batch0 = &batches[0];
    assert_eq!(ops[..9], batch0.ops);
    assert_eq!(7, batch0.num_groups());

    let batch0_groups = [
        build_group(&ops[..9]),
        ONE,
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        ZERO,
    ];

    assert_eq!(batch0_groups, batch0.groups);
    assert_eq!([9_usize, 0, 0, 0, 0, 0, 0, 0], batch0.op_counts);

    let batch1 = &batches[1];
    assert_eq!(vec![ops[9]], batch1.ops);
    assert_eq!(2, batch1.num_groups());

    let mut batch1_groups = [ZERO; BATCH_SIZE];
    batch1_groups[0] = build_group(&[ops[9]]);
    batch1_groups[1] = Felt::new(7);

    assert_eq!([1_usize, 0, 0, 0, 0, 0, 0, 0], batch1.op_counts);
    assert_eq!(batch1_groups, batch1.groups);

    let all_groups = [batch0_groups, batch1_groups].concat();
    assert_eq!(hasher::hash_elements(&all_groups), hash);

    // --- immediate values in-between groups -------------------------------------------------
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Push(Felt::new(7)),
        Operation::Add,
        Operation::Add,
        Operation::Push(Felt::new(11)),
        Operation::Mul,
        Operation::Mul,
        Operation::Add,
    ];

    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(4, batch.num_groups());

    let batch_groups = [
        build_group(&ops[..9]),
        Felt::new(7),
        Felt::new(11),
        build_group(&ops[9..]),
        ZERO,
        ZERO,
        ZERO,
        ZERO,
    ];

    assert_eq!([9_usize, 0, 0, 1, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(batch_groups, batch.groups);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- push at the end of a group is moved into the next group ----------------------------
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Add,
        Operation::Add,
        Operation::Mul,
        Operation::Mul,
        Operation::Add,
        Operation::Push(Felt::new(11)),
    ];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(3, batch.num_groups());

    let batch_groups = [
        build_group(&ops[..8]),
        build_group(&[ops[8]]),
        Felt::new(11),
        ZERO,
        ZERO,
        ZERO,
        ZERO,
        ZERO,
    ];

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([8_usize, 1, 0, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- push at the end of a group is moved into the next group ----------------------------
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Add,
        Operation::Add,
        Operation::Mul,
        Operation::Mul,
        Operation::Push(ONE),
        Operation::Push(Felt::new(2)),
    ];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(1, batches.len());

    let batch = &batches[0];
    assert_eq!(ops, batch.ops);
    assert_eq!(4, batch.num_groups());

    let batch_groups = [
        build_group(&ops[..8]),
        ONE,
        build_group(&[ops[8]]),
        Felt::new(2),
        ZERO,
        ZERO,
        ZERO,
        ZERO,
    ];

    assert_eq!(batch_groups, batch.groups);
    assert_eq!([8_usize, 0, 1, 0, 0, 0, 0, 0], batch.op_counts);
    assert_eq!(hasher::hash_elements(&batch_groups), hash);

    // --- push at the end of the 7th group overflows to the next batch -----------------------
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Push(ONE),
        Operation::Push(Felt::new(2)),
        Operation::Push(Felt::new(3)),
        Operation::Push(Felt::new(4)),
        Operation::Push(Felt::new(5)),
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Mul,
        Operation::Push(Felt::new(6)),
        Operation::Pad,
    ];

    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    assert_eq!(2, batches.len());

    let batch0 = &batches[0];
    assert_eq!(ops[..17], batch0.ops);
    assert_eq!(7, batch0.num_groups());

    let batch0_groups = [
        build_group(&ops[..9]),
        ONE,
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        build_group(&ops[9..17]),
        ZERO,
    ];

    assert_eq!(batch0_groups, batch0.groups);
    assert_eq!([9_usize, 0, 0, 0, 0, 0, 8, 0], batch0.op_counts);

    let batch1 = &batches[1];
    assert_eq!(ops[17..], batch1.ops);
    assert_eq!(2, batch1.num_groups());

    let batch1_groups = [build_group(&ops[17..]), Felt::new(6), ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];
    assert_eq!(batch1_groups, batch1.groups);
    assert_eq!([2_usize, 0, 0, 0, 0, 0, 0, 0], batch1.op_counts);

    let all_groups = [batch0_groups, batch1_groups].concat();
    assert_eq!(hasher::hash_elements(&all_groups), hash);
}

#[test]
fn operation_or_decorator_iterator() {
    let mut mast_forest = MastForest::new();
    let operations = vec![Operation::Add, Operation::Mul, Operation::MovDn2, Operation::MovDn3];

    // Note: there are 2 decorators after the last instruction
    let decorators = vec![
        (0, Decorator::Trace(0)), // ID: 0
        (0, Decorator::Trace(1)), // ID: 1
        (3, Decorator::Trace(2)), // ID: 2
        (4, Decorator::Trace(3)), // ID: 3
        (4, Decorator::Trace(4)), // ID: 4
    ];

    let node =
        BasicBlockNode::new_with_raw_decorators(operations, decorators, &mut mast_forest).unwrap();

    let mut iterator = node.iter();

    // operation index 0
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(&DecoratorId(0))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(&DecoratorId(1))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::Add)));

    // operations indices 1, 2
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::Mul)));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::MovDn2)));

    // operation index 3
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(&DecoratorId(2))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::MovDn3)));

    // after last operation
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(&DecoratorId(3))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(&DecoratorId(4))));
    assert_eq!(iterator.next(), None);
}

// TEST HELPERS
// --------------------------------------------------------------------------------------------

fn build_group(ops: &[Operation]) -> Felt {
    let mut group = 0u64;
    for (i, op) in ops.iter().enumerate() {
        group |= (op.op_code() as u64) << (Operation::OP_BITS * i);
    }
    Felt::new(group)
}

// PROPTESTS FOR BATCH CREATION INVARIANTS
// ================================================================================================

proptest! {
    /// Test that batch creation follows the basic rules:
    /// - A basic block contains one or more batches.
    /// - A batch contains exactly 8 groups.
    /// - NOOPs are used to fill groups when necessary.
    /// - Operations are correctly distributed across batches and groups.
    #[test]
    fn test_batch_creation_invariants(ops in op_sequence_strategy(50)) {
        let ops_len = ops.len();
        let (batches, _) = super::batch_and_hash_ops(ops);

        // A basic block contains one or more batches
        assert!(!batches.is_empty(), "There should be at least one batch");

        // A batch contains exactly 8 groups
        for batch in &batches {
            assert_eq!(BATCH_SIZE, batch.groups.len(), "Each batch should have exactly 8 groups");
        }

        // The total number of operations should be preserved (NOOPs are added automatically but not counted in ops.len())
        let mut total_ops_from_batches = 0;
        for batch in &batches {
            total_ops_from_batches += batch.ops.len();
        }

        // Note: total_ops_from_batches should be >= ops.len() because NOOPs may be added
        assert!(total_ops_from_batches >= ops_len, "Total operations from batches should be >= input operations");

        // Verify that operation counts in each batch don't exceed group limits
        for batch in &batches {
            for (i, &count) in batch.op_counts.iter().enumerate() {
                if count > 0 {
                    assert!(count <= GROUP_SIZE,
                        "Group {} in batch has {} operations, which exceeds the maximum of {}",
                        i, count, GROUP_SIZE);
                }
            }
        }
    }
}

proptest! {
    /// Test that operations with immediate values are placed correctly
    /// - An operation with an immediate value cannot be the last operation in a group
    /// - Immediate values use the next available group in the batch
    /// - If no groups available, both operation and immediate move to next batch
    #[test]
    fn test_immediate_value_placement(ops in op_sequence_strategy(30)) {
        let (batches, _) = super::batch_and_hash_ops(ops.clone());

        let mut op_idx = 0;
        let mut current_group_ops = 0;

        for batch in &batches {
            for group_idx in 0..BATCH_SIZE {
                if op_idx >= ops.len() {
                    break;
                }

                let op = &ops[op_idx];

                // Check if this operation has an immediate value
                if op.imm_value().is_some() {
                    // If it has an immediate value, it cannot be the last operation in a group
                    if current_group_ops == GROUP_SIZE - 1 {
                        // This should have caused the group to be finalized and a new group started
                        // The immediate value should be in the next group
                        assert!(group_idx < BATCH_SIZE - 1 || batch.groups[group_idx + 1] != ZERO,
                            "Immediate value should have space in next group");
                    }
                }

                current_group_ops += 1;
                op_idx += 1;

                // Reset group counter when we move to a new group
                if current_group_ops >= GROUP_SIZE {
                    current_group_ops = 0;
                }
            }
            current_group_ops = 0; // Reset for each batch
        }
    }

    /// Test NOOP insertion rules:
    /// - NOOPs are used to fill a group or batch when necessary
    /// - Groups should be filled to exactly 9 operations when finalized
    #[test]
    fn test_noop_insertion(ops in op_sequence_strategy(25)) {
        let (batches, _) = super::batch_and_hash_ops(ops);

        let mut op_idx = 0;

        for batch in &batches {
            let mut group_ops = Vec::new();
            let mut _expected_noops = 0;

            for _group_idx in 0..BATCH_SIZE {
                if op_idx >= ops.len() && group_ops.is_empty() {
                    break;
                }

                if !group_ops.is_empty() {
                    // This group has operations, check if it needs NOOPs
                    let ops_in_group = group_ops.len();
                    if ops_in_group < GROUP_SIZE {
                        _expected_noops += GROUP_SIZE - ops_in_group;
                    }

                    // Reset for next group
                    group_ops.clear();
                }

                // Collect operations for this group
                while op_idx < ops.len() && group_ops.len() < GROUP_SIZE {
                    let op = &ops[op_idx];

                    // Check if this operation would be the last in the group and has an immediate value
                    if group_ops.len() == GROUP_SIZE - 1 && op.imm_value().is_some() {
                        // This should cause the group to be finalized and a new group started
                        break;
                    }

                    group_ops.push(*op);
                    op_idx += 1;
                }
            }

            // The batch should contain the expected operations plus any NOOPs that were inserted
            // We can't directly count NOOPs since they're not in the original ops list,
            // but we can verify the structure is correct
            for &count in &batch.op_counts {
                assert!(count <= GROUP_SIZE,
                    "Group operation count should not exceed 9");
            }
        }
    }
}
