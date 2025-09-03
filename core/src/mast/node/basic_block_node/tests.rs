use proptest::prelude::*;

use super::*;
use crate::{Decorator, ONE, mast::MastForest};

// Helper function to generate random felt values
fn any_felt() -> impl Strategy<Value = Felt> {
    any::<u64>().prop_map(Felt::new)
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
        Just(Operation::Emit),
        Just(Operation::Ext2Mul),
        Just(Operation::Expacc),
        Just(Operation::HPerm),
        // Note: We exclude Assert here because it has an immediate value (error code)
    ]
}

// Strategy for operations with immediate values
fn op_with_imm_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![any_felt().prop_map(Operation::Push)]
}

// Strategy for all non-control flow operations
fn op_non_control_strategy() -> impl Strategy<Value = Operation> {
    prop_oneof![op_no_imm_strategy(), op_with_imm_strategy(),]
}

// Strategy for sequences of operations
pub(super) fn op_non_control_sequence_strategy(
    max_length: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    prop::collection::vec(op_non_control_strategy(), 1..=max_length)
}

#[test]
fn batch_ops_1() {
    // --- one operation ----------------------------------------------------------------------
    let ops = vec![Operation::Add];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_2() {
    // --- two operations ---------------------------------------------------------------------
    let ops = vec![Operation::Add, Operation::Mul];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_3() {
    // --- one group with one immediate value -------------------------------------------------
    let ops = vec![Operation::Add, Operation::Push(Felt::new(12345678))];
    let (batches, hash) = super::batch_and_hash_ops(ops.clone());
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);
    batch_groups[1] = Felt::new(12345678);

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_4() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_5() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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
    let mut batch1_groups = [ZERO; BATCH_SIZE];
    batch1_groups[0] = build_group(&[ops[9]]);
    batch1_groups[1] = Felt::new(7);

    let all_groups = [batch0_groups, batch1_groups].concat();
    assert_eq!(hasher::hash_elements(&all_groups), hash);
}

#[test]
fn batch_ops_6() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_7() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_8() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_9() {
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
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

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

    let batch1_groups = [build_group(&ops[17..]), Felt::new(6), ZERO, ZERO, ZERO, ZERO, ZERO, ZERO];

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

fn build_group_chunks(batches: &[OpBatch]) -> impl Iterator<Item = &[Operation]> {
    batches.iter().flat_map(|opbatch| opbatch.group_chunks())
}

// PROPTESTS FOR BATCH CREATION INVARIANTS
// ================================================================================================

proptest! {
    /// Test that batch creation follows the basic rules:
    /// - A basic block contains one or more batches.
    /// - A batch contains at most 8 groups.
    /// - NOOPs (implicit for now) are used to fill groups when necessary (empty group, finishing in immediate op)
    /// - Operations are correctly distributed across batches and groups.
    #[test]
    fn test_batch_creation_invariants(ops in op_non_control_sequence_strategy(50)) {
        let (batches, _) = super::batch_and_hash_ops(ops.clone());

        // A basic block contains one or more batches
        assert!(!batches.is_empty(), "There should be at least one batch");

        // A batch contains at most 8 groups, and groups are a power of two
        for batch in &batches {
            assert!(batch.num_groups <= BATCH_SIZE);
            assert!(batch.num_groups.is_power_of_two());
        }

        // The total number of operations should be preserved, modulo padding
        let total_ops_from_batches: usize = batches.iter().map(|batch| {
            batch.ops.len() - batch.padding.iter().filter(|b| **b).count()
        }).sum();
        assert_eq!(total_ops_from_batches, ops.len(), "Total operations from batches should be == input operations");

        // Verify that operation counts in each batch don't exceed group limits
        for batch in &batches {
            for chunk in batch.group_chunks() {
                    let count = chunk.len();
                    assert!(chunk.len() <= GROUP_SIZE,
                        "Group {:?} in batch has {} operations, which exceeds the maximum of {}",
                        chunk, count, GROUP_SIZE);
            }
        }
    }

    /// Test that operations with immediate values are placed correctly
    /// - An operation with an immediate value cannot be the last operation in a group
    /// - Immediate values use the next available group in the batch
    /// - If no groups available, both operation and immediate move to next batch
    #[test]
    fn test_immediate_value_placement(ops in op_non_control_sequence_strategy(50)) {
        let (batches, _) = super::batch_and_hash_ops(ops.clone());

        for batch in batches {
            let mut op_idx_in_group = 0;
            let mut group_idx = 0;
            let mut next_group_idx = 1;
            // interpret operations in the batch one by one
            for (op_idx_in_batch, op) in batch.ops().iter().enumerate() {
                let has_imm = op.imm_value().is_some();
                if has_imm {
                    // immediate values follow the op, their op count is zero
                    assert_eq!(batch.indptr[next_group_idx+1] - batch.indptr[next_group_idx], 0, "invalid immediate op count convention");
                    next_group_idx += 1;
                }
                // end of group logic
                if op_idx_in_batch + 1 == batch.indptr[group_idx + 1] {
                    // if we are at the end of the group, first check if the operation carries an
                    // immediate value
                    if has_imm {
                        // an operation with an immediate value cannot be the last operation in a group
                        // so, we need room to execute a NOOP after it.
                        assert!(op_idx_in_group < GROUP_SIZE - 1, "invalid op index");
                    }

                    // then, move to the next group and reset operation index
                    group_idx = next_group_idx;
                    next_group_idx += 1;
                    op_idx_in_group = 0;
                } else {
                    // if we are not at the end of the group, just increment the operation index
                    op_idx_in_group += 1;
                }
            }
        }
    }
}
