use proptest::prelude::*;

// Import strategy functions from arbitrary.rs
pub(super) use super::arbitrary::op_non_control_sequence_strategy;
use super::*;
use crate::{Decorator, ONE, mast::MastForest};

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

fn decorator_strategy(
    nops: usize,
    max_decorators: usize,
) -> impl Strategy<Value = Vec<(usize, DecoratorId)>> {
    prop::collection::vec(
        (0..=nops, any::<u32>().prop_map(DecoratorId::new_unchecked)),
        0..=max_decorators,
    )
    .prop_map(move |mut decorators| {
        // Sort decorators by index to satisfy the BasicBlockNode requirement
        decorators.sort_by_key(|(idx, _)| *idx);
        decorators
    })
}

// Strategy for generating a list of decorators with valid indices for a given operation sequence
fn decorator_list_strategy(
    ops_num: usize,
) -> impl Strategy<Value = (Vec<Operation>, Vec<(usize, DecoratorId)>)> {
    op_non_control_sequence_strategy(ops_num)
        .prop_flat_map(|ops| (Just(ops.clone()), decorator_strategy(ops.len(), ops.len())))
}

proptest! {
    /// Test that the raw_decorator_iter() method correctly preserves the original decorator list.
    /// Given random operations and decorators with indices in the valid range,
    /// creating a BasicBlock and then collecting its raw decorators should yield the original list.
    #[test]
    fn test_raw_decorator_iter_preserves_decorators(
        (ops, decs) in decorator_list_strategy(20)
    ) {
        // Create a basic block with the generated operations and decorators
        let block = BasicBlockNode::new(ops.clone(), decs.clone()).unwrap();

        // Collect the decorators using raw_decorator_iter()
        let collected_decorators: Vec<(usize, DecoratorId)> = block.raw_decorator_iter().collect();

        // The collected decorators should match the original decorators
        prop_assert_eq!(collected_decorators, decs);
    }
}

// Tests for the basic block decorator functionality added to support before_enter and after_exit
// decorators.
// --------------------------------------------------------------------------------------------

#[test]
fn test_mast_node_error_context_decorators_iterates_all_decorators() {
    let mut forest = MastForest::new();
    let operations = vec![Operation::Add, Operation::Mul];

    // Create decorators for before_enter, during operations, and after_exit
    let before_enter_deco = Decorator::Trace(1);
    let op_deco = Decorator::Trace(2);
    let after_exit_deco = Decorator::Trace(3);

    let before_enter_id = forest.add_decorator(before_enter_deco.clone()).unwrap();
    let op_id = forest.add_decorator(op_deco.clone()).unwrap();
    let after_exit_id = forest.add_decorator(after_exit_deco.clone()).unwrap();

    // Create a basic block with all types of decorators
    let mut block = BasicBlockNode::new(operations, vec![(1, op_id)]).unwrap();
    block.append_before_enter(&[before_enter_id]);
    block.append_after_exit(&[after_exit_id]);

    let all_decorators: Vec<_> = block.decorators().collect();

    // Should have 3 decorators total: 1 before_enter, 1 during, 1 after_exit
    assert_eq!(all_decorators.len(), 3);

    // Check that before_enter decorator appears first (at op index 0)
    assert_eq!(all_decorators[0], (0, before_enter_id));

    // Check that op decorator appears at the correct position (op index 1)
    assert_eq!(all_decorators[1], (1, op_id));

    // Check that after_exit decorator appears last (at op index = total_ops)
    assert_eq!(all_decorators[2], (2, after_exit_id));
}

#[test]
fn test_indexed_decorator_iter_excludes_before_enter_after_exit() {
    let mut forest = MastForest::new();
    let operations = vec![Operation::Add, Operation::Mul];

    // Create decorators
    let before_enter_deco = Decorator::Trace(1);
    let op_deco1 = Decorator::Trace(2);
    let op_deco2 = Decorator::Trace(3);
    let after_exit_deco = Decorator::Trace(4);

    let before_enter_id = forest.add_decorator(before_enter_deco.clone()).unwrap();
    let op_id1 = forest.add_decorator(op_deco1.clone()).unwrap();
    let op_id2 = forest.add_decorator(op_deco2.clone()).unwrap();
    let after_exit_id = forest.add_decorator(after_exit_deco.clone()).unwrap();

    // Create a basic block with all types of decorators
    let mut block = BasicBlockNode::new(operations, vec![(0, op_id1), (1, op_id2)]).unwrap();
    block.append_before_enter(&[before_enter_id]);
    block.append_after_exit(&[after_exit_id]);

    // Test indexed_decorator_iter - should only include op-indexed decorators
    let indexed_decorators: Vec<_> = block.indexed_decorator_iter().collect();

    // Should have only 2 decorators (the ones tied to specific operation indices)
    assert_eq!(indexed_decorators.len(), 2);

    // Should NOT include before_enter decorator
    assert!(!indexed_decorators.iter().any(|&(_, id)| id == before_enter_id));

    // Should NOT include after_exit decorator
    assert!(!indexed_decorators.iter().any(|&(_, id)| id == after_exit_id));

    // Should include the operation-indexed decorators
    let mut indexed_ids: Vec<_> = indexed_decorators.iter().map(|&(_, id)| id).collect();
    indexed_ids.sort();
    let mut expected_op_ids = vec![op_id1, op_id2];
    expected_op_ids.sort();

    assert_eq!(indexed_ids, expected_op_ids);
}

#[test]
fn test_decorator_positions() {
    let mut forest = MastForest::new();

    // Create multiple types of decorators
    let trace_deco = Decorator::Trace(42);
    let debug_deco = Decorator::Trace(999);

    let trace_id = forest.add_decorator(trace_deco.clone()).unwrap();
    let debug_id = forest.add_decorator(debug_deco.clone()).unwrap();

    // Create a basic block with complex operations
    let operations = vec![
        Operation::Push(Felt::new(1)),
        Operation::Push(Felt::new(2)),
        Operation::Add,
        Operation::Push(Felt::new(3)),
        Operation::Mul,
    ];

    let mut block =
        BasicBlockNode::new(operations.clone(), vec![(2, trace_id), (4, debug_id)]).unwrap();

    // Add before_enter and after_exit decorators
    block.append_before_enter(&[trace_id, debug_id]);
    block.append_after_exit(&[trace_id]);

    // Test that MastNodeErrorContext::decorators returns all decorators
    let all_decorators: Vec<_> = block.decorators().collect();
    assert_eq!(all_decorators.len(), 5);

    // Verify the order and positions:
    // 1. before_enter decorators at position 0
    // 2. op-indexed decorators at their respective positions
    // 3. after_exit decorators at position = total_ops
    let mut found_positions = Vec::new();

    for (pos, _id) in &all_decorators {
        found_positions.push(*pos);
    }

    let mut expected_positions = vec![0, 0, 2, 4, 5]; // total_ops = 5
    expected_positions.sort();
    assert_eq!(found_positions, expected_positions);

    // Test that indexed_decorator_iter only returns op-indexed decorators
    let indexed_decorators: Vec<_> = block.indexed_decorator_iter().collect();
    assert_eq!(indexed_decorators.len(), 2);

    let indexed_positions: Vec<_> = indexed_decorators.iter().map(|&(pos, _id)| pos).collect();
    let mut expected_indexed_positions = vec![2, 4];
    expected_indexed_positions.sort();

    assert_eq!(indexed_positions, expected_indexed_positions);
    assert!(!indexed_positions.contains(&0)); // No before_enter
    assert!(!indexed_positions.contains(&5)); // No after_exit

    // Test that the block preserves all decorator types after modification
    block.append_before_enter(&[]);
    block.append_after_exit(&[]);

    let all_decorators_after_mod: Vec<_> = block.decorators().collect();
    assert_eq!(
        all_decorators_after_mod.len(),
        5,
        "Expected 5 decorators, got {:?}. All decorators: {:?}",
        all_decorators_after_mod.len(),
        all_decorators_after_mod.iter().collect::<Vec<_>>()
    );

    // Verify the new before_enter decorator
    assert!(all_decorators_after_mod.iter().any(|&(_, id)| id == debug_id));

    // Verify the new after_exit decorators
    assert!(all_decorators_after_mod.iter().any(|&(_, id)| id == debug_id));
    assert!(all_decorators_after_mod.iter().any(|&(_, id)| id == trace_id));
}
