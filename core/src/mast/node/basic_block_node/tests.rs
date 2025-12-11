use proptest::prelude::*;

// Import strategy functions from arbitrary.rs
pub(super) use super::arbitrary::op_non_control_sequence_strategy;
use super::*;
use crate::{
    Decorator, Felt, ONE, Word,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeExt},
};

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

    // Convert raw decorators to decorator list by adding them to the forest first
    let decorator_list: Vec<(usize, crate::mast::DecoratorId)> = decorators
        .into_iter()
        .map(|(idx, decorator)| -> Result<(usize, crate::mast::DecoratorId), crate::mast::MastForestError> {
            let decorator_id = mast_forest.add_decorator(decorator)?;
            Ok((idx, decorator_id))
        })
        .collect::<Result<Vec<_>, _>>().unwrap();

    let node_id = BasicBlockNodeBuilder::new(operations, decorator_list)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let node = mast_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

    let mut iterator = node.iter(&mast_forest);

    // operation index 0
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(DecoratorId(0))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(DecoratorId(1))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::Add)));

    // operations indices 1, 2
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::Mul)));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::MovDn2)));

    // operation index 3
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(DecoratorId(2))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Operation(&Operation::MovDn3)));

    // after last operation
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(DecoratorId(3))));
    assert_eq!(iterator.next(), Some(OperationOrDecorator::Decorator(DecoratorId(4))));
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
    // At most one decorator per operation, but we could technically go a bit higher
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
        // Create a basic block with the generated operations and decorators using linked storage
        let mut dummy_forest = MastForest::new();

        // Convert decorators to use forest's decorator IDs
        let forest_decorators: Vec<(usize, crate::mast::DecoratorId)> = decs
            .iter()
            .map(|(idx, decorator_id)| (*idx, *decorator_id))
            .collect();

        let node_id = BasicBlockNodeBuilder::new(ops.clone(), forest_decorators)
            .add_to_forest(&mut dummy_forest)
            .unwrap();
        let block = dummy_forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

        // Collect the decorators using raw_decorator_iter()
        let collected_decorators: Vec<(usize, DecoratorId)> = block.raw_decorator_iter(&dummy_forest).collect();

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

    // Create a basic block with all types of decorators using add_to_forest
    let node_id = BasicBlockNodeBuilder::new(operations, vec![(1, op_id)])
        .with_before_enter(vec![before_enter_id])
        .with_after_exit(vec![after_exit_id])
        .add_to_forest(&mut forest)
        .unwrap();

    // For basic blocks, we need to combine before_enter, operation-indexed, and after_exit
    // decorators
    let all_decorators = forest.all_decorators(node_id);

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

    // Create a basic block with all types of decorators using add_to_forest
    let node_id = BasicBlockNodeBuilder::new(operations, vec![(0, op_id1), (1, op_id2)])
        .with_before_enter(vec![before_enter_id])
        .with_after_exit(vec![after_exit_id])
        .add_to_forest(&mut forest)
        .unwrap();

    let block = forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

    // Test indexed_decorator_iter - should only include op-indexed decorators
    let indexed_decorators: Vec<_> = block.indexed_decorator_iter(&forest).collect();

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

    // Create a basic block with complex operations using add_to_forest
    let node_id =
        BasicBlockNodeBuilder::new(operations.clone(), vec![(2, trace_id), (4, debug_id)])
            .with_before_enter(vec![trace_id, debug_id])
            .with_after_exit(vec![trace_id])
            .add_to_forest(&mut forest)
            .unwrap();

    let block = forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

    // Test that MastForest::decorator_links_for_node returns all decorators using the helper method
    let all_decorators = forest.all_decorators(node_id);
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
    let indexed_decorators: Vec<_> = block.indexed_decorator_iter(&forest).collect();
    assert_eq!(indexed_decorators.len(), 2);

    let indexed_positions: Vec<_> = indexed_decorators.iter().map(|&(pos, _id)| pos).collect();
    let mut expected_indexed_positions = vec![2, 4];
    expected_indexed_positions.sort();

    assert_eq!(indexed_positions, expected_indexed_positions);
    assert!(!indexed_positions.contains(&0)); // No before_enter
    assert!(!indexed_positions.contains(&5)); // No after_exit
}

proptest! {
    /// RawToPaddedPrefix / PaddedToRawPrefix correctness
    #[test]
    fn proptest_raw_to_padded_correctness(
        (ops, decorators) in
        decorator_list_strategy(72)
    ) {

        // Build BasicBlockNode using linked storage (this applies padding)
        let mut forest = MastForest::new();
        // Convert decorators to use forest's decorator IDs
        let forest_decorators: Vec<(usize, crate::mast::DecoratorId)> = decorators
            .iter()
            .map(|(idx, decorator_id)| (*idx, *decorator_id))
            .collect();
        let node_id = BasicBlockNodeBuilder::new(ops.clone(), forest_decorators)
            .add_to_forest(&mut forest)
            .unwrap();
        let block = forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();
        let padded_ops = block.op_batches().iter().flat_map(|batch| batch.ops()).collect::<Vec<_>>();

        // Build both prefix arrays
        let raw2pad = RawToPaddedPrefix::new(block.op_batches());
        let pad2raw = PaddedToRawPrefix::new(block.op_batches());

        // Test invariant 1: Raw→Padded correctness
        //  For all raw indices r in [0..raw_ops],
        //  let p = r + raw_to_padded[r];
        //  Then: p is the padded position of the r-th raw op.
        for r in 0..ops.len() {
            let p = r + raw2pad[r];
            prop_assert!(
                *padded_ops[p] == ops[r],
                "Raw->Padded conversion incorrect for raw index {}",
                r
            );
        }

        // Test invariant 2: Padded→Raw correctness
        // For all padded indices p in [0..padded_ops],
        // let r = p - padded_to_raw[p];
        // Then: r is the raw position for the op at padded position p (if that position is a real op).
        for p in 0..padded_ops.len() {
            let r = p - pad2raw[p];
            // this comparison is only valid if the operation at position p is not a padding Noop
            if *padded_ops[p] != Operation::Noop {
                prop_assert!(
                    ops[r] == *padded_ops[p],
                    "Padded->Raw conversion incorrect for padded index {}",
                    p
                );
            }
        }

        // Test invariant 3: Cross-array consistency
        // Let p = r + raw_to_padded[r]. Then padded_to_raw[p] == raw_to_padded[r].
        for r in 0..=ops.len() {
            let p = r + raw2pad[r];
            prop_assert_eq!(
                pad2raw[p],
                raw2pad[r],
                "Cross-array invariant violated for raw {}, padded {}",
                r, p
            );
        }
    }
}

proptest! {
    /// Property test 2: RawDecoratorOpLinkIterator invertibility
    #[test]
    fn proptest_decorator_iterator_invertibility(
        (ops, decorators) in
        decorator_list_strategy(72)
    ) {
        // Build BasicBlockNode using linked storage
        let mut forest = MastForest::new();
        // Convert decorators to use forest's decorator IDs
        let forest_decorators: Vec<(usize, crate::mast::DecoratorId)> = decorators
            .iter()
            .map(|(idx, decorator_id)| (*idx, *decorator_id))
            .collect();
        let node_id = BasicBlockNodeBuilder::new(ops.clone(), forest_decorators)
            .add_to_forest(&mut forest)
            .unwrap();
        let block = forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

        // Create raw decorator iterator
        let raw_iter = block.raw_decorator_iter(&forest);

        // Collect all decorators from the iterator
        let collected_decorators: Vec<_> = raw_iter.collect();

        // Verify decorators maintain order with corrected indices
        for (collected_idx, &(_expected_raw_idx, expected_id)) in decorators.iter().enumerate() {
            if collected_idx < collected_decorators.len() {
                let (actual_raw_idx, actual_id) = collected_decorators[collected_idx];
                prop_assert_eq!(actual_id, expected_id);
                prop_assert!(actual_raw_idx <= ops.len()); // Should be a valid raw index
            }
        }
    }
}

// DIGEST FORCING TESTS
// ================================================================================

#[test]
fn test_basic_block_node_digest_forcing() {
    let operations = vec![Operation::Add, Operation::Mul];
    let mut forest = MastForest::new();
    let builder1 = BasicBlockNodeBuilder::new(operations.clone(), vec![]);

    // Build normally
    let node_id1 = builder1
        .add_to_forest(&mut forest)
        .expect("Failed to add basic block node to forest");
    let node1 = forest.get_node_by_id(node_id1).unwrap().unwrap_basic_block();
    let normal_digest = node1.digest();

    // Build with forced digest
    let forced_digest = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let builder2 = BasicBlockNodeBuilder::new(operations, vec![]).with_digest(forced_digest);
    let node_id2 = builder2
        .add_to_forest(&mut forest)
        .expect("Failed to add basic block node to forest with forced digest");
    let node2 = forest.get_node_by_id(node_id2).unwrap().unwrap_basic_block();

    assert_ne!(normal_digest, forced_digest, "Normal and forced digests should be different");
    assert_eq!(node2.digest(), forced_digest, "Forced digest should be used");
}

#[test]
fn test_basic_block_digest_forcing_with_decorators() {
    let mut forest = MastForest::new();
    let decorator_id = forest.add_decorator(Decorator::Trace(42)).expect("Failed to add decorator");

    let operations = vec![Operation::Add];
    let forced_digest = Word::new([Felt::new(13), Felt::new(14), Felt::new(15), Felt::new(16)]);

    let node_id = BasicBlockNodeBuilder::new(operations, vec![])
        .with_before_enter(vec![decorator_id])
        .with_after_exit(vec![decorator_id])
        .with_digest(forced_digest)
        .add_to_forest(&mut forest)
        .expect("Failed to add node to forest");

    let node = forest.get_node_by_id(node_id).unwrap().unwrap_basic_block();

    assert_eq!(node.digest(), forced_digest, "Digest should be forced");
    assert_eq!(
        node.before_enter(&forest),
        &[decorator_id],
        "Before-enter decorators should be preserved"
    );
    assert_eq!(
        node.after_exit(&forest),
        &[decorator_id],
        "After-exit decorators should be preserved"
    );
}

#[test]
fn test_basic_block_fingerprint_uses_forced_digest() {
    let mut forest = MastForest::new();
    let decorator_id = forest.add_decorator(Decorator::Trace(99)).expect("Failed to add decorator");

    let operations = vec![Operation::Mul];
    let forced_digest = Word::new([Felt::new(17), Felt::new(18), Felt::new(19), Felt::new(20)]);

    let builder1 = BasicBlockNodeBuilder::new(operations.clone(), vec![])
        .with_before_enter(vec![decorator_id]);
    let builder2 = BasicBlockNodeBuilder::new(operations, vec![])
        .with_before_enter(vec![decorator_id])
        .with_digest(forced_digest);

    let fingerprint1 = builder1
        .fingerprint_for_node(&forest, &crate::IndexVec::new())
        .expect("Failed to compute fingerprint1");
    let fingerprint2 = builder2
        .fingerprint_for_node(&forest, &crate::IndexVec::new())
        .expect("Failed to compute fingerprint2");

    assert_ne!(
        fingerprint1, fingerprint2,
        "Fingerprints should be different when digests differ"
    );
}
