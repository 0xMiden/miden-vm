use proptest::prelude::*;

// Import strategy functions from arbitrary.rs
pub(super) use super::arbitrary::op_non_control_sequence_strategy;
use super::*;
use crate::{
    Felt, ONE, Word,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeExt},
};

#[test]
fn batch_ops_1() {
    // --- one operation ----------------------------------------------------------------------
    let ops = vec![Operation::Add];
    let (batches, hash) = batch_and_hash_ops(&ops);
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
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_3() {
    // --- one group with one immediate value -------------------------------------------------
    let ops = vec![Operation::Add, Operation::Push(Felt::new_unchecked(12345678))];
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let mut batch_groups = [ZERO; BATCH_SIZE];
    batch_groups[0] = build_group(&ops);
    batch_groups[1] = Felt::new_unchecked(12345678);

    assert_eq!(hasher::hash_elements(&batch_groups), hash);
}

#[test]
fn batch_ops_4() {
    // --- one group with 7 immediate values --------------------------------------------------
    let ops = vec![
        Operation::Push(ONE),
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Push(Felt::new_unchecked(3)),
        Operation::Push(Felt::new_unchecked(4)),
        Operation::Push(Felt::new_unchecked(5)),
        Operation::Push(Felt::new_unchecked(6)),
        Operation::Push(Felt::new_unchecked(7)),
        Operation::Add,
    ];
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch_groups = [
        build_group(&ops),
        ONE,
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
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
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Push(Felt::new_unchecked(3)),
        Operation::Push(Felt::new_unchecked(4)),
        Operation::Push(Felt::new_unchecked(5)),
        Operation::Push(Felt::new_unchecked(6)),
        Operation::Add,
        Operation::Push(Felt::new_unchecked(7)),
    ];
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch0_groups = [
        build_group(&ops[..9]),
        ONE,
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        ZERO,
    ];
    let mut batch1_groups = [ZERO; BATCH_SIZE];
    batch1_groups[0] = build_group(&[ops[9]]);
    batch1_groups[1] = Felt::new_unchecked(7);

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
        Operation::Push(Felt::new_unchecked(7)),
        Operation::Add,
        Operation::Add,
        Operation::Push(Felt::new_unchecked(11)),
        Operation::Mul,
        Operation::Mul,
        Operation::Add,
    ];

    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch_groups = [
        build_group(&ops[..9]),
        Felt::new_unchecked(7),
        Felt::new_unchecked(11),
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
        Operation::Push(Felt::new_unchecked(11)),
    ];
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch_groups = [
        build_group(&ops[..8]),
        build_group(&[ops[8]]),
        Felt::new_unchecked(11),
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
        Operation::Push(Felt::new_unchecked(2)),
    ];
    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch_groups = [
        build_group(&ops[..8]),
        ONE,
        build_group(&[ops[8]]),
        Felt::new_unchecked(2),
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
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Push(Felt::new_unchecked(3)),
        Operation::Push(Felt::new_unchecked(4)),
        Operation::Push(Felt::new_unchecked(5)),
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
        Operation::Push(Felt::new_unchecked(6)),
        Operation::Pad,
    ];

    let (batches, hash) = batch_and_hash_ops(&ops);
    insta::assert_debug_snapshot!(batches);
    insta::assert_debug_snapshot!(build_group_chunks(&batches).collect::<Vec<_>>());

    let batch0_groups = [
        build_group(&ops[..9]),
        ONE,
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
        Felt::new_unchecked(5),
        build_group(&ops[9..17]),
        ZERO,
    ];

    let batch1_groups = [
        build_group(&ops[17..]),
        Felt::new_unchecked(6),
        ZERO,
        ZERO,
        ZERO,
        ZERO,
        ZERO,
        ZERO,
    ];

    let all_groups = [batch0_groups, batch1_groups].concat();
    assert_eq!(hasher::hash_elements(&all_groups), hash);
}

fn build_group(ops: &[Operation]) -> Felt {
    let mut group = 0u64;
    for (i, op) in ops.iter().enumerate() {
        group |= (op.op_code() as u64) << (Operation::OP_BITS * i);
    }
    Felt::new_unchecked(group)
}

fn build_group_chunks(batches: &[OpBatch]) -> impl Iterator<Item = &[Operation]> {
    batches.iter().flat_map(OpBatch::group_chunks)
}

fn basic_block_from_batch(batch: OpBatch) -> BasicBlockNode {
    let digest = hasher::hash_elements(batch.groups());
    BasicBlockNodeBuilder::from_op_batches(vec![batch], digest)
        .build()
        .expect("basic block should build")
}

fn basic_block_from_batches(op_batches: Vec<OpBatch>) -> BasicBlockNode {
    BasicBlockNode { op_batches, digest: Word::default() }
}

proptest! {
    /// Test that batch creation follows the basic rules:
    /// - A basic block contains one or more batches.
    /// - A batch contains at most 8 groups.
    /// - NOOPs (implicit for now) are used to fill groups when necessary (empty group, finishing in immediate op)
    /// - Operations are correctly distributed across batches and groups.
    #[test]
    fn test_batch_creation_invariants(ops in op_non_control_sequence_strategy(50)) {
        let (batches, _) = batch_and_hash_ops(&ops);

        // A basic block contains one or more batches
        assert!(!batches.is_empty(), "There should be at least one batch");

        // A batch contains at most 8 groups, and groups are a power of two
        for batch in &batches {
            assert!(batch.num_groups <= BATCH_SIZE);
            assert!(batch.num_groups.is_power_of_two());
        }
        // All non-final batches must be full.
        for (idx, batch) in batches.iter().enumerate() {
            if idx + 1 < batches.len() {
                assert_eq!(batch.num_groups, BATCH_SIZE);
            }
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
                        "Group {chunk:?} in batch has {count} operations, which exceeds the maximum of {GROUP_SIZE}");
            }
        }
    }

    /// Test that operations with immediate values are placed correctly
    /// - An operation with an immediate value cannot be the last operation in a group
    /// - Immediate values use the next available group in the batch
    /// - If no groups available, both operation and immediate move to next batch
    #[test]
    fn test_immediate_value_placement(ops in op_non_control_sequence_strategy(50)) {
        let (batches, _) = batch_and_hash_ops(&ops);

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

#[test]
fn test_validate_immediate_commitment_rejects_opcode_group_mismatch() {
    let ops = vec![Operation::Add];
    let indptr = [0usize, 1, 1, 1, 1, 1, 1, 1, 1];
    let mut groups = [ZERO; BATCH_SIZE];
    groups[0] = ZERO;
    let batch = OpBatch::new_from_parts(ops, indptr, [false; BATCH_SIZE], groups, 1);

    let node = basic_block_from_batch(batch);
    let err = node.validate_batch_invariants().unwrap_err();
    assert!(err.contains("committed opcode group"));
}

#[test]
fn test_validate_immediate_commitment_rejects_immediate_value_mismatch() {
    let imm = Felt::new_unchecked(1);
    let ops = vec![Operation::Push(imm), Operation::Add];
    let indptr = [0usize, 2, 2, 2, 2, 2, 2, 2, 2];
    let mut groups = [ZERO; BATCH_SIZE];
    groups[0] = build_group(&ops);
    groups[1] = Felt::new_unchecked(2);
    let batch = OpBatch::new_from_parts(ops, indptr, [false; BATCH_SIZE], groups, 2);

    let node = basic_block_from_batch(batch);
    let err = node.validate_batch_invariants().unwrap_err();
    assert!(err.contains("push immediate value mismatch"));
}

#[test]
fn test_validate_immediate_commitment_rejects_overlap_with_op_group() {
    let ops = vec![Operation::Push(ONE), Operation::Add, Operation::Add];
    let indptr = [0usize, 2, 3, 3, 3, 3, 3, 3, 3];
    let mut groups = [ZERO; BATCH_SIZE];
    groups[0] = build_group(&ops[..2]);
    groups[1] = build_group(&ops[2..3]);
    let batch = OpBatch::new_from_parts(ops, indptr, [false; BATCH_SIZE], groups, 2);

    let node = basic_block_from_batch(batch);
    let err = node.validate_batch_invariants().unwrap_err();
    assert!(err.contains("overlaps operation group"));
}

#[test]
fn test_validate_immediate_commitment_rejects_nonzero_empty_group() {
    let ops = vec![Operation::Add];
    let indptr = [0usize, 1, 1, 1, 1, 1, 1, 1, 1];
    let mut groups = [ZERO; BATCH_SIZE];
    groups[0] = build_group(&ops);
    groups[1] = Felt::new_unchecked(9);
    let batch = OpBatch::new_from_parts(ops, indptr, [false; BATCH_SIZE], groups, 2);

    let node = basic_block_from_batch(batch);
    let err = node.validate_batch_invariants().unwrap_err();
    assert!(err.contains("empty group must be zero"));
}

#[test]
fn validate_batch_invariants_rejects_padded_empty_group() {
    let ops = vec![Operation::Add];
    let indptr = [0, 0, 1, 1, 1, 1, 1, 1, 1];
    let mut padding = [false; BATCH_SIZE];
    padding[0] = true;
    let groups = [ZERO; BATCH_SIZE];
    let batch = OpBatch::new_from_parts(ops, indptr, padding, groups, 2);

    let block = basic_block_from_batches(vec![batch]);
    let result = block.validate_batch_invariants();

    assert!(result.is_err());
}

#[test]
fn validate_batch_invariants_rejects_padded_group_without_noop() {
    let ops = vec![Operation::Add];
    let indptr = [0, 1, 1, 1, 1, 1, 1, 1, 1];
    let mut padding = [false; BATCH_SIZE];
    padding[0] = true;
    let groups = [ZERO; BATCH_SIZE];
    let batch = OpBatch::new_from_parts(ops, indptr, padding, groups, 1);

    let block = basic_block_from_batches(vec![batch]);
    let result = block.validate_batch_invariants();

    assert!(result.is_err());
}

#[test]
fn validate_batch_invariants_accepts_padded_group_with_noop() {
    let ops = vec![Operation::Add, Operation::Noop];
    let indptr = [0, 2, 2, 2, 2, 2, 2, 2, 2];
    let mut padding = [false; BATCH_SIZE];
    padding[0] = true;
    let mut groups = [ZERO; BATCH_SIZE];
    groups[0] = build_group(&ops);
    let batch = OpBatch::new_from_parts(ops, indptr, padding, groups, 1);

    let block = basic_block_from_batches(vec![batch]);
    let result = block.validate_batch_invariants();

    assert!(result.is_ok());
}

#[test]
fn validate_batch_invariants_rejects_malformed_indptr_without_panicking() {
    let ops = vec![Operation::Add];
    let mut indptr = [0usize; BATCH_SIZE + 1];
    indptr[1] = 2;
    let batch = OpBatch {
        ops,
        indptr,
        padding: [false; BATCH_SIZE],
        groups: [ZERO; BATCH_SIZE],
        num_groups: 1,
    };

    let block = basic_block_from_batches(vec![batch]);
    let result = block.validate_batch_invariants();

    assert!(result.is_err());
}

#[test]
fn validate_padding_semantics_rejects_malformed_metadata_without_panicking() {
    let mut indptr = [0usize; BATCH_SIZE + 1];
    indptr[1] = 2;
    let mut padding = [false; BATCH_SIZE];
    padding[0] = true;
    let batch = OpBatch {
        ops: vec![Operation::Add],
        indptr,
        padding,
        groups: [ZERO; BATCH_SIZE],
        num_groups: 1,
    };

    let result = batch.validate_padding_semantics();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid group bounds"));
}

#[test]
fn validate_padding_semantics_rejects_num_groups_overflow_without_panicking() {
    let batch = OpBatch {
        ops: vec![Operation::Noop],
        indptr: [0usize; BATCH_SIZE + 1],
        padding: [false; BATCH_SIZE],
        groups: [ZERO; BATCH_SIZE],
        num_groups: BATCH_SIZE + 1,
    };

    let result = batch.validate_padding_semantics();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("exceeds BATCH_SIZE"));
}

#[test]
fn test_basic_block_node_digest_forcing() {
    let operations = vec![Operation::Add, Operation::Mul];
    let mut forest = MastForest::new();
    let builder1 = BasicBlockNodeBuilder::new(operations.clone());

    // Build normally
    let node_id1 = builder1
        .add_to_forest(&mut forest)
        .expect("Failed to add basic block node to forest");
    let node1 = forest.get_node_by_id(node_id1).unwrap().unwrap_basic_block();
    let normal_digest = node1.digest();

    // Build with forced digest
    let forced_digest = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let builder2 = BasicBlockNodeBuilder::new(operations).with_digest(forced_digest);
    let node_id2 = builder2
        .add_to_forest(&mut forest)
        .expect("Failed to add basic block node to forest with forced digest");
    let node2 = forest.get_node_by_id(node_id2).unwrap().unwrap_basic_block();

    assert_ne!(normal_digest, forced_digest, "Normal and forced digests should be different");
    assert_eq!(node2.digest(), forced_digest, "Forced digest should be used");
}

// ARBITRARY HELPER TESTS
// ================================================================================================
//
// These helpers back the executable MAST forest generation pipeline.

#[cfg(test)]
mod arbitrary_helpers {
    use super::super::arbitrary::{KernelPool, RootPool};
    use super::*;
    use crate::mast::{JoinNodeBuilder, LoopNodeBuilder};

    #[test]
    fn test_root_pool_basic_operations() {
        // Create a simple forest with a few basic blocks
        let mut forest = MastForest::new();

        // Create some basic blocks
        let block1 = BasicBlockNode::new(alloc::vec![Operation::Add])
        .unwrap();
        let block2 = BasicBlockNode::new(alloc::vec![Operation::Mul])
        .unwrap();
        let block3 = BasicBlockNode::new(alloc::vec![Operation::Neg])
        .unwrap();

        let id1 = block1.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let id2 = block2.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let id3 = block3.to_builder(&forest).add_to_forest(&mut forest).unwrap();

        // Create a RootPool
        let mut pool = RootPool::new(&forest);

        // Test empty pool
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);

        // Add roots
        pool.push(id1);
        assert!(!pool.is_empty());
        assert_eq!(pool.len(), 1);

        pool.push(id2);
        pool.push(id3);
        assert_eq!(pool.len(), 3);

        // Test roots_not_reaching - all basic blocks should not reach each other
        let not_reaching: Vec<_> = pool.roots_not_reaching(id1).collect();
        assert_eq!(not_reaching.len(), 2); // id2 and id3 don't reach id1
        assert!(not_reaching.contains(&id2));
        assert!(not_reaching.contains(&id3));
    }

    #[test]
    fn test_root_pool_reachability() {
        // Create a forest with a join node
        let mut forest = MastForest::new();

        // Create basic blocks
        let block1 = BasicBlockNode::new(alloc::vec![Operation::Add])
        .unwrap();
        let block2 = BasicBlockNode::new(alloc::vec![Operation::Mul])
        .unwrap();

        let id1 = block1.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let id2 = block2.to_builder(&forest).add_to_forest(&mut forest).unwrap();

        // Create a join node that references both blocks
        let join_id = JoinNodeBuilder::new([id1, id2]).add_to_forest(&mut forest).unwrap();

        // Create a RootPool
        let mut pool = RootPool::new(&forest);
        pool.push(id1);
        pool.push(id2);
        pool.push(join_id);

        // Test that join_id reaches both id1 and id2
        let not_reaching_id1: Vec<_> = pool.roots_not_reaching(id1).collect();
        assert!(!not_reaching_id1.contains(&join_id)); // join_id reaches id1
        assert!(not_reaching_id1.contains(&id2)); // id2 doesn't reach id1

        let not_reaching_id2: Vec<_> = pool.roots_not_reaching(id2).collect();
        assert!(!not_reaching_id2.contains(&join_id)); // join_id reaches id2
        assert!(not_reaching_id2.contains(&id1)); // id1 doesn't reach id2
    }

    #[test]
    fn test_root_pool_self_exclusion() {
        // Create a simple forest
        let mut forest = MastForest::new();

        let block = BasicBlockNode::new(alloc::vec![Operation::Add])
        .unwrap();
        let id = block.to_builder(&forest).add_to_forest(&mut forest).unwrap();

        let mut pool = RootPool::new(&forest);
        pool.push(id);

        // A node should not be in the list of roots not reaching itself
        let not_reaching: Vec<_> = pool.roots_not_reaching(id).collect();
        assert_eq!(not_reaching.len(), 0);
    }

    #[test]
    fn test_root_pool_transitive_reachability() {
        // Create a forest with nested control flow: join -> loop -> block
        let mut forest = MastForest::new();

        // Create basic blocks
        let block1 = BasicBlockNode::new(alloc::vec![Operation::Add])
        .unwrap();
        let block2 = BasicBlockNode::new(alloc::vec![Operation::Mul])
        .unwrap();

        let id1 = block1.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let id2 = block2.to_builder(&forest).add_to_forest(&mut forest).unwrap();

        // Create a loop that contains block1
        let loop_id = LoopNodeBuilder::new(id1).add_to_forest(&mut forest).unwrap();

        // Create a join that contains the loop and block2
        let join_id = JoinNodeBuilder::new([loop_id, id2]).add_to_forest(&mut forest).unwrap();

        // Create a RootPool
        let mut pool = RootPool::new(&forest);
        pool.push(id1);
        pool.push(id2);
        pool.push(loop_id);
        pool.push(join_id);

        // Test transitive reachability: join_id -> loop_id -> id1
        let not_reaching_id1: Vec<_> = pool.roots_not_reaching(id1).collect();
        assert!(!not_reaching_id1.contains(&join_id)); // join_id transitively reaches id1
        assert!(!not_reaching_id1.contains(&loop_id)); // loop_id reaches id1
        assert!(not_reaching_id1.contains(&id2)); // id2 doesn't reach id1
    }

    #[test]
    fn test_kernel_pool_basic_operations() {
        // Test empty pool
        let pool = KernelPool::new();
        assert!(pool.hashes().is_empty());
        assert!(!pool.contains(Word::from([Felt::ZERO; 4])));

        // Test insertion
        let mut pool = KernelPool::new();
        let hash1 = Word::from([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);
        let hash2 = Word::from([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]);

        pool.insert(hash1);
        assert_eq!(pool.hashes().len(), 1);
        assert!(pool.contains(hash1));
        assert!(!pool.contains(hash2));

        pool.insert(hash2);
        assert_eq!(pool.hashes().len(), 2);
        assert!(pool.contains(hash1));
        assert!(pool.contains(hash2));
    }

    #[test]
    fn test_kernel_pool_frozen() {
        // Test frozen pool
        let hash1 = Word::from([
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]);
        let hash2 = Word::from([
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]);

        let mut pool = KernelPool::new_frozen(alloc::vec![hash1]);
        assert_eq!(pool.hashes().len(), 1);
        assert!(pool.contains(hash1));

        // Insertion should be a no-op when frozen
        pool.insert(hash2);
        assert_eq!(pool.hashes().len(), 1);
        assert!(pool.contains(hash1));
        assert!(!pool.contains(hash2));
    }

    #[test]
    fn test_kernel_pool_has_candidate_in() {
        // Create a simple forest with basic blocks
        let mut forest = MastForest::new();

        let block1 = BasicBlockNode::new(alloc::vec![Operation::Add])
        .unwrap();
        let block2 = BasicBlockNode::new(alloc::vec![Operation::Mul])
        .unwrap();

        let id1 = block1.to_builder(&forest).add_to_forest(&mut forest).unwrap();
        let id2 = block2.to_builder(&forest).add_to_forest(&mut forest).unwrap();

        // Get the digests of the blocks
        let digest1 = forest.get_node_by_id(id1).unwrap().digest();
        let digest2 = forest.get_node_by_id(id2).unwrap().digest();

        // Create a pool with only digest1
        let pool = KernelPool::new_frozen(alloc::vec![digest1]);

        // Test has_candidate_in
        let roots = alloc::vec![id1, id2];
        assert!(pool.has_candidate_in(&roots, &forest)); // id1's digest is in the pool

        // Create a pool with neither digest
        let other_hash = Word::from([
            Felt::new_unchecked(99),
            Felt::new_unchecked(99),
            Felt::new_unchecked(99),
            Felt::new_unchecked(99),
        ]);
        let pool = KernelPool::new_frozen(alloc::vec![other_hash]);
        assert!(!pool.has_candidate_in(&roots, &forest)); // neither digest is in the pool

        // Create a pool with both digests
        let pool = KernelPool::new_frozen(alloc::vec![digest1, digest2]);
        assert!(pool.has_candidate_in(&roots, &forest)); // both digests are in the pool
    }

    #[test]
    fn test_kernel_pool_empty_roots() {
        // Test has_candidate_in with empty roots
        let forest = MastForest::new();
        let pool = KernelPool::new();
        let roots = alloc::vec![];
        assert!(!pool.has_candidate_in(&roots, &forest));
    }
}
