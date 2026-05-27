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
    BasicBlockNodeBuilder::from_op_batches(vec![batch], Vec::new(), digest)
        .build()
        .expect("basic block should build")
}

fn basic_block_from_batches(op_batches: Vec<OpBatch>) -> BasicBlockNode {
    BasicBlockNode {
        op_batches,
        digest: Word::default(),
        decorators: DecoratorStore::Owned {
            decorators: DecoratorList::new(),
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        },
    }
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
    let builder1 = BasicBlockNodeBuilder::new(operations.clone(), vec![]);

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
    let builder2 = BasicBlockNodeBuilder::new(operations, vec![]).with_digest(forced_digest);
    let node_id2 = builder2
        .add_to_forest(&mut forest)
        .expect("Failed to add basic block node to forest with forced digest");
    let node2 = forest.get_node_by_id(node_id2).unwrap().unwrap_basic_block();

    assert_ne!(normal_digest, forced_digest, "Normal and forced digests should be different");
    assert_eq!(node2.digest(), forced_digest, "Forced digest should be used");
}
