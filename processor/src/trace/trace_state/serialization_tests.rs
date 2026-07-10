use alloc::vec::Vec;

use miden_core::serde::{BudgetedReader, SliceReader};

use super::*;
use crate::mast::MastForestId;

#[test]
fn memory_replay_queues_reject_oversized_lengths_before_allocation() {
    let mut bytes = Vec::new();
    usize::MAX.write_into(&mut bytes);

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = read_memory_element_queue(&mut reader).unwrap_err();
    assert!(err.to_string().contains("exceeds reader allocation bound"));

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = read_memory_word_queue(&mut reader).unwrap_err();
    assert!(err.to_string().contains("exceeds reader allocation bound"));
}

#[test]
fn stack_state_read_rejects_depth_below_minimum() {
    let mut bytes = Vec::new();
    [ZERO; MIN_STACK_DEPTH].write_into(&mut bytes);
    (MIN_STACK_DEPTH - 1).write_into(&mut bytes);
    ZERO.write_into(&mut bytes);

    let err = StackState::read_from_bytes(&bytes).unwrap_err();
    assert!(err.to_string().contains("below minimum"));
}

#[test]
fn execution_replay_round_trip_preserves_replay_order() {
    let mut replay = ExecutionReplay::default();
    replay.block_stack.record_node_start_parent_addr(Felt::from_u32(7));
    replay
        .block_stack
        .record_node_end(Felt::from_u32(9), Felt::from_u32(8), Felt::from_u32(7));
    replay.execution_context.record_execution_context(ExecutionContextSystemInfo {
        parent_ctx: ContextId::from(3),
        parent_fn_hash: Word::from([ONE, ZERO, ZERO, ZERO]),
    });
    replay
        .stack_overflow
        .record_pop_overflow(Felt::from_u32(11), Felt::from_u32(10));
    replay
        .stack_overflow
        .record_restore_context_overflow_addr(17, Felt::from_u32(16));
    replay.memory_reads.record_read_element(
        Felt::from_u32(21),
        Felt::from_u32(20),
        ContextId::from(4),
        RowIndex::from(5_u32),
    );
    replay.memory_reads.record_read_word(
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]),
        Felt::from_u32(24),
        ContextId::from(4),
        RowIndex::from(6_u32),
    );
    replay.advice.record_pop_stack(Felt::from_u32(31));
    replay
        .advice
        .record_pop_stack_word(Word::from([Felt::from_u32(5), ZERO, ZERO, ZERO]));
    replay.advice.record_pop_stack_dword([
        Word::from([Felt::from_u32(6), ZERO, ZERO, ZERO]),
        Word::default(),
    ]);
    replay.hasher.record_permute(Felt::from_u32(40), [Felt::from_u32(41); 12]);
    replay.block_address.record_block_address(Felt::from_u32(50));
    replay
        .mast_forest_resolution
        .record_resolution(MastNodeId::from(2), MastForestId::from(1));

    let bytes = replay.to_bytes();
    let mut restored = ExecutionReplay::read_from_bytes(&bytes).unwrap();

    assert_eq!(restored.block_stack.replay_node_start_parent_addr().unwrap(), Felt::from_u32(7));
    let node_end = restored.block_stack.replay_node_end().unwrap();
    assert_eq!(node_end.ended_node_addr, Felt::from_u32(9));
    assert_eq!(node_end.prev_addr, Felt::from_u32(8));
    assert_eq!(node_end.prev_parent_addr, Felt::from_u32(7));
    let ctx = restored.execution_context.replay_execution_context().unwrap();
    assert_eq!(ctx.parent_ctx, ContextId::from(3));
    assert_eq!(ctx.parent_fn_hash, Word::from([ONE, ZERO, ZERO, ZERO]));
    assert_eq!(
        restored.stack_overflow.replay_pop_overflow().unwrap(),
        (Felt::from_u32(11), Felt::from_u32(10))
    );
    assert_eq!(
        restored.stack_overflow.replay_restore_context_overflow_addr().unwrap(),
        (17, Felt::from_u32(16))
    );
    assert_eq!(
        restored.memory_reads.replay_read_element(Felt::from_u32(20)).unwrap(),
        Felt::from_u32(21)
    );
    assert_eq!(
        restored.memory_reads.replay_read_word(Felt::from_u32(24)).unwrap(),
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)])
    );
    assert_eq!(restored.advice.replay_pop_stack().unwrap(), Felt::from_u32(31));
    assert_eq!(
        restored.advice.replay_pop_stack_word().unwrap(),
        Word::from([Felt::from_u32(5), ZERO, ZERO, ZERO])
    );
    assert_eq!(
        restored.advice.replay_pop_stack_dword().unwrap(),
        [Word::from([Felt::from_u32(6), ZERO, ZERO, ZERO]), Word::default()]
    );
    assert_eq!(
        restored.hasher.replay_permute().unwrap(),
        (Felt::from_u32(40), [Felt::from_u32(41); 12])
    );
    assert_eq!(restored.block_address.replay_block_address().unwrap(), Felt::from_u32(50));
    assert_eq!(
        restored.mast_forest_resolution.replay_resolution().unwrap(),
        (MastNodeId::from(2), MastForestId::from(1))
    );
}
