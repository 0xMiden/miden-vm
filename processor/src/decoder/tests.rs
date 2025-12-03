use alloc::vec::Vec;
use std::sync::Arc;

use miden_air::trace::{
    CTX_COL_IDX, DECODER_TRACE_RANGE, DECODER_TRACE_WIDTH, FN_HASH_RANGE, SYS_TRACE_RANGE,
    SYS_TRACE_WIDTH,
    decoder::{
        ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_RANGE, IN_SPAN_COL_IDX, NUM_HASHER_COLUMNS,
        NUM_OP_BATCH_FLAGS, NUM_OP_BITS, OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS,
        OP_BATCH_8_GROUPS, OP_BATCH_FLAGS_RANGE, OP_BITS_EXTRA_COLS_RANGE, OP_BITS_OFFSET,
        OP_INDEX_COL_IDX,
    },
};
use miden_core::{
    EMPTY_WORD, EventName, ONE, Program, WORD_SIZE, ZERO,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, JoinNodeBuilder, LoopNodeBuilder,
        MastForest, MastForestContributor, MastNodeExt, OP_BATCH_SIZE, SplitNodeBuilder,
    },
};
use miden_utils_testing::rand::rand_value;

use super::{
    super::{
        ExecutionOptions, ExecutionTrace, Felt, Kernel, Operation, Process, StackInputs, Word,
    },
    build_op_group,
};
use crate::{AdviceInputs, DefaultHost, NoopEventHandler};

// CONSTANTS
// ================================================================================================

const TWO: Felt = Felt::new(2);
const EIGHT: Felt = Felt::new(8);
const NINE: Felt = Felt::new(9);
const FOURTEEN: Felt = Felt::new(14);

const INIT_ADDR: Felt = ONE;
const EMIT_EVENT: EventName = EventName::new("test::emit::event");

// TYPE ALIASES
// ================================================================================================

type SystemTrace = [Vec<Felt>; SYS_TRACE_WIDTH];
type DecoderTrace = [Vec<Felt>; DECODER_TRACE_WIDTH];

// SPAN BLOCK TESTS
// ================================================================================================

#[test]
fn basic_block_one_group() {
    let ops = vec![Operation::Pad, Operation::Add, Operation::Mul];
    let (basic_block, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block = mast_forest[basic_block_id].unwrap_basic_block().clone();
        mast_forest.make_root(basic_block_id);

        (basic_block, Program::new(mast_forest.into(), basic_block_id))
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 2, INIT_ADDR, Operation::Add, 0, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Mul, 0, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash = program.hash();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(), // first group should contain op batch
            vec![build_op_group(&ops[1..])],
            vec![build_op_group(&ops[2..])],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn basic_block_small() {
    let iv = [ONE, TWO];
    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Add,
        Operation::Swap,
        Operation::Drop,
    ];
    let (basic_block, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block = mast_forest[basic_block_id].unwrap_basic_block().clone();
        mast_forest.make_root(basic_block_id);

        (basic_block, Program::new(mast_forest.into(), basic_block_id))
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 4, 0, 0);
    check_op_decoding_with_imm(&trace, 1, INIT_ADDR, ONE, 1, 3, 0, 1);
    check_op_decoding_with_imm(&trace, 2, INIT_ADDR, TWO, 2, 2, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Add, 1, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Swap, 1, 3, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Drop, 1, 4, 1);

    // starting new group: NOOP group is inserted by the processor to make sure number of groups
    // is a power of two
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 8, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash = program.hash();

    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..])],
            vec![build_op_group(&ops[2..])],
            vec![build_op_group(&ops[3..])],
            vec![build_op_group(&ops[4..])],
            vec![],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 8..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn basic_block_small_with_emit() {
    let emit_event_felt = EMIT_EVENT.to_event_id().as_felt();
    let ops = vec![
        Operation::Push(ONE),
        Operation::Push(emit_event_felt),
        Operation::Emit,
        Operation::Drop,
        Operation::Add,
    ];
    let (basic_block, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block = mast_forest[basic_block_id].unwrap_basic_block().clone();
        mast_forest.make_root(basic_block_id);

        (basic_block, Program::new(mast_forest.into(), basic_block_id))
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 4, 0, 0);
    check_op_decoding_with_imm(&trace, 1, INIT_ADDR, ONE, 1, 3, 0, 1);
    check_op_decoding_with_imm(&trace, 2, INIT_ADDR, emit_event_felt, 2, 2, 1, 1);
    check_op_decoding(&trace, 3, INIT_ADDR, Operation::Emit, 1, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Drop, 1, 3, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Add, 1, 4, 1);
    // starting new group: NOOP group is inserted by the processor to make sure number of groups
    // is a power of two
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 8, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash = program.hash();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..])],
            vec![build_op_group(&ops[2..])],
            vec![build_op_group(&ops[3..])],
            vec![build_op_group(&ops[4..])],
            vec![],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 8..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn basic_block() {
    let iv = [ONE, TWO, Felt::new(3), Felt::new(4), Felt::new(5)];
    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Pad,
        Operation::Mul,
        Operation::Add,
        Operation::Drop,
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Mul,
        Operation::Add,
        Operation::Inv,
        Operation::Swap,
        Operation::Drop,
    ];
    let (basic_block, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block = mast_forest[basic_block_id].unwrap_basic_block().clone();
        mast_forest.make_root(basic_block_id);

        (basic_block, Program::new(mast_forest.into(), basic_block_id))
    };
    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 8, 0, 0);
    check_op_decoding_with_imm(&trace, 1, INIT_ADDR, iv[0], 1, 7, 0, 1);
    check_op_decoding_with_imm(&trace, 2, INIT_ADDR, iv[1], 2, 6, 1, 1);
    check_op_decoding_with_imm(&trace, 3, INIT_ADDR, iv[2], 3, 5, 2, 1);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Pad, 4, 3, 1);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Mul, 4, 4, 1);
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Add, 4, 5, 1);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::Drop, 4, 6, 1);
    check_op_decoding_with_imm(&trace, 8, INIT_ADDR, iv[3], 4, 4, 7, 1);
    // NOOP inserted by the processor to make sure the group doesn't end with a PUSH
    check_op_decoding(&trace, 9, INIT_ADDR, Operation::Noop, 3, 8, 1);
    // starting new operation group
    check_op_decoding_with_imm(&trace, 10, INIT_ADDR, iv[4], 6, 2, 0, 1);
    check_op_decoding(&trace, 11, INIT_ADDR, Operation::Mul, 1, 1, 1);
    check_op_decoding(&trace, 12, INIT_ADDR, Operation::Add, 1, 2, 1);
    check_op_decoding(&trace, 13, INIT_ADDR, Operation::Inv, 1, 3, 1);
    check_op_decoding(&trace, 14, INIT_ADDR, Operation::Swap, 1, 4, 1);
    check_op_decoding(&trace, 15, INIT_ADDR, Operation::Drop, 1, 5, 1);

    // NOOP inserted by the processor to make sure the number of groups is a power of two
    check_op_decoding(&trace, 16, INIT_ADDR, Operation::Noop, 0, 0, 1);
    check_op_decoding(&trace, 17, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 18, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash = program.hash();
    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..8])], // first group starts
            vec![build_op_group(&ops[2..8])],
            vec![build_op_group(&ops[3..8])],
            vec![build_op_group(&ops[4..8])],
            vec![build_op_group(&ops[5..8])],
            vec![build_op_group(&ops[6..8])],
            vec![build_op_group(&ops[7..8])],
            vec![], // NOOP inserted after push
            vec![],
            vec![build_op_group(&ops[9..])], // next group starts
            vec![build_op_group(&ops[10..])],
            vec![build_op_group(&ops[11..])],
            vec![build_op_group(&ops[12..])],
            vec![build_op_group(&ops[13..])],
            vec![],
            vec![],                // a group with single NOOP added at the end
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 18..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn span_block_with_respan() {
    let iv = [
        ONE,
        TWO,
        Felt::new(3),
        Felt::new(4),
        Felt::new(5),
        Felt::new(6),
        Felt::new(7),
        EIGHT,
        Felt::new(9),
    ];

    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Push(iv[5]),
        Operation::Push(iv[6]),
        Operation::Push(iv[7]),
        Operation::Add,
        Operation::Push(iv[8]),
        Operation::SwapDW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ];
    let (basic_block, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(ops.clone(), Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block = mast_forest[basic_block_id].unwrap_basic_block().clone();
        mast_forest.make_root(basic_block_id);

        (basic_block, Program::new(mast_forest.into(), basic_block_id))
    };
    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Span, 12, 0, 0);
    check_op_decoding_with_imm(&trace, 1, INIT_ADDR, iv[0], 1, 11, 0, 1);
    check_op_decoding_with_imm(&trace, 2, INIT_ADDR, iv[1], 2, 10, 1, 1);
    check_op_decoding_with_imm(&trace, 3, INIT_ADDR, iv[2], 3, 9, 2, 1);
    check_op_decoding_with_imm(&trace, 4, INIT_ADDR, iv[3], 4, 8, 3, 1);
    check_op_decoding_with_imm(&trace, 5, INIT_ADDR, iv[4], 5, 7, 4, 1);
    check_op_decoding_with_imm(&trace, 6, INIT_ADDR, iv[5], 6, 6, 5, 1);
    check_op_decoding_with_imm(&trace, 7, INIT_ADDR, iv[6], 7, 5, 6, 1);
    // NOOP inserted by the processor to make sure the group doesn't end with a PUSH
    check_op_decoding(&trace, 8, INIT_ADDR, Operation::Noop, 4, 7, 1);
    // RESPAN since the previous batch is full
    let batch1_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 9, INIT_ADDR, Operation::Respan, 4, 0, 0);
    check_op_decoding_with_imm(&trace, 10, batch1_addr, iv[7], 1, 3, 0, 1);
    check_op_decoding(&trace, 11, batch1_addr, Operation::Add, 2, 1, 1);
    check_op_decoding_with_imm(&trace, 12, batch1_addr, iv[8], 2, 2, 2, 1);

    check_op_decoding(&trace, 13, batch1_addr, Operation::SwapDW, 1, 3, 1);
    check_op_decoding(&trace, 14, batch1_addr, Operation::Drop, 1, 4, 1);
    check_op_decoding(&trace, 15, batch1_addr, Operation::Drop, 1, 5, 1);
    check_op_decoding(&trace, 16, batch1_addr, Operation::Drop, 1, 6, 1);
    check_op_decoding(&trace, 17, batch1_addr, Operation::Drop, 1, 7, 1);
    check_op_decoding(&trace, 18, batch1_addr, Operation::Drop, 1, 8, 1);
    check_op_decoding(&trace, 19, batch1_addr, Operation::Drop, 0, 0, 1);
    check_op_decoding(&trace, 20, batch1_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 21, batch1_addr, Operation::Drop, 0, 2, 1);

    check_op_decoding(&trace, 22, batch1_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 23, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    let program_hash = program.hash();

    check_hasher_state(
        &trace,
        vec![
            basic_block.op_batches()[0].groups().to_vec(),
            vec![build_op_group(&ops[1..7])], // first group starts
            vec![build_op_group(&ops[2..7])],
            vec![build_op_group(&ops[3..7])],
            vec![build_op_group(&ops[4..7])],
            vec![build_op_group(&ops[5..7])],
            vec![build_op_group(&ops[6..7])],
            vec![],
            vec![], // a NOOP inserted after last PUSH
            basic_block.op_batches()[1].groups().to_vec(),
            vec![build_op_group(&ops[8..16])], // next group starts
            vec![build_op_group(&ops[9..16])],
            vec![build_op_group(&ops[10..16])],
            vec![build_op_group(&ops[11..16])],
            vec![build_op_group(&ops[12..16])],
            vec![build_op_group(&ops[13..16])],
            vec![build_op_group(&ops[14..16])],
            vec![build_op_group(&ops[15..16])],
            vec![],
            vec![build_op_group(&ops[17..])],
            vec![build_op_group(&ops[18..])],
            vec![],
            program_hash.to_vec(), // last row should contain program hash
        ],
    );

    // HALT opcode and program hash gets propagated to the last row
    for i in 23..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// JOIN BLOCK TESTS
// ================================================================================================

#[test]
fn join_node() {
    let (basic_block1, basic_block2, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block1 = mast_forest[basic_block1_id].unwrap_basic_block().clone();
        let basic_block2 = mast_forest[basic_block2_id].unwrap_basic_block().clone();

        let join_node_id = JoinNodeBuilder::new([basic_block1_id, basic_block2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(join_node_id);

        (basic_block1, basic_block2, Program::new(mast_forest.into(), join_node_id))
    };

    let (trace, trace_len) = build_trace(&[], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting first span
    let span1_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, span1_addr, Operation::Mul, 0, 0, 1);
    check_op_decoding(&trace, 3, span1_addr, Operation::End, 0, 0, 0);
    // starting second span
    let span2_addr = INIT_ADDR + Felt::new(16);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 5, span2_addr, Operation::Add, 0, 0, 1);
    check_op_decoding(&trace, 6, span2_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 7, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 8, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash = basic_block1.digest();
    let span2_hash = basic_block2.digest();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(span1_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the second SPAN, the hasher state is set to the hash of the second child
    assert_eq!(span2_hash, get_hasher_state1(&trace, 6));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 6));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 7));

    // HALT opcode and program hash gets propagated to the last row
    for i in 9..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// SPLIT BLOCK TESTS
// ================================================================================================

#[test]
fn split_node_true() {
    let (basic_block1, basic_block2, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block1 = mast_forest[basic_block1_id].unwrap_basic_block().clone();
        let basic_block2 = mast_forest[basic_block2_id].unwrap_basic_block().clone();

        let split_node_id = SplitNodeBuilder::new([basic_block1_id, basic_block2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(split_node_id);

        (basic_block1, basic_block2, Program::new(mast_forest.into(), split_node_id))
    };

    let (trace, trace_len) = build_trace(&[1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let basic_block_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Split, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, basic_block_addr, Operation::Mul, 0, 0, 1);
    check_op_decoding(&trace, 3, basic_block_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash = basic_block1.digest();
    let span2_hash = basic_block2.digest();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the SPAN, the hasher state is set to the hash of the first child
    assert_eq!(span1_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 4));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 4));

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn split_node_false() {
    let (basic_block1, basic_block2, program) = {
        let mut mast_forest = MastForest::new();

        let basic_block1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block1 = mast_forest[basic_block1_id].unwrap_basic_block().clone();
        let basic_block2 = mast_forest[basic_block2_id].unwrap_basic_block().clone();

        let split_node_id = SplitNodeBuilder::new([basic_block1_id, basic_block2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(split_node_id);

        (basic_block1, basic_block2, Program::new(mast_forest.into(), split_node_id))
    };

    let (trace, trace_len) = build_trace(&[0], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let basic_block_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Split, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, basic_block_addr, Operation::Add, 0, 0, 1);
    check_op_decoding(&trace, 3, basic_block_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 4, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let span1_hash = basic_block1.digest();
    let span2_hash = basic_block2.digest();
    assert_eq!(span1_hash, get_hasher_state1(&trace, 0));
    assert_eq!(span2_hash, get_hasher_state2(&trace, 0));

    // at the end of the SPAN, the hasher state is set to the hash of the second child
    assert_eq!(span2_hash, get_hasher_state1(&trace, 3));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 3));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 4));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 4));

    // HALT opcode and program hash gets propagated to the last row
    for i in 6..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// LOOP BLOCK TESTS
// ================================================================================================

#[test]
fn loop_node() {
    let (loop_body, program) = {
        let mut mast_forest = MastForest::new();

        let loop_body_id =
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                .add_to_forest(&mut mast_forest)
                .unwrap();
        let loop_body = mast_forest[loop_body_id].unwrap_basic_block().clone();
        let loop_node_id =
            LoopNodeBuilder::new(loop_body_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_node_id);

        (loop_body, Program::new(mast_forest.into(), loop_node_id))
    };

    let (trace, trace_len) = build_trace(&[0, 1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let body_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, body_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 3, body_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 4, body_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 6, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash = loop_body.digest();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // at the end of the SPAN block, the hasher state is also set to the hash of the loops body,
    // and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 4));
    assert_eq!(Word::from([ONE, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 4));

    // the hash of the program is located in the last END row; this row should also have is_loop
    // flag set to ONE
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 5));
    assert_eq!(Word::from([ZERO, ONE, ZERO, ZERO]), get_hasher_state2(&trace, 5));

    // HALT opcode and program hash gets propagated to the last row
    for i in 7..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn loop_node_skip() {
    let (loop_body, program) = {
        let mut mast_forest = MastForest::new();

        let loop_body_id =
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                .add_to_forest(&mut mast_forest)
                .unwrap();
        let loop_body = mast_forest[loop_body_id].unwrap_basic_block().clone();
        let loop_node_id =
            LoopNodeBuilder::new(loop_body_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_node_id);

        (loop_body, Program::new(mast_forest.into(), loop_node_id))
    };

    let (trace, trace_len) = build_trace(&[0], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 2, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash = loop_body.digest();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // the hash of the program is located in the last END row; is_loop is not set to ONE because
    // we didn't enter the loop's body
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 1));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 1));

    // HALT opcode and program hash gets propagated to the last row
    for i in 3..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

#[test]
fn loop_node_repeat() {
    let (loop_body, program) = {
        let mut mast_forest = MastForest::new();

        let loop_body_id =
            BasicBlockNodeBuilder::new(vec![Operation::Pad, Operation::Drop], Vec::new())
                .add_to_forest(&mut mast_forest)
                .unwrap();
        let loop_body = mast_forest[loop_body_id].unwrap_basic_block().clone();
        let loop_node_id =
            LoopNodeBuilder::new(loop_body_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_node_id);

        (loop_body, Program::new(mast_forest.into(), loop_node_id))
    };

    let (trace, trace_len) = build_trace(&[0, 1, 1], &program);

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    let iter1_addr = INIT_ADDR + EIGHT;
    let iter2_addr = INIT_ADDR + Felt::new(16);

    check_op_decoding(&trace, 0, ZERO, Operation::Loop, 0, 0, 0);
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 2, iter1_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 3, iter1_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 4, iter1_addr, Operation::End, 0, 0, 0);
    // start second iteration
    check_op_decoding(&trace, 5, INIT_ADDR, Operation::Repeat, 0, 0, 0);
    check_op_decoding(&trace, 6, INIT_ADDR, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 7, iter2_addr, Operation::Pad, 0, 0, 1);
    check_op_decoding(&trace, 8, iter2_addr, Operation::Drop, 0, 1, 1);
    check_op_decoding(&trace, 9, iter2_addr, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 10, INIT_ADDR, Operation::End, 0, 0, 0);
    check_op_decoding(&trace, 11, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to the hash of the loop's body
    let loop_body_hash = loop_body.digest();
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 0));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&trace, 0));

    // at the end of the first iteration, the hasher state is also set to the hash of the loops
    // body, and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 4));
    assert_eq!(Word::from([ONE, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 4));

    // at the RESPAN row hasher state is copied over from the previous row
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 5));
    assert_eq!(Word::from([ONE, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 5));

    // at the end of the second iteration, the hasher state is again set to the hash of the loops
    // body, and is_loop_body flag is also set to ONE
    assert_eq!(loop_body_hash, get_hasher_state1(&trace, 9));
    assert_eq!(Word::from([ONE, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 9));

    // the hash of the program is located in the last END row; this row should also have is_loop
    // flag set to ONE
    let program_hash = program.hash();
    assert_eq!(program_hash, get_hasher_state1(&trace, 10));
    assert_eq!(Word::from([ZERO, ONE, ZERO, ZERO]), get_hasher_state2(&trace, 10));

    // HALT opcode and program hash gets propagated to the last row
    for i in 12..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// CALL BLOCK TESTS
// ================================================================================================

#[test]
#[rustfmt::skip]
#[allow(clippy::needless_range_loop)]
fn test_call_decoding() {
    // build a program which looks like this:
    //
    // pub proc foo
    //     add
    // end
    //
    // proc bar
    //     mul
    //     call.foo
    // end
    //
    // begin
    //    push.1 push.2
    //    call.bar
    //    drop
    //    drop
    // end

    let mut mast_forest = MastForest::new();

    // build foo procedure body
    let foo_root_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let foo_root = mast_forest[foo_root_id].clone();
    mast_forest.make_root(foo_root_id);
    let kernel = Kernel::new(&[foo_root.digest()]).unwrap();

    // build bar procedure body
    let bar_basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let bar_basic_block = mast_forest[bar_basic_block_id].clone();

    let foo_call_node_id = CallNodeBuilder::new(foo_root_id)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let foo_call_node = mast_forest[foo_call_node_id].clone();

    let bar_root_node_id = JoinNodeBuilder::new([bar_basic_block_id, foo_call_node_id]).add_to_forest(&mut mast_forest).unwrap();
    let bar_root_node = mast_forest[bar_root_node_id].clone();
    mast_forest.make_root(bar_root_node_id);

    // build the program
    let first_basic_block_id = BasicBlockNodeBuilder::new(vec![
        Operation::Push(ONE),
        Operation::Push(TWO),
    ], Vec::new()).add_to_forest(&mut mast_forest).unwrap();
    let first_basic_block = mast_forest[first_basic_block_id].clone();

    let last_basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Drop, Operation::Drop], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let last_basic_block = mast_forest[last_basic_block_id].clone();

    let bar_call_node_id = CallNodeBuilder::new(bar_root_node_id)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let bar_call_node = mast_forest[bar_call_node_id].clone();

    let inner_join_node_id = JoinNodeBuilder::new([first_basic_block_id, bar_call_node_id]).add_to_forest(&mut mast_forest).unwrap();
    let inner_join_node = mast_forest[inner_join_node_id].clone();

    let program_root_node_id = JoinNodeBuilder::new([inner_join_node_id, last_basic_block_id]).add_to_forest(&mut mast_forest).unwrap();
    let program_root_node = mast_forest[program_root_node_id].clone();
    mast_forest.make_root(program_root_node_id);

    let program = Program::with_kernel(mast_forest.into(), program_root_node_id, kernel.clone());

    let (sys_trace, dec_trace,   trace_len) =
        build_call_trace(&program, kernel);

    let mut row_idx = 0;
    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&dec_trace, row_idx, ZERO, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting the internal JOIN block
    let inner_join_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting first SPAN block
    let first_basic_block_addr = inner_join_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::Span, 4, 0, 0);
    row_idx += 1;
    check_op_decoding_with_imm(&dec_trace, row_idx, first_basic_block_addr, ONE, 1, 3, 0, 1);
    row_idx += 1;
    check_op_decoding_with_imm(&dec_trace, row_idx, first_basic_block_addr, TWO, 2, 2, 1, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::Noop, 1, 2, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::Noop, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting CALL block for bar
    let call_addr = first_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::Call, 0, 0, 0);
    row_idx += 1;
    // starting JOIN block inside bar
    let bar_join_addr = call_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, call_addr, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting SPAN block inside bar
    let bar_basic_block_addr = bar_join_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, bar_basic_block_addr, Operation::Mul, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, bar_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting CALL to foo
    let syscall_addr = bar_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::Call, 0, 0, 0);
    row_idx += 1;
    // starting SPAN block within syscall
    let syscall_basic_block_addr = syscall_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, syscall_addr, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, syscall_basic_block_addr, Operation::Add, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, syscall_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;
    // ending SYSCALL block
    check_op_decoding(&dec_trace, row_idx, syscall_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending CALL block
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::End, 0, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, call_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending the inner JOIN block
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting the last SPAN block
    let last_basic_block_addr = syscall_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::Drop, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::Drop, 0, 1, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending the program
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::End, 0, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    // in the first row, the hasher state is set to hashes of (inner_join, last_span)
    let inner_join_hash = inner_join_node.digest();
    let last_span_hash = last_basic_block.digest();
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 0));
    assert_eq!(last_span_hash, get_hasher_state2(&dec_trace, 0));

    // in the second row, the hasher state is set to hashes of (first_span, bar_call)
    let first_span_hash = first_basic_block.digest();
    let bar_call_hash = bar_call_node.digest();
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 1));
    assert_eq!(bar_call_hash, get_hasher_state2(&dec_trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 7));

    // in the 8th row, we start the CALL block which has bar_join as its only child
    let bar_root_hash = bar_root_node.digest();
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 8));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 8));

    // in the 9th row, the hasher state for JOIN is set to hashes of (bar_span, foo_call)
    let bar_span_hash = bar_basic_block.digest();
    let foo_call_hash = foo_call_node.digest();
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 9));
    assert_eq!(foo_call_hash, get_hasher_state2(&dec_trace, 9));

    // at the end of the bar_span, the hasher state is set to the hash of the first child
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 12));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 12));

    // in the 13th row, we start the CALL block which has foo_span as its only child
    let foo_root_hash = foo_root.digest();
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 13));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 13));

    // at the end of the foo block, the hasher state is set to the hash of the first child
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 16));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 16));

    // CALL ends in the 17th row; the second to last element of the hasher state
    // is set to ONE because we are exiting a CALL
    assert_eq!(foo_call_hash, get_hasher_state1(&dec_trace, 17));
    assert_eq!(Word::from([ZERO, ZERO, ONE, ZERO]), get_hasher_state2(&dec_trace, 17));

    // internal bar_join block ends in the 18th row
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 18));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 18));

    // CALL block ends in the 19th row; the second to last element of the hasher state
    // is set to ONE because we are exiting a CALL block
    assert_eq!(bar_call_hash, get_hasher_state1(&dec_trace, 19));
    assert_eq!(Word::from([ZERO, ZERO, ONE, ZERO]), get_hasher_state2(&dec_trace, 19));

    // internal JOIN block ends in the 20th row
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 20));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 20));

    // last span ends in the 24th row
    assert_eq!(last_span_hash, get_hasher_state1(&dec_trace, 24));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 24));

    // the program ends in the 25th row
    let program_hash = program_root_node.digest();
    assert_eq!(program_hash, get_hasher_state1(&dec_trace, 25));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 25));

    // HALT opcode and program hash gets propagated to the last row
    for i in 26..trace_len {
        assert!(contains_op(&dec_trace, i, Operation::Halt));
        assert_eq!(ZERO, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&dec_trace, i));
    }

    // --- check the ctx column -------------------------------------------------------------------

    // for the first 8 cycles, we are in the root context
    for i in 0..9 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when CALL operation is executed, we switch to the new context; the ID of this context is 8
    // because we switch to it at the 9th cycle
    for i in 9..14 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], NINE);
    }

    // when CALL operation is executed, we switch to a new context (14)
    for i in 14..18 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], FOURTEEN);
    }

    // when CALL ends, we return to the previous context
    for i in 18..20 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], NINE);
    }

    // once the CALL exited, we go back to the root context
    for i in 20..trace_len {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // --- check fn hash columns ------------------------------------------------------------------

    // before the CALL operation is executed, we are in a root context and thus fn_hash is ZEROs.
    for i in 0..9 {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }

    // inside the first CALL, fn hash is set to bar's root hash
    for i in 9..14 {
        assert_eq!(get_fn_hash(&sys_trace, i), bar_root_hash);
    }

    // fn_hash set to foo inside the second CALL
    for i in 14..18 {
        assert_eq!(get_fn_hash(&sys_trace, i), foo_root_hash);
    }

    // return from the first call
    for i in 18..20 {
        assert_eq!(get_fn_hash(&sys_trace, i), bar_root_hash);
    }

    // after the CALL block is ended, we are back in the root context
    for i in 20..trace_len {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }
}

// SYSCALL TESTS
// ================================================================================================

#[test]
#[rustfmt::skip]
#[allow(clippy::needless_range_loop)]
fn test_syscall_decoding() {
    // build a program which looks like this:
    //
    // --- kernel ---
    // pub proc foo
    //     add
    // end
    //
    // --- program ---
    // proc bar
    //     mul
    //     syscall.foo
    // end
    //
    // begin
    //    push.1 push.2
    //    call.bar
    //    drop
    //    drop
    // end

    let mut mast_forest = MastForest::new();

    // build foo procedure body
    let foo_root_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let foo_root = mast_forest[foo_root_id].clone();
    mast_forest.make_root(foo_root_id);
    let kernel = Kernel::new(&[foo_root.digest()]).unwrap();

    // build bar procedure body
    let bar_basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let bar_basic_block = mast_forest[bar_basic_block_id].clone();

    let foo_call_node_id = CallNodeBuilder::new_syscall(foo_root_id)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let foo_call_node = mast_forest[foo_call_node_id].clone();

    let bar_root_node_id = JoinNodeBuilder::new([bar_basic_block_id, foo_call_node_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let bar_root_node = mast_forest[bar_root_node_id].clone();
    mast_forest.make_root(bar_root_node_id);

    // build the program
    let first_basic_block_id = BasicBlockNodeBuilder::new(vec![
        Operation::Push(ONE),
        Operation::Push(TWO),
    ], Vec::new()).add_to_forest(&mut mast_forest).unwrap();
    let first_basic_block = mast_forest[first_basic_block_id].clone();

    let last_basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Drop, Operation::Drop], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let last_basic_block = mast_forest[last_basic_block_id].clone();

    let bar_call_node_id = CallNodeBuilder::new(bar_root_node_id)
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let bar_call_node = mast_forest[bar_call_node_id].clone();

    let inner_join_node_id = JoinNodeBuilder::new([first_basic_block_id, bar_call_node_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let inner_join_node = mast_forest[inner_join_node_id].clone();

    let program_root_node_id = JoinNodeBuilder::new([inner_join_node_id, last_basic_block_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let program_root_node = mast_forest[program_root_node_id].clone();
    mast_forest.make_root(program_root_node_id);

    let program = Program::with_kernel(mast_forest.into(), program_root_node_id, kernel.clone());

    let (sys_trace, dec_trace,   trace_len) =
        build_call_trace(&program, kernel);

    let mut row_idx = 0;
    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&dec_trace, row_idx, ZERO, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting the internal JOIN block
    let inner_join_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting first SPAN block
    let first_basic_block_addr = inner_join_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::Span, 4, 0, 0);
    row_idx += 1;
    check_op_decoding_with_imm(&dec_trace, row_idx, first_basic_block_addr, ONE, 1, 3, 0, 1);
    row_idx += 1;
    check_op_decoding_with_imm(&dec_trace, row_idx, first_basic_block_addr, TWO, 2, 2, 1, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::Noop, 1, 2, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::Noop, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, first_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting CALL block for bar
    let call_addr = first_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::Call, 0, 0, 0);
    row_idx += 1;
    // starting JOIN block inside bar
    let bar_join_addr = call_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, call_addr, Operation::Join, 0, 0, 0);
    row_idx += 1;
    // starting SPAN block inside bar
    let bar_basic_block_addr = bar_join_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, bar_basic_block_addr, Operation::Mul, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, bar_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting SYSCALL block for bar
    let syscall_addr = bar_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::SysCall, 0, 0, 0);
    row_idx += 1;
    // starting SPAN block within syscall
    let syscall_basic_block_addr = syscall_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, syscall_addr, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, syscall_basic_block_addr, Operation::Add, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, syscall_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;
    // ending SYSCALL block
    check_op_decoding(&dec_trace, row_idx, syscall_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending CALL block
    check_op_decoding(&dec_trace, row_idx, bar_join_addr, Operation::End, 0, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, call_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending the inner JOIN block
    check_op_decoding(&dec_trace, row_idx, inner_join_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // starting the last SPAN block
    let last_basic_block_addr = syscall_basic_block_addr + EIGHT;
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::Span, 1, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::Drop, 0, 0, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::Drop, 0, 1, 1);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, last_basic_block_addr, Operation::End, 0, 0, 0);
    row_idx += 1;

    // ending the program
    check_op_decoding(&dec_trace, row_idx, INIT_ADDR, Operation::End, 0, 0, 0);
    row_idx += 1;
    check_op_decoding(&dec_trace, row_idx, ZERO, Operation::Halt, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------
    // in the first row, the hasher state is set to hashes of (inner_join, last_span)
    let inner_join_hash = inner_join_node.digest();
    let last_span_hash = last_basic_block.digest();
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 0));
    assert_eq!(last_span_hash, get_hasher_state2(&dec_trace, 0));

    // in the second row, the hasher state is set to hashes of (first_span, bar_call)
    let first_span_hash = first_basic_block.digest();
    let bar_call_hash = bar_call_node.digest();
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 1));
    assert_eq!(bar_call_hash, get_hasher_state2(&dec_trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(first_span_hash, get_hasher_state1(&dec_trace, 7));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 7));

    // in the 8th row, we start the CALL block which has bar_join as its only child
    let bar_root_hash = bar_root_node.digest();
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 8));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 8));

    // in the 9th row, the hasher state for JOIN is set to hashes of (bar_span, foo_call)
    let bar_span_hash = bar_basic_block.digest();
    let foo_call_hash = foo_call_node.digest();
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 9));
    assert_eq!(foo_call_hash, get_hasher_state2(&dec_trace, 9));

    // at the end of the bar_span, the hasher state is set to the hash of the first child
    assert_eq!(bar_span_hash, get_hasher_state1(&dec_trace, 12));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 12));

    // in the 13th row, we start the SYSCALL block which has foo_span as its only child
    let foo_root_hash = foo_root.digest();
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 13));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 13));

    // at the end of the foo block, the hasher state is set to the hash of the first child
    assert_eq!(foo_root_hash, get_hasher_state1(&dec_trace, 16));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 16));

    // SYSCALL block ends in the 17th row; the last element of the hasher state
    // is set to ONE because we are exiting a SYSCALL block
    assert_eq!(foo_call_hash, get_hasher_state1(&dec_trace, 17));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ONE]), get_hasher_state2(&dec_trace, 17));

    // internal bar_join block ends in the 18th row
    assert_eq!(bar_root_hash, get_hasher_state1(&dec_trace, 18));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 18));

    // CALL block ends in the 19th row; the second to last element of the hasher state
    // is set to ONE because we are exiting a CALL block
    assert_eq!(bar_call_hash, get_hasher_state1(&dec_trace, 19));
    assert_eq!(Word::from([ZERO, ZERO, ONE, ZERO]), get_hasher_state2(&dec_trace, 19));

    // internal JOIN block ends in the 20th row
    assert_eq!(inner_join_hash, get_hasher_state1(&dec_trace, 20));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 20));

    // last span ends in the 24th row
    assert_eq!(last_span_hash, get_hasher_state1(&dec_trace, 24));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 24));

    // the program ends in the 25th row
    let program_hash = program_root_node.digest();
    assert_eq!(program_hash, get_hasher_state1(&dec_trace, 25));
    assert_eq!(EMPTY_WORD, get_hasher_state2(&dec_trace, 25));

    // HALT opcode and program hash gets propagated to the last row
    for i in 26..trace_len {
        assert!(contains_op(&dec_trace, i, Operation::Halt));
        assert_eq!(ZERO, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, dec_trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&dec_trace, i));
    }

    // --- check the ctx column -------------------------------------------------------------------

    // for the first 8 cycles, we are in the root context
    for i in 0..9 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when CALL operation is executed, we switch to the new context; the ID of this context is 8
    // because we switch to it at the 9th cycle
    for i in 9..14 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], NINE);
    }

    // when SYSCALL operation is executed, we switch back to the root context (0)
    for i in 14..18 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // when SYSCALL ends, we return to the context of the CALL block
    for i in 18..20 {
        assert_eq!(sys_trace[CTX_COL_IDX][i], NINE);
    }

    // once the CALL block exited, we go back to the root context
    for i in 20..trace_len {
        assert_eq!(sys_trace[CTX_COL_IDX][i], ZERO);
    }

    // --- check fn hash columns ------------------------------------------------------------------

    // before the CALL operation is executed, we are in a root context and thus fn_hash is ZEROs.
    for i in 0..9 {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }

    // inside the CALL block (and the invoked from it SYSCALL block), fn hash is set to the hash
    // of the bar procedure
    for i in 9..20 {
        assert_eq!(get_fn_hash(&sys_trace, i), bar_root_hash);
    }

    // after the CALL block is ended, we are back in the root context
    for i in 20..trace_len {
        assert_eq!(get_fn_hash(&sys_trace, i), EMPTY_WORD);
    }
}

// DYN BLOCK TESTS
// ================================================================================================
#[test]
fn dyn_block() {
    // Equivalent masm:
    //
    // proc foo
    //   push.1 add
    // end
    //
    // begin
    //   # stack: [40, DIGEST]
    //   mstorew
    //   push.42
    //   dynexec
    // end

    const FOO_ROOT_NODE_ADDR: u64 = 40;
    const PUSH_40_OP: Operation = Operation::Push(Felt::new(FOO_ROOT_NODE_ADDR));

    let mut mast_forest = MastForest::new();

    let foo_root_node_id =
        BasicBlockNodeBuilder::new(vec![Operation::Push(ONE), Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
    let foo_root_node = mast_forest[foo_root_node_id].clone();
    mast_forest.make_root(foo_root_node_id);

    let mstorew_node_id = BasicBlockNodeBuilder::new(vec![Operation::MStoreW], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let mstorew_node = mast_forest[mstorew_node_id].clone();

    let push_node_id = BasicBlockNodeBuilder::new(vec![PUSH_40_OP], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let push_node = mast_forest[push_node_id].clone();

    let join_node_id = JoinNodeBuilder::new([mstorew_node_id, push_node_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let join_node = mast_forest[join_node_id].clone();

    // This dyn will point to foo.
    let dyn_node_id = DynNodeBuilder::new_dyn().add_to_forest(&mut mast_forest).unwrap();
    let dyn_node = mast_forest[dyn_node_id].clone();

    let program_root_node_id = JoinNodeBuilder::new([join_node_id, dyn_node_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let program_root_node = mast_forest[program_root_node_id].clone();
    mast_forest.make_root(program_root_node_id);

    let program = Program::new(mast_forest.into(), program_root_node_id);

    let (trace, trace_len) = build_dyn_trace(
        &[
            foo_root_node.digest()[0].as_int(),
            foo_root_node.digest()[1].as_int(),
            foo_root_node.digest()[2].as_int(),
            foo_root_node.digest()[3].as_int(),
            FOO_ROOT_NODE_ADDR,
        ],
        &program,
    );

    // --- check block address, op_bits, group count, op_index, and in_span columns ---------------
    check_op_decoding(&trace, 0, ZERO, Operation::Join, 0, 0, 0);
    // starting inner join
    let join_addr = INIT_ADDR + EIGHT;
    check_op_decoding(&trace, 1, INIT_ADDR, Operation::Join, 0, 0, 0);
    // starting first span
    let mstorew_basic_block_addr = join_addr + EIGHT;
    check_op_decoding(&trace, 2, join_addr, Operation::Span, 1, 0, 0);
    check_op_decoding(&trace, 3, mstorew_basic_block_addr, Operation::MStoreW, 0, 0, 1);
    check_op_decoding(&trace, 4, mstorew_basic_block_addr, Operation::End, 0, 0, 0);
    // starting second span
    let push_basic_block_addr = mstorew_basic_block_addr + EIGHT;
    check_op_decoding(&trace, 5, join_addr, Operation::Span, 2, 0, 0);
    check_op_decoding(&trace, 6, push_basic_block_addr, PUSH_40_OP, 1, 0, 1);
    check_op_decoding(&trace, 7, push_basic_block_addr, Operation::Noop, 0, 1, 1);
    check_op_decoding(&trace, 8, push_basic_block_addr, Operation::End, 0, 0, 0);
    // end inner join
    check_op_decoding(&trace, 9, join_addr, Operation::End, 0, 0, 0);
    // dyn
    check_op_decoding(&trace, 10, INIT_ADDR, Operation::Dyn, 0, 0, 0);
    // starting foo span
    let dyn_addr = push_basic_block_addr + EIGHT;
    let add_basic_block_addr = dyn_addr + EIGHT;
    check_op_decoding(&trace, 11, dyn_addr, Operation::Span, 2, 0, 0);
    check_op_decoding_with_imm(&trace, 12, add_basic_block_addr, ONE, 1, 1, 0, 1);
    check_op_decoding(&trace, 13, add_basic_block_addr, Operation::Add, 0, 1, 1);
    check_op_decoding(&trace, 14, add_basic_block_addr, Operation::End, 0, 0, 0);
    // end dyn
    check_op_decoding(&trace, 15, dyn_addr, Operation::End, 0, 0, 0);
    // end outer join
    check_op_decoding(&trace, 16, INIT_ADDR, Operation::End, 0, 0, 0);

    // --- check hasher state columns -------------------------------------------------------------

    // in the first row, the hasher state is set to hashes of both child nodes
    let join_hash = join_node.digest();
    let dyn_hash = dyn_node.digest();
    assert_eq!(join_hash, get_hasher_state1(&trace, 0));
    assert_eq!(dyn_hash, get_hasher_state2(&trace, 0));

    // in the second row, the hasher set is set to hashes of both child nodes of the inner JOIN
    let mul_bb_node_hash = mstorew_node.digest();
    let save_bb_node_hash = push_node.digest();
    assert_eq!(mul_bb_node_hash, get_hasher_state1(&trace, 1));
    assert_eq!(save_bb_node_hash, get_hasher_state2(&trace, 1));

    // at the end of the first SPAN, the hasher state is set to the hash of the first child
    assert_eq!(mul_bb_node_hash, get_hasher_state1(&trace, 4));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 4));

    // at the end of the second SPAN, the hasher state is set to the hash of the second child
    assert_eq!(save_bb_node_hash, get_hasher_state1(&trace, 8));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 8));

    // at the end of the inner JOIN, the hasher set is set to the hash of the JOIN
    assert_eq!(join_hash, get_hasher_state1(&trace, 9));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 9));

    // at the start of the DYN block, the hasher state is set to foo digest
    let foo_hash = foo_root_node.digest();
    assert_eq!(foo_hash, get_hasher_state1(&trace, 10));

    // at the end of the DYN SPAN, the hasher state is set to the hash of the foo span
    assert_eq!(foo_hash, get_hasher_state1(&trace, 14));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 14));

    // at the end of the DYN block, the hasher state is set to the hash of the DYN node
    assert_eq!(dyn_hash, get_hasher_state1(&trace, 15));

    // at the end of the program, the hasher state is set to the hash of the entire program
    let program_hash = program_root_node.digest();
    assert_eq!(program_hash, get_hasher_state1(&trace, 16));
    assert_eq!(Word::from([ZERO, ZERO, ZERO, ZERO]), get_hasher_state2(&trace, 16));

    // the HALT opcode and program hash get propagated to the last row
    for i in 17..trace_len {
        assert!(contains_op(&trace, i, Operation::Halt));
        assert_eq!(ZERO, trace[OP_BITS_EXTRA_COLS_RANGE.start][i]);
        assert_eq!(ONE, trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][i]);
        assert_eq!(program_hash, get_hasher_state1(&trace, i));
    }
}

// HELPER REGISTERS TESTS
// ================================================================================================
#[test]
fn set_user_op_helpers_many() {
    // --- user operation with 4 helper values ----------------------------------------------------
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::U32div], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    let a = rand_value::<u32>();
    let b = rand_value::<u32>();
    let (dividend, divisor) = if a > b { (a, b) } else { (b, a) };
    let (trace, ..) = build_trace(&[dividend as u64, divisor as u64], &program);
    let hasher_state = get_hasher_state(&trace, 1);

    // Check the hasher state of the user operation which was executed.
    // h2 to h5 are expected to hold the values for range checks.
    let quot = dividend / divisor;
    let rem = dividend - quot * divisor;
    let check_1 = dividend - quot;
    let check_2 = divisor as i128 - rem as i128 - 1; // note that `check2` is non-negative
    let expected = build_expected_hasher_state(&[
        ZERO,
        ZERO,
        Felt::new((check_1 as u16).into()),
        Felt::new(((check_1 >> 16) as u16).into()),
        Felt::new((check_2 as u16).into()),
        Felt::new(((check_2 >> 16) as u16).into()),
    ]);

    assert_eq!(expected, hasher_state);
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_trace(stack_inputs: &[u64], program: &Program) -> (DecoderTrace, usize) {
    let stack_inputs = StackInputs::try_from_ints(stack_inputs.iter().copied()).unwrap();
    let mut host = DefaultHost::default();
    host.register_handler(EMIT_EVENT, Arc::new(NoopEventHandler)).unwrap();
    let mut process = Process::new(
        Kernel::default(),
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );
    process.execute(program, &mut host).unwrap();

    let (trace, ..) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    (
        trace
            .get_column_range(DECODER_TRACE_RANGE)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

fn build_dyn_trace(stack_inputs: &[u64], program: &Program) -> (DecoderTrace, usize) {
    let stack_inputs = StackInputs::try_from_ints(stack_inputs.iter().copied()).unwrap();
    let mut host = DefaultHost::default();
    let mut process = Process::new(
        Kernel::default(),
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    );

    process.execute(program, &mut host).unwrap();

    let (trace, ..) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    (
        trace
            .get_column_range(DECODER_TRACE_RANGE)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

fn build_call_trace(program: &Program, kernel: Kernel) -> (SystemTrace, DecoderTrace, usize) {
    let mut host = DefaultHost::default();
    let stack_inputs = crate::StackInputs::default();
    let mut process =
        Process::new(kernel, stack_inputs, AdviceInputs::default(), ExecutionOptions::default());

    process.execute(program, &mut host).unwrap();

    let (trace, ..) = ExecutionTrace::test_finalize_trace(process);
    let trace_len = trace.num_rows() - ExecutionTrace::NUM_RAND_ROWS;

    let sys_trace = trace
        .get_column_range(SYS_TRACE_RANGE)
        .try_into()
        .expect("failed to convert vector to array");

    let decoder_trace = trace
        .get_column_range(DECODER_TRACE_RANGE)
        .try_into()
        .expect("failed to convert vector to array");

    (sys_trace, decoder_trace, trace_len)
}

// OPCODES
// ------------------------------------------------------------------------------------------------

#[track_caller]
fn check_op_decoding(
    trace: &DecoderTrace,
    row_idx: usize,
    addr: Felt,
    op: Operation,
    group_count: u64,
    op_idx: u64,
    in_span: u64,
) {
    let opcode = read_opcode(trace, row_idx);

    assert_eq!(trace[ADDR_COL_IDX][row_idx], addr, "address mismatch");
    assert_eq!(op.op_code(), opcode, "opcode mismatch");
    assert_eq!(trace[IN_SPAN_COL_IDX][row_idx], Felt::new(in_span), "in_span mismatch");
    assert_eq!(
        trace[GROUP_COUNT_COL_IDX][row_idx],
        Felt::new(group_count),
        "group count mismatch"
    );
    assert_eq!(trace[OP_INDEX_COL_IDX][row_idx], Felt::new(op_idx), "op index mismatch");

    let expected_batch_flags = if op == Operation::Span || op == Operation::Respan {
        let num_groups = core::cmp::min(OP_BATCH_SIZE, group_count as usize);
        build_op_batch_flags(num_groups)
    } else {
        [ZERO, ZERO, ZERO]
    };

    for (i, flag_value) in OP_BATCH_FLAGS_RANGE.zip(expected_batch_flags) {
        assert_eq!(trace[i][row_idx], flag_value, "op batch flag mismatch at column {}", i);
    }

    // make sure the op bit extra columns for degree reduction are set correctly
    let bit6 = Felt::from((opcode >> 6) & 1);
    let bit5 = Felt::from((opcode >> 5) & 1);
    let bit4 = Felt::from((opcode >> 4) & 1);
    assert_eq!(
        trace[OP_BITS_EXTRA_COLS_RANGE.start][row_idx],
        bit6 * (ONE - bit5) * bit4,
        "op bits extra mismatch column 0"
    );
    assert_eq!(
        trace[OP_BITS_EXTRA_COLS_RANGE.start + 1][row_idx],
        bit6 * bit5,
        "op bits extra mismatch column 1"
    );
}

#[allow(clippy::too_many_arguments)]
#[track_caller]
fn check_op_decoding_with_imm(
    trace: &DecoderTrace,
    row_idx: usize,
    addr: Felt,
    imm: Felt,
    imm_idx: usize,
    group_count: u64,
    op_idx: u64,
    in_span: u64,
) {
    // first, check standard decoding expectations
    check_op_decoding(trace, row_idx, addr, Operation::Push(imm), group_count, op_idx, in_span);

    // then, ensure the immediate value is present in the hasher state of the most recent
    // SPAN/RESPAN row (immediates are absorbed into hasher state as separate groups)
    let mut span_row = None;
    for r in (0..=row_idx).rev() {
        if contains_op(trace, r, Operation::Span) || contains_op(trace, r, Operation::Respan) {
            span_row = Some(r);
            break;
        }
    }
    let span_row = span_row.expect("no preceding SPAN/RESPAN row found for PUSH");

    assert_eq!(
        trace[HASHER_STATE_RANGE.start + imm_idx][span_row],
        imm,
        "immediate value in hasher state mismatch"
    );
}

fn contains_op(trace: &DecoderTrace, row_idx: usize, op: Operation) -> bool {
    op.op_code() == read_opcode(trace, row_idx)
}

fn read_opcode(trace: &DecoderTrace, row_idx: usize) -> u8 {
    let mut result = 0;
    for (i, column) in trace.iter().skip(OP_BITS_OFFSET).take(NUM_OP_BITS).enumerate() {
        let op_bit = column[row_idx].as_int();
        assert!(op_bit <= 1, "invalid op bit");
        result += op_bit << i;
    }
    result as u8
}

fn build_op_batch_flags(num_groups: usize) -> [Felt; NUM_OP_BATCH_FLAGS] {
    match num_groups {
        1 => OP_BATCH_1_GROUPS,
        2 => OP_BATCH_2_GROUPS,
        4 => OP_BATCH_4_GROUPS,
        8 => OP_BATCH_8_GROUPS,
        _ => panic!("invalid num groups: {num_groups}"),
    }
}

// SYSTEM REGISTERS
// ------------------------------------------------------------------------------------------------

fn get_fn_hash(trace: &SystemTrace, row_idx: usize) -> Word {
    let mut result = [ZERO; WORD_SIZE];
    let trace = &trace[FN_HASH_RANGE];
    for (element, column) in result.iter_mut().zip(trace) {
        *element = column[row_idx];
    }
    result.into()
}

// HASHER STATE
// ------------------------------------------------------------------------------------------------

fn check_hasher_state(trace: &DecoderTrace, expected: Vec<Vec<Felt>>) {
    for (i, expected) in expected.iter().enumerate() {
        let expected = build_expected_hasher_state(expected);
        assert_eq!(expected, get_hasher_state(trace, i));
    }
}

fn get_hasher_state(trace: &DecoderTrace, row_idx: usize) -> [Felt; NUM_HASHER_COLUMNS] {
    let mut result = [ZERO; NUM_HASHER_COLUMNS];
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter()) {
        *result = column[row_idx];
    }
    result
}

fn get_hasher_state1(trace: &DecoderTrace, row_idx: usize) -> Word {
    let mut result = [ZERO; WORD_SIZE];
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter()) {
        *result = column[row_idx];
    }
    result.into()
}

fn get_hasher_state2(trace: &DecoderTrace, row_idx: usize) -> Word {
    let mut result = [ZERO; WORD_SIZE];
    for (result, column) in result.iter_mut().zip(trace[HASHER_STATE_RANGE].iter().skip(4)) {
        *result = column[row_idx];
    }
    result.into()
}

fn build_expected_hasher_state(values: &[Felt]) -> [Felt; NUM_HASHER_COLUMNS] {
    let mut result = [ZERO; NUM_HASHER_COLUMNS];
    for (i, value) in values.iter().enumerate() {
        result[i] = *value;
    }
    result
}
