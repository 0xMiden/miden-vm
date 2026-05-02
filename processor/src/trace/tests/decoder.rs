use alloc::vec::Vec;

use miden_air::trace::{
    AUX_TRACE_RAND_CHALLENGES, Challenges,
    chiplets::hasher::CONTROLLER_ROWS_PER_PERM_FELT,
    decoder::{P1_COL_IDX, P2_COL_IDX, P3_COL_IDX},
};
use miden_utils_testing::rand::rand_array;

use super::super::{
    decoder::{BlockHashTableRow, build_op_group},
    tests::{build_trace_from_ops, build_trace_from_program, build_trace_from_program_with_stack},
    utils::build_span_with_respan_ops,
};
use crate::{
    ContextId, Felt, ONE, Program, StackInputs, Word, ZERO,
    field::{ExtensionField, Field},
    mast::{
        BasicBlockNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor,
        MastNodeExt, SplitNodeBuilder,
    },
    operation::Operation,
};

// BLOCK STACK TABLE TESTS
// ================================================================================================

#[test]
fn decoder_p1_span_with_respan() {
    let (ops, _) = build_span_with_respan_ops();
    let trace = build_trace_from_ops(ops, &[]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&challenges),
        BlockStackTableRow::new(ONE + CONTROLLER_ROWS_PER_PERM_FELT, ZERO, false)
            .to_value(&challenges),
    ];

    // make sure the first entry is ONE
    assert_eq!(ONE, p1[0]);

    // when SPAN operation is executed, entry for span block is added to the table
    let expected_value = row_values[0];
    assert_eq!(expected_value, p1[1]);

    // for the next 8 cycles (as we execute user ops), the table is not affected
    for i in 2..10 {
        assert_eq!(expected_value, p1[i]);
    }

    // when RESPAN is executed, the first entry is replaced with a new entry
    let expected_value = expected_value * row_values[0].inverse() * row_values[1];
    assert_eq!(expected_value, p1[10]);

    // for the next 11 cycles (as we execute user ops), the table is not affected
    for i in 11..22 {
        assert_eq!(expected_value, p1[i]);
    }

    // at cycle 22, the END operation is executed and the table is cleared
    let expected_value = expected_value * row_values[1].inverse();
    assert_eq!(expected_value, ONE);
    for i in 22..(p1.len()) {
        assert_eq!(ONE, p1[i]);
    }
}

#[test]
fn decoder_p1_join() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let join_id = JoinNodeBuilder::new([basic_block_1_id, basic_block_2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(join_id);

        Program::new(mast_forest.into(), join_id)
    };

    let trace = build_trace_from_program(&program, &[]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let a_3 = ONE + CONTROLLER_ROWS_PER_PERM_FELT;
    let a_5 = a_3 + CONTROLLER_ROWS_PER_PERM_FELT;
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&challenges),
        BlockStackTableRow::new(a_3, ONE, false).to_value(&challenges),
        BlockStackTableRow::new(a_5, ONE, false).to_value(&challenges),
    ];

    // make sure the first entry is ONE
    assert_eq!(ONE, p1[0]);

    // when JOIN operation is executed, entry for the JOIN block is added to the table
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p1[1]);

    // when the first SPAN is executed, its entry is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[2]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[3]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[4]);

    // when the second SPAN is executed, its entry is added to the table
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[5]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[6]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p1[7]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[8]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 9..(p1.len()) {
        assert_eq!(ONE, p1[i]);
    }
}

#[test]
fn decoder_p1_split() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let split_id = SplitNodeBuilder::new([basic_block_1_id, basic_block_2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(split_id);

        Program::new(mast_forest.into(), split_id)
    };

    let trace = build_trace_from_program(&program, &[1]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let a_3 = ONE + CONTROLLER_ROWS_PER_PERM_FELT;
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&challenges),
        BlockStackTableRow::new(a_3, ONE, false).to_value(&challenges),
    ];

    // make sure the first entry is ONE
    assert_eq!(ONE, p1[0]);

    // when SPLIT operation is executed, entry for the SPLIT block is added to the table
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p1[1]);

    // when the true branch SPAN is executed, its entry is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[2]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[3]);

    // when the SPAN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[4]);

    // when the SPLIT block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[5]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 6..(p1.len()) {
        assert_eq!(ONE, p1[i]);
    }
}

#[test]
fn decoder_p1_loop_with_repeat() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Pad], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let join_id = JoinNodeBuilder::new([basic_block_1_id, basic_block_2_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let loop_node_id = LoopNodeBuilder::new(join_id).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(loop_node_id);

        Program::new(mast_forest.into(), loop_node_id)
    };

    // Input [1, 1, 0]: position 0 (top) = 1 (1st iteration enters)
    // After Pad+Drop: position 0 = 1 (2nd iteration enters)
    // After Pad+Drop: position 0 = 0 (loop exits)
    let trace = build_trace_from_program(&program, &[1, 1, 0]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    // The loop node consumes the first hasher cycle; join/span addresses follow sequentially.
    let a_3 = ONE + CONTROLLER_ROWS_PER_PERM_FELT; // address of the JOIN block in the first iteration
    let a_5 = a_3 + CONTROLLER_ROWS_PER_PERM_FELT; // address of the first SPAN block in the first iteration
    let a_7 = a_5 + CONTROLLER_ROWS_PER_PERM_FELT; // address of the second SPAN block in the first iteration
    let a_9 = a_7 + CONTROLLER_ROWS_PER_PERM_FELT; // address of the JOIN block in the second iteration
    let a_11 = a_9 + CONTROLLER_ROWS_PER_PERM_FELT; // address of the first SPAN block in the second iteration
    let a_13 = a_11 + CONTROLLER_ROWS_PER_PERM_FELT; // address of the second SPAN block in the second iteration
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, true).to_value(&challenges),
        BlockStackTableRow::new(a_3, ONE, false).to_value(&challenges),
        BlockStackTableRow::new(a_5, a_3, false).to_value(&challenges),
        BlockStackTableRow::new(a_7, a_3, false).to_value(&challenges),
        BlockStackTableRow::new(a_9, ONE, false).to_value(&challenges),
        BlockStackTableRow::new(a_11, a_9, false).to_value(&challenges),
        BlockStackTableRow::new(a_13, a_9, false).to_value(&challenges),
    ];

    // make sure the first entry is ONE
    assert_eq!(ONE, p1[0]);

    // --- first iteration ----------------------------------------------------

    // when LOOP operation is executed, entry for the LOOP block is added to the table
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p1[1]);

    // when JOIN operation is executed, entry for the JOIN block is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[2]);

    // when the first SPAN is executed, its entry is added to the table
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[3]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[4]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p1[5]);

    // when the second SPAN is executed, its entry is added to the table
    expected_value *= row_values[3];
    assert_eq!(expected_value, p1[6]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[7]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[3].inverse();
    assert_eq!(expected_value, p1[8]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[9]);

    // --- second iteration ---------------------------------------------------

    // when REPEAT operation is executed, the table is not affected
    assert_eq!(expected_value, p1[10]);

    // when JOIN operation is executed, entry for the JOIN block is added to the table
    expected_value *= row_values[4];
    assert_eq!(expected_value, p1[11]);

    // when the first SPAN is executed, its entry is added to the table
    expected_value *= row_values[5];
    assert_eq!(expected_value, p1[12]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[13]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[5].inverse();
    assert_eq!(expected_value, p1[14]);

    // when the second SPAN is executed, its entry is added to the table
    expected_value *= row_values[6];
    assert_eq!(expected_value, p1[15]);

    // when the user op is executed, the table is not affected
    assert_eq!(expected_value, p1[16]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[6].inverse();
    assert_eq!(expected_value, p1[17]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[4].inverse();
    assert_eq!(expected_value, p1[18]);

    // when the LOOP block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[19]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 20..(p1.len()) {
        assert_eq!(ONE, p1[i]);
    }
}

// BLOCK HASH TABLE TESTS
// ================================================================================================

#[test]
fn decoder_p2_span_with_respan() {
    let program = {
        let mut mast_forest = MastForest::new();

        let (ops, _) = build_span_with_respan_ops();
        let basic_block_id = BasicBlockNodeBuilder::new(ops, Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    let trace = build_trace_from_program(&program, &[]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let program_hash_msg =
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&challenges);

    // p2 starts at identity (1)
    let mut expected_value = ONE;
    assert_eq!(expected_value, p2[0]);

    // as operations inside the span execute (including RESPAN), the table is not affected
    for i in 1..22 {
        assert_eq!(expected_value, p2[i]);
    }

    // at cycle 22, the END operation removes the root block hash (unmatched by any add)
    expected_value *= program_hash_msg.inverse();
    for i in 22..(p2.len()) {
        assert_eq!(expected_value, p2[i]);
    }
}

#[test]
fn decoder_p2_join() {
    let mut mast_forest = MastForest::new();

    let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();

    let join_id = JoinNodeBuilder::new([basic_block_1_id, basic_block_2_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_1 = mast_forest[basic_block_1_id].clone();
    let basic_block_2 = mast_forest[basic_block_2_id].clone();
    let join = mast_forest[join_id].clone();
    mast_forest.make_root(join_id);

    let program = Program::new(mast_forest.into(), join_id);

    let trace = build_trace_from_program(&program, &[]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let program_hash_msg =
        BlockHashTableRow::new_test(ZERO, join.digest(), false, false).collapse(&challenges);
    let child1_msg =
        BlockHashTableRow::new_test(ONE, basic_block_1.digest(), true, false).collapse(&challenges);
    let child2_msg = BlockHashTableRow::new_test(ONE, basic_block_2.digest(), false, false)
        .collapse(&challenges);

    // p2 starts at identity (1)
    let mut expected_value = ONE;
    assert_eq!(expected_value, p2[0]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= child1_msg * child2_msg;
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= child1_msg.inverse();
    assert_eq!(expected_value, p2[4]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[5]);
    assert_eq!(expected_value, p2[6]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= child2_msg.inverse();
    assert_eq!(expected_value, p2[7]);

    // when the JOIN block ends, its entry (the root hash) is removed (unmatched by any add)
    expected_value *= program_hash_msg.inverse();
    assert_eq!(expected_value, p2[8]);

    // the final value is 1/program_hash_msg
    for i in 9..(p2.len()) {
        assert_eq!(expected_value, p2[i]);
    }
}

#[test]
fn decoder_p2_split_true() {
    // build program
    let mut mast_forest = MastForest::new();

    let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_1 = mast_forest[basic_block_1_id].clone();
    let _basic_block_2 = mast_forest[basic_block_2_id].clone();
    let split_id = SplitNodeBuilder::new([basic_block_1_id, basic_block_2_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(split_id);

    let program = Program::new(mast_forest.into(), split_id);

    // build trace from program
    let trace = build_trace_from_program(&program, &[1]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let program_hash_msg =
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&challenges);
    let child_msg = BlockHashTableRow::new_test(ONE, basic_block_1.digest(), false, false)
        .collapse(&challenges);

    // p2 starts at identity (1)
    let mut expected_value = ONE;
    assert_eq!(expected_value, p2[0]);

    // when SPLIT operation is executed, entry for the true branch is added to the table
    expected_value *= child_msg;
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the SPAN block ends, its entry is removed from the table
    expected_value *= child_msg.inverse();
    assert_eq!(expected_value, p2[4]);

    // when the SPLIT block ends, its entry (the root hash) is removed (unmatched by any add)
    expected_value *= program_hash_msg.inverse();
    assert_eq!(expected_value, p2[5]);

    // the final value is 1/program_hash_msg
    for i in 6..(p2.len()) {
        assert_eq!(expected_value, p2[i]);
    }
}

#[test]
fn decoder_p2_split_false() {
    // build program
    let mut mast_forest = MastForest::new();

    let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let _basic_block_1 = mast_forest[basic_block_1_id].clone();
    let basic_block_2 = mast_forest[basic_block_2_id].clone();

    let split_id = SplitNodeBuilder::new([basic_block_1_id, basic_block_2_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(split_id);

    let program = Program::new(mast_forest.into(), split_id);

    // build trace from program
    let trace = build_trace_from_program(&program, &[0]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    let program_hash_msg =
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&challenges);
    let child_msg = BlockHashTableRow::new_test(ONE, basic_block_2.digest(), false, false)
        .collapse(&challenges);

    // p2 starts at identity (1)
    let mut expected_value = ONE;
    assert_eq!(expected_value, p2[0]);

    // when SPLIT operation is executed, entry for the false branch is added to the table
    expected_value *= child_msg;
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the SPAN block ends, its entry is removed from the table
    expected_value *= child_msg.inverse();
    assert_eq!(expected_value, p2[4]);

    // when the SPLIT block ends, its entry (the root hash) is removed (unmatched by any add)
    expected_value *= program_hash_msg.inverse();
    assert_eq!(expected_value, p2[5]);

    // the final value is 1/program_hash_msg
    for i in 6..(p2.len()) {
        assert_eq!(expected_value, p2[i]);
    }
}

#[test]
fn decoder_p2_loop_with_repeat() {
    // build program
    let mut mast_forest = MastForest::new();

    let basic_block_1_id = BasicBlockNodeBuilder::new(vec![Operation::Pad], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_2_id = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
        .add_to_forest(&mut mast_forest)
        .unwrap();

    let join_id = JoinNodeBuilder::new([basic_block_1_id, basic_block_2_id])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    let basic_block_1 = mast_forest[basic_block_1_id].clone();
    let basic_block_2 = mast_forest[basic_block_2_id].clone();
    let join = mast_forest[join_id].clone();

    let loop_node_id = LoopNodeBuilder::new(join_id).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(loop_node_id);

    let program = Program::new(mast_forest.into(), loop_node_id);

    // Input [1, 1, 0]: position 0 (top) = 1 (1st iteration enters)
    // After Pad+Drop: position 0 = 1 (2nd iteration enters)
    // After Pad+Drop: position 0 = 0 (loop exits)
    let trace = build_trace_from_program(&program, &[1, 1, 0]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    // The loop node consumes the first hasher cycle; join/span addresses follow sequentially.
    let a_3 = ONE + CONTROLLER_ROWS_PER_PERM_FELT; // address of the JOIN block in the first iteration
    let a_9 = a_3 + CONTROLLER_ROWS_PER_PERM_FELT * Felt::new_unchecked(3); // address of the JOIN block in the second iteration
    let program_hash_msg =
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&challenges);
    let loop_body_msg =
        BlockHashTableRow::new_test(ONE, join.digest(), false, true).collapse(&challenges);
    let child1_iter1 =
        BlockHashTableRow::new_test(a_3, basic_block_1.digest(), true, false).collapse(&challenges);
    let child2_iter1 = BlockHashTableRow::new_test(a_3, basic_block_2.digest(), false, false)
        .collapse(&challenges);
    let child1_iter2 =
        BlockHashTableRow::new_test(a_9, basic_block_1.digest(), true, false).collapse(&challenges);
    let child2_iter2 = BlockHashTableRow::new_test(a_9, basic_block_2.digest(), false, false)
        .collapse(&challenges);

    // p2 starts at identity (1)
    let mut expected_value = ONE;
    assert_eq!(expected_value, p2[0]);

    // --- first iteration ----------------------------------------------------

    // when LOOP operation is executed, entry for loop body is added to the table
    expected_value *= loop_body_msg;
    assert_eq!(expected_value, p2[1]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= child1_iter1 * child2_iter1;
    assert_eq!(expected_value, p2[2]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[3]);
    assert_eq!(expected_value, p2[4]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= child1_iter1.inverse();
    assert_eq!(expected_value, p2[5]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[6]);
    assert_eq!(expected_value, p2[7]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= child2_iter1.inverse();
    assert_eq!(expected_value, p2[8]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= loop_body_msg.inverse();
    assert_eq!(expected_value, p2[9]);

    // --- second iteration ---------------------------------------------------

    // when REPEAT operation is executed, entry for loop body is again added to the table
    expected_value *= loop_body_msg;
    assert_eq!(expected_value, p2[10]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= child1_iter2 * child2_iter2;
    assert_eq!(expected_value, p2[11]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[12]);
    assert_eq!(expected_value, p2[13]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= child1_iter2.inverse();
    assert_eq!(expected_value, p2[14]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[15]);
    assert_eq!(expected_value, p2[16]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= child2_iter2.inverse();
    assert_eq!(expected_value, p2[17]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= loop_body_msg.inverse();
    assert_eq!(expected_value, p2[18]);

    // when the LOOP block ends, its entry (the root hash) is removed (unmatched by any add)
    expected_value *= program_hash_msg.inverse();
    assert_eq!(expected_value, p2[19]);

    // the final value is 1/program_hash_msg
    for i in 20..(p2.len()) {
        assert_eq!(expected_value, p2[i]);
    }
}

// OP GROUP TABLE TESTS
// ================================================================================================

#[test]
fn decoder_p3_trace_empty_table() {
    let stack = [1, 2];
    let operations = vec![Operation::Add];
    let trace = build_trace_from_ops(operations, &stack);

    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();

    // no rows should have been added or removed from the op group table, and thus, all values
    // in the column must be ONE
    let p3 = aux_columns.get_column(P3_COL_IDX);
    for &value in p3.iter().take(p3.len()) {
        assert_eq!(ONE, value);
    }
}

#[test]
fn decoder_p3_trace_one_batch() {
    let stack = [1, 2, 3, 4, 5, 6, 7, 8];
    let ops = vec![
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Push(ONE),
        Operation::Add,
        Operation::Mul,
        Operation::Add,
        Operation::Push(Felt::new_unchecked(2)),
        Operation::Add,
        Operation::Swap,
        Operation::Mul,
        Operation::Add,
    ];
    let trace = build_trace_from_ops(ops.clone(), &stack);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p3 = aux_columns.get_column(P3_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);

    // make sure the first entry is ONE
    assert_eq!(ONE, p3[0]);

    // make sure 3 groups were inserted at clock cycle 1; these entries are for the two immediate
    // values and the second operation group consisting of [SWAP, MUL, ADD]
    let g1_value = OpGroupTableRow::new(ONE, Felt::new_unchecked(3), ONE).to_value(&challenges);
    let g2_value = OpGroupTableRow::new(ONE, Felt::new_unchecked(2), Felt::new_unchecked(2))
        .to_value(&challenges);
    let g3_value = OpGroupTableRow::new(ONE, ONE, build_op_group(&ops[9..])).to_value(&challenges);
    let expected_value = g1_value * g2_value * g3_value;
    assert_eq!(expected_value, p3[1]);

    // for the next 3 cycles (2, 3, 4), op group table doesn't change
    for i in 2..5 {
        assert_eq!(expected_value, p3[i]);
    }

    // at cycle 5, when PUSH(1) is executed, the entry for the first group is removed from the
    // table
    let expected_value = expected_value / g1_value;
    assert_eq!(expected_value, p3[5]);

    // for the next 3 cycles (6, 7, 8), op group table doesn't change
    for i in 6..9 {
        assert_eq!(expected_value, p3[i]);
    }

    // at cycle 9, when PUSH(2) is executed, the entry for the second group is removed from the
    // table
    let expected_value = expected_value / g2_value;
    assert_eq!(expected_value, p3[9]);

    // at cycle 10, op group 0 is completed, and the entry for the next op group is removed from
    // the table
    let expected_value = expected_value / g3_value;
    assert_eq!(expected_value, p3[10]);

    // at this point, the table should be empty and thus, running product should be ONE
    assert_eq!(expected_value, ONE);
    for i in 11..(p3.len()) {
        assert_eq!(ONE, p3[i]);
    }
}

#[test]
fn decoder_p3_trace_two_batches() {
    let (ops, iv) = build_span_with_respan_ops();
    let trace = build_trace_from_ops(ops, &[]);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p3 = aux_columns.get_column(P3_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);

    // make sure the first entry is ONE
    assert_eq!(ONE, p3[0]);

    // --- first batch ----------------------------------------------------------------------------
    // make sure entries for 7 groups were inserted at clock cycle 1
    let b0_values = [
        OpGroupTableRow::new(ONE, Felt::new_unchecked(11), iv[0]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(10), iv[1]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(9), iv[2]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(8), iv[3]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(7), iv[4]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(6), iv[5]).to_value(&challenges),
        OpGroupTableRow::new(ONE, Felt::new_unchecked(5), iv[6]).to_value(&challenges),
    ];
    let mut expected_value: Felt = b0_values.iter().fold(ONE, |acc, &val| acc * val);
    assert_eq!(expected_value, p3[1]);

    // for the next 7 cycles (2, 3, 4, 5, 6, 7, 8), an entry for an op group is removed from the
    // table
    for (i, clk) in (2..9).enumerate() {
        expected_value /= b0_values[i];
        assert_eq!(expected_value, p3[clk]);
    }

    // at cycle 9, when we execute a NOOP to finish the first batch, op group table doesn't change;
    // also, at this point op group table must be empty
    assert_eq!(expected_value, p3[9]);
    assert_eq!(expected_value, ONE);

    // --- second batch ---------------------------------------------------------------------------
    // make sure entries for 3 group are inserted at clock cycle 10 (when RESPAN is executed)
    // group 3 consists of two DROP operations which do not fit into group 0
    let batch1_addr = ONE + CONTROLLER_ROWS_PER_PERM_FELT;
    let op_group3 = build_op_group(&[Operation::Drop; 2]);
    let b1_values = [
        OpGroupTableRow::new(batch1_addr, Felt::new_unchecked(3), iv[7]).to_value(&challenges),
        OpGroupTableRow::new(batch1_addr, Felt::new_unchecked(2), iv[8]).to_value(&challenges),
        OpGroupTableRow::new(batch1_addr, ONE, op_group3).to_value(&challenges),
    ];
    let mut expected_value: Felt = b1_values.iter().fold(ONE, |acc, &val| acc * val);
    assert_eq!(expected_value, p3[10]);

    // for the next 2 cycles (11, 12), an entry for an op group is removed from the table
    for (i, clk) in (11..13).enumerate() {
        expected_value *= b1_values[i].inverse();
        assert_eq!(expected_value, p3[clk]);
    }

    // then, as we executed ADD and DROP operations for group 0, op group table doesn't change
    for i in 13..19 {
        assert_eq!(expected_value, p3[i]);
    }

    // at cycle 19 we start executing group 3 - so, the entry for the last op group is removed
    // from the table
    expected_value *= b1_values[2].inverse();
    assert_eq!(expected_value, p3[19]);

    // at this point, the table should be empty and thus, running product should be ONE
    assert_eq!(expected_value, ONE);
    for i in 20..(p3.len()) {
        assert_eq!(ONE, p3[i]);
    }
}

// DYNCALL REGRESSION TESTS
// ================================================================================================

#[test]
fn decoder_dyncall_at_min_stack_depth_records_post_drop_ctx_info() {
    use std::sync::Arc;

    use crate::{
        MIN_STACK_DEPTH,
        mast::{DynNodeBuilder, MastForestContributor},
        operation::opcodes,
    };

    // Build exactly the same program shape as `dyncall_program()` in parallel/tests.rs:
    //   join(
    //       block(push(HASH_ADDR), mem_storew, drop, drop, drop, drop, push(HASH_ADDR)),
    //       dyncall,
    //   )
    // The target procedure (single SWAP) is added as a second root so the VM can find it.
    //
    // The caller passes the 4-element procedure hash as the initial stack contents
    // (top-of-stack first).  The preamble stores that word at HASH_ADDR so that DYNCALL
    // can load it and dispatch to the correct procedure.
    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    // --- build the forest in the same order as dyncall_program() ---
    let mut forest = MastForest::new();

    // 1. Build the root join node first (preamble + dyncall).
    let root = {
        let preamble = BasicBlockNodeBuilder::new(
            vec![
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Push(HASH_ADDR),
            ],
            Vec::new(),
        )
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();

        JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap()
    };
    forest.make_root(root);

    // 2. Add the procedure that DYNCALL will call, as a second forest root.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(target);

    // 3. Derive the stack inputs from the target's digest (4 Felts, top-of-stack first). We collect
    //    as Felt directly to avoid any StarkField trait-import requirement.
    let target_hash: Vec<Felt> =
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect();

    let program = Program::new(Arc::new(forest), root);

    // The stack now has the 4-element hash at the top, padded to MIN_STACK_DEPTH with
    // zeros — exactly 16 elements, no overflow entries.
    let trace =
        build_trace_from_program_with_stack(&program, StackInputs::new(&target_hash).unwrap());
    let main = trace.main_trace();

    // Locate the DYNCALL row.
    let dyncall_opcode = Felt::from_u8(opcodes::DYNCALL);
    let row = main
        .row_iter()
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    // ExecutionContextInfo fields map to the second hasher-state word (trace_row.rs):
    //   second_hasher_state[0] = parent_stack_depth        → decoder_hasher_state_element(4)
    //   second_hasher_state[1] = parent_next_overflow_addr → decoder_hasher_state_element(5)
    //
    // With 4 hash elements on the stack the depth is still MIN_STACK_DEPTH (16); after
    // DYNCALL drops those 4 elements the post-drop depth is 12 = MIN_STACK_DEPTH, which
    // means no overflow entry was pushed, so parent_next_overflow_addr must be ZERO.
    assert_eq!(
        main.decoder_hasher_state_element(4, row),
        Felt::new_unchecked(MIN_STACK_DEPTH as u64),
        "parent_stack_depth should equal MIN_STACK_DEPTH"
    );
    assert_eq!(
        main.decoder_hasher_state_element(5, row),
        ZERO,
        "parent_next_overflow_addr should be ZERO when stack is at MIN_STACK_DEPTH"
    );
}

#[test]
fn decoder_dyncall_with_multiple_overflow_entries_records_correct_overflow_addr() {
    // Regression test for the bug identified by huitseeker (PR #2904 review comment
    // #3002220853): when the caller context has *more than one* overflow entry, the
    // serial ExecutionTracer must record the post-pop overflow address (the clock of
    // the second-to-last entry), not the pre-pop address (the clock of the top entry).
    //
    // Root cause: the fast processor's `depth()` is always ≥ MIN_STACK_DEPTH (16),
    // so Drops from depth=16 do not reduce the reported depth.  Only Pushes starting
    // from depth=16 create overflow entries in the tracer's overflow table.  We
    // therefore build exactly 2 overflow entries by pushing 1 zero then HASH_ADDR
    // (depth 16 → 17 → 18), and wrap the call in an outer join whose cleanup block
    // drops 1 element to balance the final stack back to depth=16.
    //
    // Program structure:
    //
    //   outer_join(
    //       inner_join(preamble, dyncall),
    //       cleanup(drop),
    //   )
    //
    //   preamble:
    //     push(HASH_ADDR) mstorew drop×4   ← store callee hash at HASH_ADDR; depth stays 16
    //     push(0)                           ← depth=17, overflow[0]=0 (clk=T1)
    //     push(HASH_ADDR)                   ← depth=18, overflow[1]=0 (clk=T2)
    //
    //   dyncall:  reads mem[40]=[h0,h1,h2,h3], pops address → depth=17 for caller
    //             recorded parent_stack_depth       = 17  (= 18 − 1)
    //             recorded parent_next_overflow_addr = T1 (second-to-last, nonzero)
    //             buggy last_update_clk_in_current_ctx() would record T2 instead
    //
    //   cleanup: Drop → depth=16  ✓ (no OutputStackOverflow)
    //
    // Concrete stack trace (initial stack = [h0,h1,h2,h3,0,…,0], depth=16):
    //   push(HASH_ADDR=40): depth=17, overflow[0]=0 (clk=T0)
    //   mstorew:  mem[40]=[h0,h1,h2,h3]; pops addr → depth=16, overflow empty
    //   drop×4:   depth stays 16 (fast processor depth cannot go below MIN_STACK_DEPTH)
    //   push(0):  depth=17, overflow[0]=0 (clk=T1)
    //   push(40): depth=18, overflow[1]=0 (clk=T2, T2>T1)
    //   DYNCALL → recorded depth=17, overflow_addr=T1 (nonzero ✓)
    //   cleanup Drop → depth=16
    use std::sync::Arc;

    use crate::{
        mast::{DynNodeBuilder, MastForestContributor},
        operation::opcodes,
    };

    const HASH_ADDR: Felt = Felt::new_unchecked(40);

    let mut forest = MastForest::new();

    // 1. Build the callee procedure first so we can get its digest.
    let target = BasicBlockNodeBuilder::new(vec![Operation::Swap], Vec::new())
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(target);

    let target_hash: Vec<Felt> =
        forest.get_node_by_id(target).unwrap().digest().iter().copied().collect();

    // 2. Build the main program.
    let root = {
        let preamble = BasicBlockNodeBuilder::new(
            vec![
                // Store the callee hash at HASH_ADDR.
                // Initial stack: [h0,h1,h2,h3,0,…] depth=16
                // push(HASH_ADDR): depth=17, overflow[0]=0 (clk=T0)
                // mstorew:        mem[40]=[h0,h1,h2,h3]; pops addr → depth=16, overflow empty
                // drop×4:         removes h0..h3 from stack; depth stays 16
                Operation::Push(HASH_ADDR),
                Operation::MStoreW,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                Operation::Drop,
                // Push exactly 2 elements to create 2 overflow entries.
                Operation::Push(ZERO),      // depth=17, overflow[0]=0 (clk=T1)
                Operation::Push(HASH_ADDR), // depth=18, overflow[1]=0 (clk=T2)
            ],
            Vec::new(),
        )
        .add_to_forest(&mut forest)
        .unwrap();

        let dyncall = DynNodeBuilder::new_dyncall().add_to_forest(&mut forest).unwrap();
        // After inner_join completes: DYNCALL has popped the address, leaving depth=17.
        let inner_join =
            JoinNodeBuilder::new([preamble, dyncall]).add_to_forest(&mut forest).unwrap();

        // Cleanup: drop 1 element so the final stack depth returns to MIN_STACK_DEPTH=16.
        let cleanup = BasicBlockNodeBuilder::new(vec![Operation::Drop], Vec::new())
            .add_to_forest(&mut forest)
            .unwrap();

        JoinNodeBuilder::new([inner_join, cleanup]).add_to_forest(&mut forest).unwrap()
    };
    forest.make_root(root);

    let program = Program::new(Arc::new(forest), root);

    // Pass the 4-element callee hash as initial stack inputs so MStoreW stores the
    // real procedure digest at HASH_ADDR.
    let trace =
        build_trace_from_program_with_stack(&program, StackInputs::new(&target_hash).unwrap());
    let main = trace.main_trace();

    // Locate the DYNCALL row.
    let dyncall_opcode = Felt::from_u8(opcodes::DYNCALL);
    let dyncall_row = main
        .row_iter()
        .find(|&i| main.get_op_code(i) == dyncall_opcode)
        .expect("DYNCALL row not found in trace");

    // second_hasher_state[0] = parent_stack_depth        → decoder_hasher_state_element(4)
    // second_hasher_state[1] = parent_next_overflow_addr → decoder_hasher_state_element(5)
    let recorded_depth = main.decoder_hasher_state_element(4, dyncall_row);
    let recorded_overflow_addr = main.decoder_hasher_state_element(5, dyncall_row);

    // At DYNCALL time depth=18 (>MIN_STACK_DEPTH), so post-drop depth = 17.
    assert_eq!(
        recorded_depth,
        Felt::new_unchecked(17),
        "parent_stack_depth should be 17 (= pre-DYNCALL depth 18 minus 1)"
    );

    // Independently determine T1 (clock of push(0)) and T2 (clock of push(HASH_ADDR)) by
    // scanning the trace for all PUSH rows that appear before the DYNCALL row.
    //
    // The preamble BasicBlockNode contains 8 ops in order:
    //   [push(HASH_ADDR), mstorew, drop×4, push(0), push(HASH_ADDR)]
    // All 8 fit in a single op-group, so they run at consecutive clocks within the span.
    // The last two PUSH rows before DYNCALL are therefore:
    //   push_rows[n-2] → push(0)        at clock T1
    //   push_rows[n-1] → push(HASH_ADDR) at clock T2 = T1 + 1
    let push_opcode = Felt::from_u8(opcodes::PUSH);
    let push_rows_before_dyncall: Vec<_> = main
        .row_iter()
        .filter(|&i| i < dyncall_row && main.get_op_code(i) == push_opcode)
        .collect();
    let n = push_rows_before_dyncall.len();
    assert!(n >= 2, "expected at least 2 PUSH rows before DYNCALL, found {n}");
    let t1_row = push_rows_before_dyncall[n - 2]; // push(0) → overflow[0]
    let t2_row = push_rows_before_dyncall[n - 1]; // push(HASH_ADDR) → overflow[1]
    let t1 = main.clk(t1_row);
    let t2 = main.clk(t2_row);
    // Sanity: push(0) and push(HASH_ADDR) execute at consecutive clocks in the same op-group.
    assert_eq!(t2, t1 + ONE, "push(0) and push(HASH_ADDR) must be at consecutive clocks");

    // clk_after_pop_in_current_ctx() returns T1 (the second-to-last overflow entry's clock).
    // The buggy last_update_clk_in_current_ctx() would return T2 (the top entry's clock).
    // Asserting exact equality with T1 (not just != ZERO) distinguishes the two code paths
    // even when both T1 and T2 are nonzero.
    assert_eq!(
        recorded_overflow_addr, t1,
        "parent_next_overflow_addr must equal T1 (second-to-last overflow clock = {t1}); \
         T2 (top overflow clock = {t2}) would indicate the buggy \
         last_update_clk_in_current_ctx() path"
    );
}

// HELPER STRUCTS AND METHODS
// ================================================================================================

/// Describes a single entry in the block stack table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStackTableRow {
    block_id: Felt,
    parent_id: Felt,
    is_loop: bool,
    parent_ctx: ContextId,
    parent_fn_hash: Word,
    parent_fmp: Felt,
    parent_stack_depth: u32,
    parent_next_overflow_addr: Felt,
}

impl BlockStackTableRow {
    /// Returns a new [BlockStackTableRow] instantiated with the specified parameters. This is
    /// used for test purpose only.
    #[cfg(test)]
    pub fn new(block_id: Felt, parent_id: Felt, is_loop: bool) -> Self {
        Self {
            block_id,
            parent_id,
            is_loop,
            parent_ctx: ContextId::root(),
            parent_fn_hash: miden_core::EMPTY_WORD,
            parent_fmp: ZERO,
            parent_stack_depth: 0,
            parent_next_overflow_addr: ZERO,
        }
    }
}

impl BlockStackTableRow {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 12 coefficients.
    pub fn to_value<E: ExtensionField<Felt>>(&self, challenges: &Challenges<E>) -> E {
        let is_loop = if self.is_loop { ONE } else { ZERO };
        challenges.bus_prefix[miden_air::trace::bus_types::BLOCK_STACK_TABLE]
            + challenges.beta_powers[0] * self.block_id
            + challenges.beta_powers[1] * self.parent_id
            + challenges.beta_powers[2] * is_loop
            + challenges.beta_powers[3] * Felt::from_u32(u32::from(self.parent_ctx))
            + challenges.beta_powers[4] * self.parent_fmp
            + challenges.beta_powers[5] * Felt::from_u32(self.parent_stack_depth)
            + challenges.beta_powers[6] * self.parent_next_overflow_addr
            + challenges.beta_powers[7] * self.parent_fn_hash[0]
            + challenges.beta_powers[8] * self.parent_fn_hash[1]
            + challenges.beta_powers[9] * self.parent_fn_hash[2]
            + challenges.beta_powers[10] * self.parent_fn_hash[3]
    }
}

/// Describes a single entry in the op group table. An entry in the op group table is a tuple
/// (batch_id, group_pos, group_value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpGroupTableRow {
    batch_id: Felt,
    group_pos: Felt,
    group_value: Felt,
}

impl OpGroupTableRow {
    /// Returns a new [OpGroupTableRow] instantiated with the specified parameters.
    pub fn new(batch_id: Felt, group_pos: Felt, group_value: Felt) -> Self {
        Self { batch_id, group_pos, group_value }
    }
}

impl OpGroupTableRow {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 4 coefficients.
    pub fn to_value<E: ExtensionField<Felt>>(&self, challenges: &Challenges<E>) -> E {
        challenges.bus_prefix[miden_air::trace::bus_types::OP_GROUP_TABLE]
            + challenges.beta_powers[0] * self.batch_id
            + challenges.beta_powers[1] * self.group_pos
            + challenges.beta_powers[2] * self.group_value
    }
}
