use alloc::vec::Vec;

use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS,
    decoder::{P1_COL_IDX, P2_COL_IDX, P3_COL_IDX},
};
use miden_core::{
    ONE, Operation, Program, Word, ZERO,
    field::{ExtensionField, Field, PrimeCharacteristicRing},
    mast::{
        BasicBlockNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor,
        MastNodeExt, SplitNodeBuilder,
    },
};
use miden_utils_testing::rand::rand_array;

use super::{
    super::{
        tests::{build_trace_from_ops, build_trace_from_program},
        utils::build_span_with_respan_ops,
    },
    Felt,
};
use crate::{
    ContextId,
    decoder::{BlockHashTableRow, build_op_group},
};

// BLOCK STACK TABLE TESTS
// ================================================================================================

#[test]
#[expect(clippy::needless_range_loop)]
fn decoder_p1_span_with_respan() {
    let (ops, _) = build_span_with_respan_ops();
    let trace = build_trace_from_ops(ops, &[]);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&alphas),
        BlockStackTableRow::new(Felt::new(9), ZERO, false).to_value(&alphas),
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
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let a_9 = Felt::new(9);
    let a_17 = Felt::new(17);
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&alphas),
        BlockStackTableRow::new(a_9, ONE, false).to_value(&alphas),
        BlockStackTableRow::new(a_17, ONE, false).to_value(&alphas),
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
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let a_9 = Felt::new(9);
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, false).to_value(&alphas),
        BlockStackTableRow::new(a_9, ONE, false).to_value(&alphas),
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
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let a_9 = Felt::new(9); // address of the JOIN block in the first iteration
    let a_17 = Felt::new(17); // address of the first SPAN block in the first iteration
    let a_25 = Felt::new(25); // address of the second SPAN block in the first iteration
    let a_33 = Felt::new(33); // address of the JOIN block in the second iteration
    let a_41 = Felt::new(41); // address of the first SPAN block in the second iteration
    let a_49 = Felt::new(49); // address of the second SPAN block in the second iteration
    let row_values = [
        BlockStackTableRow::new(ONE, ZERO, true).to_value(&alphas),
        BlockStackTableRow::new(a_9, ONE, false).to_value(&alphas),
        BlockStackTableRow::new(a_17, a_9, false).to_value(&alphas),
        BlockStackTableRow::new(a_25, a_9, false).to_value(&alphas),
        BlockStackTableRow::new(a_33, ONE, false).to_value(&alphas),
        BlockStackTableRow::new(a_41, a_33, false).to_value(&alphas),
        BlockStackTableRow::new(a_49, a_33, false).to_value(&alphas),
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
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let row_values =
        [BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&alphas)];

    // make sure the first entry is initialized to program hash
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p2[0]);

    // as operations inside the span execute (including RESPAN), the table is not affected
    for i in 1..22 {
        assert_eq!(expected_value, p2[i]);
    }

    // at cycle 22, the END operation is executed and the table is cleared
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, ONE);
    for i in 22..(p2.len()) {
        assert_eq!(ONE, p2[i]);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let row_values = [
        BlockHashTableRow::new_test(ZERO, join.digest(), false, false).collapse(&alphas),
        BlockHashTableRow::new_test(ONE, basic_block_1.digest(), true, false).collapse(&alphas),
        BlockHashTableRow::new_test(ONE, basic_block_2.digest(), false, false).collapse(&alphas),
    ];

    // make sure the first entry is initialized to program hash
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p2[0]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= row_values[1] * row_values[2];
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p2[4]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[5]);
    assert_eq!(expected_value, p2[6]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p2[7]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p2[8]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 9..(p2.len()) {
        assert_eq!(ONE, p2[i]);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let row_values = [
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&alphas),
        BlockHashTableRow::new_test(ONE, basic_block_1.digest(), false, false).collapse(&alphas),
    ];

    // make sure the first entry is initialized to program hash
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p2[0]);

    // when SPLIT operation is executed, entry for the true branch is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the SPAN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p2[4]);

    // when the SPLIT block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p2[5]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 6..(p2.len()) {
        assert_eq!(ONE, p2[i]);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let row_values = [
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&alphas),
        BlockHashTableRow::new_test(ONE, basic_block_2.digest(), false, false).collapse(&alphas),
    ];

    // make sure the first entry is initialized to program hash
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p2[0]);

    // when SPLIT operation is executed, entry for the false branch is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p2[1]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[2]);
    assert_eq!(expected_value, p2[3]);

    // when the SPAN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p2[4]);

    // when the SPLIT block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p2[5]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 6..(p2.len()) {
        assert_eq!(ONE, p2[i]);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p2 = aux_columns.get_column(P2_COL_IDX);

    let a_9 = Felt::new(9); // address of the JOIN block in the first iteration
    let a_33 = Felt::new(33); // address of the JOIN block in the second iteration
    let row_values = [
        BlockHashTableRow::new_test(ZERO, program.hash(), false, false).collapse(&alphas),
        BlockHashTableRow::new_test(ONE, join.digest(), false, true).collapse(&alphas),
        BlockHashTableRow::new_test(a_9, basic_block_1.digest(), true, false).collapse(&alphas),
        BlockHashTableRow::new_test(a_9, basic_block_2.digest(), false, false).collapse(&alphas),
        BlockHashTableRow::new_test(a_33, basic_block_1.digest(), true, false).collapse(&alphas),
        BlockHashTableRow::new_test(a_33, basic_block_2.digest(), false, false).collapse(&alphas),
    ];

    // make sure the first entry is initialized to program hash
    let mut expected_value = row_values[0];
    assert_eq!(expected_value, p2[0]);

    // --- first iteration ----------------------------------------------------

    // when LOOP operation is executed, entry for loop body is added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p2[1]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= row_values[2] * row_values[3];
    assert_eq!(expected_value, p2[2]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[3]);
    assert_eq!(expected_value, p2[4]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p2[5]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[6]);
    assert_eq!(expected_value, p2[7]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[3].inverse();
    assert_eq!(expected_value, p2[8]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p2[9]);

    // --- second iteration ---------------------------------------------------

    // when REPEAT operation is executed, entry for loop body is again added to the table
    expected_value *= row_values[1];
    assert_eq!(expected_value, p2[10]);

    // when JOIN operation is executed, entries for both children are added to the table
    expected_value *= row_values[4] * row_values[5];
    assert_eq!(expected_value, p2[11]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[12]);
    assert_eq!(expected_value, p2[13]);

    // when the first SPAN block ends, its entry is removed from the table
    expected_value *= row_values[4].inverse();
    assert_eq!(expected_value, p2[14]);

    // for the next 2 cycles, the table is not affected
    assert_eq!(expected_value, p2[15]);
    assert_eq!(expected_value, p2[16]);

    // when the second SPAN block ends, its entry is removed from the table
    expected_value *= row_values[5].inverse();
    assert_eq!(expected_value, p2[17]);

    // when the JOIN block ends, its entry is removed from the table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p2[18]);

    // when the LOOP block ends, its entry is removed from the table
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p2[19]);

    // at this point the table should be empty, and thus, all subsequent values must be ONE
    assert_eq!(expected_value, ONE);
    for i in 20..(p2.len()) {
        assert_eq!(ONE, p2[i]);
    }
}

// OP GROUP TABLE TESTS
// ================================================================================================

#[test]
fn decoder_p3_trace_empty_table() {
    let stack = [1, 2];
    let operations = vec![Operation::Add];
    let trace = build_trace_from_ops(operations, &stack);

    let rand_elements = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&rand_elements).unwrap();

    // no rows should have been added or removed from the op group table, and thus, all values
    // in the column must be ONE
    let p3 = aux_columns.get_column(P3_COL_IDX);
    for &value in p3.iter().take(p3.len()) {
        assert_eq!(ONE, value);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
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
        Operation::Push(Felt::new(2)),
        Operation::Add,
        Operation::Swap,
        Operation::Mul,
        Operation::Add,
    ];
    let trace = build_trace_from_ops(ops.clone(), &stack);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p3 = aux_columns.get_column(P3_COL_IDX);

    // make sure the first entry is ONE
    assert_eq!(ONE, p3[0]);

    // make sure 3 groups were inserted at clock cycle 1; these entries are for the two immediate
    // values and the second operation group consisting of [SWAP, MUL, ADD]
    let g1_value = OpGroupTableRow::new(ONE, Felt::new(3), ONE).to_value(&alphas);
    let g2_value = OpGroupTableRow::new(ONE, Felt::new(2), Felt::new(2)).to_value(&alphas);
    let g3_value = OpGroupTableRow::new(ONE, ONE, build_op_group(&ops[9..])).to_value(&alphas);
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
#[expect(clippy::needless_range_loop)]
fn decoder_p3_trace_two_batches() {
    let (ops, iv) = build_span_with_respan_ops();
    let trace = build_trace_from_ops(ops, &[]);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p3 = aux_columns.get_column(P3_COL_IDX);

    // make sure the first entry is ONE
    assert_eq!(ONE, p3[0]);

    // --- first batch ----------------------------------------------------------------------------
    // make sure entries for 7 groups were inserted at clock cycle 1
    let b0_values = [
        OpGroupTableRow::new(ONE, Felt::new(11), iv[0]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(10), iv[1]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(9), iv[2]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(8), iv[3]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(7), iv[4]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(6), iv[5]).to_value(&alphas),
        OpGroupTableRow::new(ONE, Felt::new(5), iv[6]).to_value(&alphas),
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
    let batch1_addr = ONE + Felt::new(8);
    let op_group3 = build_op_group(&[Operation::Drop; 2]);
    let b1_values = [
        OpGroupTableRow::new(batch1_addr, Felt::new(3), iv[7]).to_value(&alphas),
        OpGroupTableRow::new(batch1_addr, Felt::new(2), iv[8]).to_value(&alphas),
        OpGroupTableRow::new(batch1_addr, ONE, op_group3).to_value(&alphas),
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
    /// at least 12 alpha values.
    pub fn to_value<E: ExtensionField<Felt>>(&self, alphas: &[E]) -> E {
        let is_loop = if self.is_loop { ONE } else { ZERO };
        alphas[0]
            + alphas[1] * self.block_id
            + alphas[2] * self.parent_id
            + alphas[3] * is_loop
            + alphas[4] * Felt::from_u32(u32::from(self.parent_ctx))
            + alphas[5] * self.parent_fmp
            + alphas[6] * Felt::from_u32(self.parent_stack_depth)
            + alphas[7] * self.parent_next_overflow_addr
            + alphas[8] * self.parent_fn_hash[0]
            + alphas[9] * self.parent_fn_hash[1]
            + alphas[10] * self.parent_fn_hash[2]
            + alphas[11] * self.parent_fn_hash[3]
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
    /// at least 4 alpha values.
    pub fn to_value<E: ExtensionField<Felt>>(&self, alphas: &[E]) -> E {
        alphas[0]
            + alphas[1] * self.batch_id
            + alphas[2] * self.group_pos
            + alphas[3] * self.group_value
    }
}
