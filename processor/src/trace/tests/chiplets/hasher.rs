use alloc::vec::Vec;
use core::ops::Range;

use miden_air::trace::{
    CLK_COL_IDX, DECODER_TRACE_OFFSET, RowIndex,
    chiplets::{
        HASHER_NODE_INDEX_COL_IDX, HASHER_STATE_COL_RANGE, HASHER_TRACE_OFFSET,
        hasher::{
            CAPACITY_DOMAIN_IDX, DIGEST_RANGE, HASH_CYCLE_LEN, HasherState, LAST_CYCLE_ROW,
            LINEAR_HASH, LINEAR_HASH_LABEL, MP_VERIFY, MP_VERIFY_LABEL, MR_UPDATE_NEW,
            MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD, MR_UPDATE_OLD_LABEL, RATE_LEN, RETURN_HASH,
            RETURN_HASH_LABEL, RETURN_STATE, RETURN_STATE_LABEL, STATE_WIDTH, Selectors,
        },
    },
    decoder::{NUM_OP_BITS, OP_BITS_OFFSET},
};
use miden_core::{
    Program, Word,
    chiplets::hasher::apply_permutation,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    field::{Field, PrimeCharacteristicRing},
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SplitNodeBuilder},
    utils::range,
};
use miden_utils_testing::stack;

use super::{
    AUX_TRACE_RAND_ELEMENTS, AdviceInputs, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt,
    ONE, Operation, ZERO, build_span_with_respan_ops, build_trace_from_ops_with_inputs,
    build_trace_from_program, init_state_from_words, rand_array,
};
use crate::{PrimeField64, StackInputs};

// CONSTANTS
// ================================================================================================

const DECODER_HASHER_STATE_RANGE: Range<usize> = range(
    DECODER_TRACE_OFFSET + miden_air::trace::decoder::HASHER_STATE_OFFSET,
    miden_air::trace::decoder::NUM_HASHER_COLUMNS,
);

/// Location of operation bits columns relative to the main trace.
pub const DECODER_OP_BITS_RANGE: Range<usize> =
    range(DECODER_TRACE_OFFSET + OP_BITS_OFFSET, NUM_OP_BITS);

// TESTS
// ================================================================================================

/// Tests the generation of the `b_chip` bus column when the hasher only performs a single `SPAN`
/// with one operation batch.
#[test]
#[expect(clippy::needless_range_loop)]
pub fn b_chip_span() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id =
            BasicBlockNodeBuilder::new(vec![Operation::Add, Operation::Mul], Vec::new())
                .add_to_forest(&mut mast_forest)
                .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };

    let trace = build_trace_from_program(&program, &[]);

    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at the first cycle the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut state, 0.into());
    // request the initialization of the span hash
    let request_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = request_init.inverse();

    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 2..4 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 3 the decoder requests the result of the span hash.
    apply_permutation(&mut state);
    let request_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= request_result.inverse();
    assert_eq!(expected, b_chip[4]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 5..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the hash cycle, the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in HASH_CYCLE_LEN..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher only performs a `SPAN` but it
/// includes multiple batches.
#[test]
#[expect(clippy::needless_range_loop)]
pub fn b_chip_span_with_respan() {
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
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut state, 0.into());
    // request the initialization of the span hash
    let request_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = request_init.inverse();

    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 2..10 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 9, after the first operation batch, the decoder initiates a respan and requests the
    // absorption of the next operation batch.
    apply_permutation(&mut state);
    let prev_state = state;
    // get the state with the next absorbed batch.
    fill_state_from_decoder(&trace, &mut state, 9.into());

    let request_respan = build_expected(
        &alphas,
        LINEAR_HASH_LABEL,
        prev_state,
        state,
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= request_respan.inverse();
    assert_eq!(expected, b_chip[10]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 11..22 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 21, after the second operation batch, the decoder ends the SPAN block and requests
    // its hash.
    apply_permutation(&mut state);
    let request_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        state,
        [ZERO; STATE_WIDTH],
        Felt::new((2 * HASH_CYCLE_LEN) as u64),
        ZERO,
    );
    expected *= request_result.inverse();
    assert_eq!(expected, b_chip[22]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 23..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the first hash cycle, the absorption of the next operation batch is provided
    // by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 1)..(2 * HASH_CYCLE_LEN) {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the second hash cycle, the result of the span hash is provided by the hasher.
    expected *=
        build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN + LAST_CYCLE_ROW).into());
    assert_eq!(expected, b_chip[2 * HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (2 * HASH_CYCLE_LEN)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a merge of two code
/// blocks requested by the decoder. (This also requires a `SPAN` block.)
#[test]
#[expect(clippy::needless_range_loop)]
pub fn b_chip_merge() {
    let program = {
        let mut mast_forest = MastForest::new();

        let t_branch_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let f_branch_id = BasicBlockNodeBuilder::new(vec![Operation::Mul], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        let split_id = SplitNodeBuilder::new([t_branch_id, f_branch_id])
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(split_id);

        Program::new(mast_forest.into(), split_id)
    };

    let trace = build_trace_from_program(&program, &[]);

    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the merge of the split's child hashes is requested by the decoder
    // - the initialization of the code block merge is provided by the hasher

    // initialize the request state.
    let mut split_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut split_state, 0.into());
    // request the initialization of the span hash
    let split_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, split_state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = split_init.inverse();

    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 the initialization of the span block hash for the false branch is requested by the
    // decoder
    let mut f_branch_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut f_branch_state, 1.into());
    // request the initialization of the false branch hash
    let f_branch_init = build_expected(
        &alphas,
        LINEAR_HASH_LABEL,
        f_branch_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        ZERO,
    );
    expected *= f_branch_init.inverse();
    assert_eq!(expected, b_chip[2]);

    // Nothing changes when there is no communication with the hash chiplet.
    assert_eq!(expected, b_chip[3]);

    // at cycle 3 the result hash of the span block for the false branch is requested by the decoder
    apply_permutation(&mut f_branch_state);
    let f_branch_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        f_branch_state,
        [ZERO; STATE_WIDTH],
        Felt::new((2 * HASH_CYCLE_LEN) as u64),
        ZERO,
    );
    expected *= f_branch_result.inverse();
    assert_eq!(expected, b_chip[4]);

    // at cycle 4 the result of the split code block's hash is requested by the decoder
    apply_permutation(&mut split_state);
    let split_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        split_state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= split_result.inverse();
    assert_eq!(expected, b_chip[5]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 6..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the merge hash cycle, the result of the merge is provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // At the start of the next hash cycle, the initialization of the hash of the span block for the
    // false branch is provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(2 * HASH_CYCLE_LEN) {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the false branch hash cycle, the result of the span block for the false branch
    // is provided by the hasher.
    expected *=
        build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN + LAST_CYCLE_ROW).into());
    assert_eq!(expected, b_chip[2 * HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (2 * HASH_CYCLE_LEN)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a permutation
/// requested by the `HPerm` user operation.
#[test]
#[expect(clippy::needless_range_loop)]
pub fn b_chip_permutation() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::HPerm], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    let stack = vec![8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 8];
    let trace = build_trace_from_program(&program, &stack);

    let mut hperm_state: [Felt; STATE_WIDTH] = stack
        .iter()
        .map(|v| Felt::new(*v))
        .collect::<Vec<_>>()
        .try_into()
        .expect("failed to convert vector to array");
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut span_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut span_state, 0.into());
    // request the initialization of the span hash
    let span_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, span_state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = span_init.inverse();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 hperm is executed and the initialization and result of the hash are both
    // requested by the stack.
    let hperm_init = build_expected(
        &alphas,
        LINEAR_HASH_LABEL,
        hperm_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        ZERO,
    );
    // request the hperm initialization.
    expected *= hperm_init.inverse();
    apply_permutation(&mut hperm_state);
    let hperm_result = build_expected(
        &alphas,
        RETURN_STATE_LABEL,
        hperm_state,
        [ZERO; STATE_WIDTH],
        Felt::new((2 * HASH_CYCLE_LEN) as u64),
        ZERO,
    );
    // request the hperm result.
    expected *= hperm_result.inverse();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= span_result.inverse();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the span hash cycle, the result of the span hash is provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // At the start of the next hash cycle, the initialization of the hperm hash is provided by the
    // hasher.
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(2 * HASH_CYCLE_LEN) {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the hperm hash cycle, the result of the hperm hash is provided by the hasher.
    expected *=
        build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN + LAST_CYCLE_ROW).into());
    assert_eq!(expected, b_chip[2 * HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (2 * HASH_CYCLE_LEN)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a log_precompile
/// operation requested by the stack. The operation absorbs TAG and COMM into a Poseidon2
/// sponge with capacity CAP_PREV, producing (CAP_NEXT, R0, R1).
#[test]
#[expect(clippy::needless_range_loop)]
pub fn b_chip_log_precompile() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::LogPrecompile], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    // Runtime stack layout: [COMM(5,6,7,8), TAG(1,2,3,4)] with comm[0]=5 on top
    let comm_word: Word = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();
    let tag_word: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    // stack! takes elements in runtime order (first = top) and handles reversal
    let stack_inputs = stack![5, 6, 7, 8, 1, 2, 3, 4];
    let trace = build_trace_from_program(&program, &stack_inputs);

    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    let mut expected = ONE;

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut span_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut span_state, 0.into());
    // request the initialization of the span hash
    let span_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, span_state, [ZERO; STATE_WIDTH], ONE, ZERO);
    expected *= span_init.inverse();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 log_precompile is executed and the initialization and result of the hash are both
    // requested by the stack.

    // Build the input state in sponge order: [COMM, TAG, CAP_PREV] = [RATE0, RATE1, CAP]
    // CAP_PREV comes from helper registers and defaults to [0,0,0,0].
    // COMM = [5,6,7,8] is at stack positions 0-3.
    // TAG = [1,2,3,4] is at stack positions 4-7.
    // init_state_from_words(w1, w2) puts w1 at RATE0 and w2 at RATE1.
    let log_pc_state = init_state_from_words(&comm_word, &tag_word);

    let log_pc_init = build_expected(
        &alphas,
        LINEAR_HASH_LABEL,
        log_pc_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        ZERO,
    );
    // request the log_precompile initialization.
    expected *= log_pc_init.inverse();

    // Compute the output state by applying the permutation
    let mut log_pc_output_state = log_pc_state;
    apply_permutation(&mut log_pc_output_state);

    let log_pc_result = build_expected(
        &alphas,
        RETURN_STATE_LABEL,
        log_pc_output_state,
        [ZERO; STATE_WIDTH],
        Felt::new((2 * HASH_CYCLE_LEN) as u64),
        ZERO,
    );
    // request the log_precompile result.
    expected *= log_pc_result.inverse();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= span_result.inverse();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // at cycle 8 the initialization of the log_precompile hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(2 * HASH_CYCLE_LEN) {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 15 the result of the log_precompile hash is provided by the hasher
    expected *=
        build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN + LAST_CYCLE_ROW).into());
    assert_eq!(expected, b_chip[2 * HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (2 * HASH_CYCLE_LEN)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle path
/// verification requested by the `MpVerify` user operation.
#[test]
#[expect(clippy::needless_range_loop)]
fn b_chip_mpverify() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut runtime_stack = Vec::new();
    runtime_stack.extend_from_slice(&word_to_ints(leaves[index]));
    runtime_stack.push(tree.depth() as u64);
    runtime_stack.push(index as u64);
    runtime_stack.extend_from_slice(&word_to_ints(tree.root()));
    let stack_inputs = StackInputs::try_from_ints(runtime_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let trace = build_trace_from_ops_with_inputs(
        vec![Operation::MpVerify(ZERO)],
        stack_inputs,
        advice_inputs,
    );
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut span_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut span_state, 0.into());
    // request the initialization of the span hash
    let span_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, span_state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = span_init.inverse();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 a merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(&path[0], &leaves[index]);
    let mp_init = build_expected(
        &alphas,
        MP_VERIFY_LABEL,
        mp_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        Felt::new(index as u64),
    );
    // request the initialization of the Merkle path verification
    expected *= mp_init.inverse();

    let mp_verify_complete = HASH_CYCLE_LEN + (tree.depth() as usize) * HASH_CYCLE_LEN;
    let mut result_state = [ZERO; STATE_WIDTH];
    result_state[DIGEST_RANGE].copy_from_slice(tree.root().as_elements());
    let mp_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        result_state,
        [ZERO; STATE_WIDTH],
        Felt::new(mp_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );
    // request the result of the Merkle path verification
    expected *= mp_result.inverse();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= span_result.inverse();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the span hash cycle, the result of the span hash is provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // At the start of the next hash cycle, the initialization of the merkle path is provided by
    // the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(mp_verify_complete) {
        assert_eq!(expected, b_chip[row]);
    }

    // when the merkle path verification has been completed the hasher provides the result
    expected *= build_expected_from_trace(&trace, &alphas, (mp_verify_complete - 1).into());
    assert_eq!(expected, b_chip[mp_verify_complete]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in mp_verify_complete..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle root update
/// requested by the `MrUpdate` user operation.
#[test]
#[expect(clippy::needless_range_loop)]
fn b_chip_mrupdate() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut tree = MerkleTree::new(&leaves).unwrap();

    let old_root = tree.root();
    let old_leaf_value = leaves[index];

    let new_leaf_value = leaves[0];

    let mut runtime_stack = Vec::new();
    runtime_stack.extend_from_slice(&word_to_ints(old_leaf_value));
    runtime_stack.push(tree.depth() as u64);
    runtime_stack.push(index as u64);
    runtime_stack.extend_from_slice(&word_to_ints(old_root));
    runtime_stack.extend_from_slice(&word_to_ints(new_leaf_value));
    let stack_inputs = StackInputs::try_from_ints(runtime_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let trace =
        build_trace_from_ops_with_inputs(vec![Operation::MrUpdate], stack_inputs, advice_inputs);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // at cycle 0 the following are added for inclusion in the next row:
    // - the initialization of the span hash is requested by the decoder
    // - the initialization of the span hash is provided by the hasher

    // initialize the request state.
    let mut span_state = [ZERO; STATE_WIDTH];
    fill_state_from_decoder_with_domain(&trace, &mut span_state, 0.into());
    // request the initialization of the span hash
    let span_init =
        build_expected(&alphas, LINEAR_HASH_LABEL, span_state, [ZERO; STATE_WIDTH], ONE, ZERO);
    let mut expected = span_init.inverse();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 a merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(&path[0], &leaves[index]);
    let mp_init_old = build_expected(
        &alphas,
        MR_UPDATE_OLD_LABEL,
        mp_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        Felt::new(index as u64),
    );
    // request the initialization of the (first) Merkle path verification
    expected *= mp_init_old.inverse();

    let mp_old_verify_complete = HASH_CYCLE_LEN + (tree.depth() as usize) * HASH_CYCLE_LEN;
    let mut result_state_old = [ZERO; STATE_WIDTH];
    result_state_old[DIGEST_RANGE].copy_from_slice(tree.root().as_elements());
    let mp_result_old = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        result_state_old,
        [ZERO; STATE_WIDTH],
        Felt::new(mp_old_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );

    // request the result of the first Merkle path verification
    expected *= mp_result_old.inverse();

    let new_leaf_value = leaves[0];
    tree.update_leaf(index as u64, new_leaf_value).unwrap();
    let new_root = tree.root();

    // a second merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(&path[0], &new_leaf_value);

    let mp_new_verify_complete = mp_old_verify_complete + (tree.depth() as usize) * HASH_CYCLE_LEN;
    let mp_init_new = build_expected(
        &alphas,
        MR_UPDATE_NEW_LABEL,
        mp_state,
        [ZERO; STATE_WIDTH],
        Felt::new(mp_old_verify_complete as u64 + 1),
        Felt::new(index as u64),
    );

    // request the initialization of the second Merkle path verification
    expected *= mp_init_new.inverse();

    let mut result_state_new = [ZERO; STATE_WIDTH];
    result_state_new[DIGEST_RANGE].copy_from_slice(new_root.as_elements());
    let mp_result_new = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        result_state_new,
        [ZERO; STATE_WIDTH],
        Felt::new(mp_new_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );

    // request the result of the second Merkle path verification
    expected *= mp_result_new.inverse();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(HASH_CYCLE_LEN as u64),
        ZERO,
    );
    expected *= span_result.inverse();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the span hash cycle, the result of the span hash is provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, LAST_CYCLE_ROW.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // At the start of the next hash cycle, the initialization of the first merkle path is provided
    // by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(mp_old_verify_complete) {
        assert_eq!(expected, b_chip[row]);
    }

    // when the first merkle path verification has been completed the hasher provides the result
    expected *= build_expected_from_trace(&trace, &alphas, (mp_old_verify_complete - 1).into());
    assert_eq!(expected, b_chip[mp_old_verify_complete]);

    // at cycle 32 the initialization of the second merkle path is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, mp_old_verify_complete.into());
    assert_eq!(expected, b_chip[mp_old_verify_complete + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (mp_old_verify_complete + 1)..(mp_new_verify_complete) {
        assert_eq!(expected, b_chip[row]);
    }

    // when the merkle path verification has been completed the hasher provides the result
    expected *= build_expected_from_trace(&trace, &alphas, (mp_new_verify_complete - 1).into());
    assert_eq!(expected, b_chip[mp_new_verify_complete]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (mp_new_verify_complete)..trace.length() {
        assert_eq!(ONE, b_chip[row]);
    }
}

// TEST HELPERS
// ================================================================================================

/// Reduces the provided hasher row information to an expected value.
fn build_expected(
    alphas: &[Felt],
    label: u8,
    state: HasherState,
    next_state: HasherState,
    addr: Felt,
    index: Felt,
) -> Felt {
    let first_cycle_row = addr_to_cycle_row(addr) == 0;
    let transition_label = if first_cycle_row { label + 16_u8 } else { label + 32_u8 };
    let header = alphas[0]
        + alphas[1] * Felt::from_u8(transition_label)
        + alphas[2] * addr
        + alphas[3] * index;
    let mut value = header;

    if (first_cycle_row && label == LINEAR_HASH_LABEL) || label == RETURN_STATE_LABEL {
        // include the entire state (words a, b, c)
        value += build_value(&alphas[4..16], &state);
    } else if label == LINEAR_HASH_LABEL {
        // Include the next absorbed rate portion of the state (RATE0 || RATE1).
        // With LE sponge layout [RATE0, RATE1, CAP], rate is at indices 0..8.
        value += build_value(&alphas[8..16], &next_state[0..RATE_LEN]);
    } else if label == RETURN_HASH_LABEL {
        // include the digest (word b)
        value += build_value(&alphas[8..12], &state[DIGEST_RANGE]);
    } else {
        assert!(
            label == MP_VERIFY_LABEL
                || label == MR_UPDATE_NEW_LABEL
                || label == MR_UPDATE_OLD_LABEL
        );
        let bit = index.as_canonical_u64() & 1;
        // For Merkle operations, RATE0 and RATE1 hold the two child digests.
        // With LE sponge layout [RATE0, RATE1, CAP], they are at indices 0..4 and 4..8.
        let left_word = build_value(&alphas[8..12], &state[0..4]);
        let right_word = build_value(&alphas[8..12], &state[4..8]);

        value += Felt::new(1 - bit) * left_word + Felt::new(bit) * right_word;
    }

    value
}

/// Reduces the specified row in the execution trace to an expected value representing a hash
/// operation lookup.
fn build_expected_from_trace(trace: &ExecutionTrace, alphas: &[Felt], row: RowIndex) -> Felt {
    let s0 = trace.main_trace.get_column(HASHER_TRACE_OFFSET)[row];
    let s1 = trace.main_trace.get_column(HASHER_TRACE_OFFSET + 1)[row];
    let s2 = trace.main_trace.get_column(HASHER_TRACE_OFFSET + 2)[row];
    let selectors: Selectors = [s0, s1, s2];

    let label = get_label_from_selectors(selectors)
        .expect("unrecognized hasher operation label in hasher trace");

    let addr = trace.main_trace.get_column(CLK_COL_IDX)[row] + ONE;
    let index = trace.main_trace.get_column(HASHER_NODE_INDEX_COL_IDX)[row];

    let cycle_row = addr_to_cycle_row(addr);

    // Trace is already in sponge order [RATE0, RATE1, CAP]
    let mut state = [ZERO; STATE_WIDTH];
    let mut next_state = [ZERO; STATE_WIDTH];
    for (i, col_idx) in HASHER_STATE_COL_RANGE.enumerate() {
        state[i] = trace.main_trace.get_column(col_idx)[row];
        if cycle_row == LAST_CYCLE_ROW && label == LINEAR_HASH_LABEL {
            next_state[i] = trace.main_trace.get_column(col_idx)[row + 1];
        }
    }

    build_expected(alphas, label, state, next_state, addr, index)
}

/// Builds a value from alphas and elements of matching lengths. This can be used to build the
/// value for a single word or for the entire state.
fn build_value(alphas: &[Felt], elements: &[Felt]) -> Felt {
    let mut value = ZERO;
    for (&alpha, &element) in alphas.iter().zip(elements.iter()) {
        value += alpha * element;
    }
    value
}

/// Returns the hash operation label for the specified selectors.
fn get_label_from_selectors(selectors: Selectors) -> Option<u8> {
    if selectors == LINEAR_HASH {
        Some(LINEAR_HASH_LABEL)
    } else if selectors == MP_VERIFY {
        Some(MP_VERIFY_LABEL)
    } else if selectors == MR_UPDATE_OLD {
        Some(MR_UPDATE_OLD_LABEL)
    } else if selectors == MR_UPDATE_NEW {
        Some(MR_UPDATE_NEW_LABEL)
    } else if selectors == RETURN_HASH {
        Some(RETURN_HASH_LABEL)
    } else if selectors == RETURN_STATE {
        Some(RETURN_STATE_LABEL)
    } else {
        None
    }
}

/// Populates the provided HasherState with the state stored in the decoder's execution trace at the
/// specified row.
fn fill_state_from_decoder_with_domain(
    trace: &ExecutionTrace,
    state: &mut HasherState,
    row: RowIndex,
) {
    let domain = extract_control_block_domain_from_trace(trace, row);
    state[CAPACITY_DOMAIN_IDX] = domain;

    fill_state_from_decoder(trace, state, row);
}

/// Populates the provided HasherState with the state stored in the decoder's execution trace at the
/// specified row. The decoder stores the 8 rate elements which go at sponge indices 0..8.
fn fill_state_from_decoder(trace: &ExecutionTrace, state: &mut HasherState, row: RowIndex) {
    for (i, col_idx) in DECODER_HASHER_STATE_RANGE.enumerate() {
        // In sponge order [RATE0, RATE1, CAP], rate is at indices 0..8
        state[i] = trace.main_trace.get_column(col_idx)[row];
    }
}

/// Extract the control block domain from the execution trace.  This is achieved
/// by calculating the op code as [bit_0 * 2**0 + bit_1 * 2**1 + ... + bit_6 * 2**6]
fn extract_control_block_domain_from_trace(trace: &ExecutionTrace, row: RowIndex) -> Felt {
    // calculate the op code
    let opcode_value = DECODER_OP_BITS_RANGE.rev().fold(0u8, |result, bit_index| {
        let op_bit = trace.main_trace.get_column(bit_index)[row].as_canonical_u64() as u8;
        (result << 1) ^ op_bit
    });

    // opcode values that represent control block initialization (excluding span)
    let control_block_initializers = [
        Operation::Call.op_code(),
        Operation::Join.op_code(),
        Operation::Loop.op_code(),
        Operation::Split.op_code(),
        Operation::SysCall.op_code(),
    ];

    if control_block_initializers.contains(&opcode_value) {
        Felt::from_u8(opcode_value)
    } else {
        ZERO
    }
}

/// Returns the row of the hash cycle which corresponds to the provided Hasher address.
fn addr_to_cycle_row(addr: Felt) -> usize {
    let cycle = (addr.as_canonical_u64() - 1) as usize;
    let cycle_row = cycle % HASH_CYCLE_LEN;
    debug_assert!(
        cycle_row == 0 || cycle_row == LAST_CYCLE_ROW,
        "invalid address for hasher lookup"
    );

    cycle_row
}

/// Initializes Merkle tree leaves with the specified values.
fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

/// Initializes a Merkle tree leaf with the specified value.
fn init_leaf(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO].into()
}

/// Converts a Word to stack input values (u64 array) in element order.
fn word_to_ints(w: Word) -> [u64; 4] {
    [
        w[0].as_canonical_u64(),
        w[1].as_canonical_u64(),
        w[2].as_canonical_u64(),
        w[3].as_canonical_u64(),
    ]
}
