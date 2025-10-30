use alloc::vec::Vec;
use core::ops::Range;

use miden_air::{
    RowIndex,
    trace::{
        CLK_COL_IDX, DECODER_TRACE_OFFSET,
        chiplets::{
            HASHER_NODE_INDEX_COL_IDX, HASHER_STATE_COL_RANGE, HASHER_TRACE_OFFSET,
            hasher::{
                CAPACITY_DOMAIN_IDX, CAPACITY_LEN, DIGEST_RANGE, HASH_CYCLE_LEN, HasherState,
                LINEAR_HASH, LINEAR_HASH_LABEL, MP_VERIFY, MP_VERIFY_LABEL, MR_UPDATE_NEW,
                MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD, MR_UPDATE_OLD_LABEL, RETURN_HASH,
                RETURN_HASH_LABEL, RETURN_STATE, RETURN_STATE_LABEL, STATE_WIDTH, Selectors,
            },
        },
        decoder::{NUM_OP_BITS, OP_BITS_OFFSET},
    },
};
use miden_core::{
    Program, Word,
    chiplets::hasher::apply_permutation,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    mast::MastForest,
    utils::range,
};

use super::{
    AUX_TRACE_RAND_ELEMENTS, AdviceInputs, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt,
    FieldElement, NUM_RAND_ROWS, ONE, Operation, Trace, ZERO, build_span_with_respan_ops,
    build_trace_from_ops_with_inputs, build_trace_from_program, init_state_from_words, rand_array,
};
use crate::StackInputs;

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
#[allow(clippy::needless_range_loop)]
pub fn b_chip_span() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id =
            mast_forest.add_block(vec![Operation::Add, Operation::Mul], Vec::new()).unwrap();
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
    let mut expected = request_init.inv();

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
    expected *= request_result.inv();
    assert_eq!(expected, b_chip[4]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 5..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the hash cycle, the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN - 1).into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in HASH_CYCLE_LEN..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher only performs a `SPAN` but it
/// includes multiple batches.
#[test]
#[allow(clippy::needless_range_loop)]
pub fn b_chip_span_with_respan() {
    let program = {
        let mut mast_forest = MastForest::new();

        let (ops, _) = build_span_with_respan_ops();
        let basic_block_id = mast_forest.add_block(ops, Vec::new()).unwrap();
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
    let mut expected = request_init.inv();

    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 2..8 {
        assert_eq!(expected, b_chip[row]);
    }

    // At the end of the first hash cycle at cycle 7, the absorption of the next operation batch is
    // provided by the hasher.
    expected *= build_expected_from_trace(&trace, &alphas, 7.into());
    assert_eq!(expected, b_chip[8]);

    // Nothing changes when there is no communication with the hash chiplet.
    assert_eq!(expected, b_chip[9]);

    // At cycle 9, after the first operation batch, the decoder initiates a respan and requests the
    // absorption of the next operation batch.
    apply_permutation(&mut state);
    let prev_state = state;
    // get the state with the next absorbed batch.
    fill_state_from_decoder(&trace, &mut state, 9.into());

    let request_respan =
        build_expected(&alphas, LINEAR_HASH_LABEL, prev_state, state, Felt::new(8), ZERO);
    expected *= request_respan.inv();
    assert_eq!(expected, b_chip[10]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 11..16 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 15 at the end of the second hash cycle, the result of the span hash is provided by
    // the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 15.into());
    assert_eq!(expected, b_chip[16]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 17..22 {
        assert_eq!(expected, b_chip[row]);
    }

    // At cycle 21, after the second operation batch, the decoder ends the SPAN block and requests
    // its hash.
    apply_permutation(&mut state);
    let request_result =
        build_expected(&alphas, RETURN_HASH_LABEL, state, [ZERO; STATE_WIDTH], Felt::new(16), ZERO);
    expected *= request_result.inv();
    assert_eq!(expected, b_chip[22]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in 22..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a merge of two code
/// blocks requested by the decoder. (This also requires a `SPAN` block.)
#[test]
#[allow(clippy::needless_range_loop)]
pub fn b_chip_merge() {
    let program = {
        let mut mast_forest = MastForest::new();

        let t_branch_id = mast_forest.add_block(vec![Operation::Add], Vec::new()).unwrap();
        let f_branch_id = mast_forest.add_block(vec![Operation::Mul], Vec::new()).unwrap();
        let split_id = mast_forest.add_split(t_branch_id, f_branch_id).unwrap();
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
    let mut expected = split_init.inv();

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
        Felt::new(9),
        ZERO,
    );
    expected *= f_branch_init.inv();
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
        Felt::new(16),
        ZERO,
    );
    expected *= f_branch_result.inv();
    assert_eq!(expected, b_chip[4]);

    // at cycle 4 the result of the split code block's hash is requested by the decoder
    apply_permutation(&mut split_state);
    let split_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        split_state,
        [ZERO; STATE_WIDTH],
        Felt::new(8),
        ZERO,
    );
    expected *= split_result.inv();
    assert_eq!(expected, b_chip[5]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 6..8 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the merge is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 7.into());
    assert_eq!(expected, b_chip[8]);

    // at cycle 8 the initialization of the hash of the span block for the false branch is provided
    // by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 8.into());
    assert_eq!(expected, b_chip[9]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 9..16 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 15 the result of the span block for the false branch is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 15.into());
    assert_eq!(expected, b_chip[16]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in 16..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a permutation
/// requested by the `HPerm` user operation.
#[test]
#[allow(clippy::needless_range_loop)]
pub fn b_chip_permutation() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = mast_forest.add_block(vec![Operation::HPerm], Vec::new()).unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    let stack = vec![8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
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
    let mut expected = span_init.inv();
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
        Felt::new(9),
        ZERO,
    );
    // request the hperm initialization.
    expected *= hperm_init.inv();
    apply_permutation(&mut hperm_state);
    let hperm_result = build_expected(
        &alphas,
        RETURN_STATE_LABEL,
        hperm_state,
        [ZERO; STATE_WIDTH],
        Felt::new(16),
        ZERO,
    );
    // request the hperm result.
    expected *= hperm_result.inv();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(8),
        ZERO,
    );
    expected *= span_result.inv();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..8 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 7.into());
    assert_eq!(expected, b_chip[8]);

    // at cycle 8 the initialization of the hperm hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 8.into());
    assert_eq!(expected, b_chip[9]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 10..16 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 15 the result of the hperm hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 15.into());
    assert_eq!(expected, b_chip[16]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in 16..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a log_precompile
/// operation requested by the stack. The operation absorbs TAG and COMM into an RPO
/// sponge with capacity CAP_PREV, producing (CAP_NEXT, R0, R1).
#[test]
#[allow(clippy::needless_range_loop)]
pub fn b_chip_log_precompile() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id =
            mast_forest.add_block(vec![Operation::LogPrecompile], Vec::new()).unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    // Stack inputs are specified deepest-first: [1,2,3,4,5,6,7,8]. The VM reverses them at
    // initialization, so the live stack holds [8,7,6,5,4,3,2,1] with 8 on top. Because
    // `stack.get_word` collects elements in reverse order from the stack slots (i.e.,
    // [stack[3], stack[2], stack[1], stack[0]]), `COMM` is read as
    // [5,6,7,8] from stack slots 0-3 and `TAG` as [1,2,3,4] from slots 4-7.
    let stack = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let trace = build_trace_from_program(&program, &stack);

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
    expected *= span_init.inv();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 log_precompile is executed and the initialization and result of the hash are both
    // requested by the stack.

    // Build the input state: [CAP_PREV, TAG, COMM]
    // CAP_PREV comes from helper registers and defaults to [0,0,0,0].
    // TAG = [1,2,3,4] is drawn via `stack.get_word(4)`.
    // COMM = [5,6,7,8] is drawn via `stack.get_word(0)`.
    let log_pc_state = init_state_from_words(
        &[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into(),
        &[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into(),
    );

    let log_pc_init = build_expected(
        &alphas,
        LINEAR_HASH_LABEL,
        log_pc_state,
        [ZERO; STATE_WIDTH],
        Felt::new((HASH_CYCLE_LEN + 1) as u64),
        ZERO,
    );
    // request the log_precompile initialization.
    expected *= log_pc_init.inv();

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
    expected *= log_pc_result.inv();
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
    expected *= span_result.inv();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 4..HASH_CYCLE_LEN {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, (HASH_CYCLE_LEN - 1).into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN]);

    // at cycle 8 the initialization of the log_precompile hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, HASH_CYCLE_LEN.into());
    assert_eq!(expected, b_chip[HASH_CYCLE_LEN + 1]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in (HASH_CYCLE_LEN + 2)..(2 * HASH_CYCLE_LEN) {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 15 the result of the log_precompile hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, (2 * HASH_CYCLE_LEN - 1).into());
    assert_eq!(expected, b_chip[2 * HASH_CYCLE_LEN]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in (2 * HASH_CYCLE_LEN)..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle path
/// verification requested by the `MpVerify` user operation.
#[test]
#[allow(clippy::needless_range_loop)]
fn b_chip_mpverify() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let stack_inputs = [
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        index as u64,
        tree.depth() as u64,
        leaves[index][0].as_int(),
        leaves[index][1].as_int(),
        leaves[index][2].as_int(),
        leaves[index][3].as_int(),
    ];
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
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
    let mut expected = span_init.inv();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 a merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(
        &[path[0][0], path[0][1], path[0][2], path[0][3]].into(),
        &[leaves[index][0], leaves[index][1], leaves[index][2], leaves[index][3]].into(),
    );
    let mp_init = build_expected(
        &alphas,
        MP_VERIFY_LABEL,
        mp_state,
        [ZERO; STATE_WIDTH],
        Felt::new(9),
        Felt::new(index as u64),
    );
    // request the initialization of the Merkle path verification
    expected *= mp_init.inv();

    let mp_verify_complete = HASH_CYCLE_LEN + (tree.depth() as usize) * HASH_CYCLE_LEN;
    let mp_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        // for the return hash, only the state digest matters, and it should match the root
        [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            tree.root()[0],
            tree.root()[1],
            tree.root()[2],
            tree.root()[3],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        [ZERO; STATE_WIDTH],
        Felt::new(mp_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );
    // request the result of the Merkle path verification
    expected *= mp_result.inv();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(8),
        ZERO,
    );
    expected *= span_result.inv();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 3..8 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 7.into());
    assert_eq!(expected, b_chip[8]);

    // at cycle 8 the initialization of the merkle path is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 8.into());
    assert_eq!(expected, b_chip[9]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 10..(mp_verify_complete) {
        assert_eq!(expected, b_chip[row]);
    }

    // when the merkle path verification has been completed the hasher provides the result
    expected *= build_expected_from_trace(&trace, &alphas, (mp_verify_complete - 1).into());
    assert_eq!(expected, b_chip[mp_verify_complete]);

    // The value in b_chip should be ONE now and for the rest of the trace.
    for row in mp_verify_complete..trace.length() - NUM_RAND_ROWS {
        assert_eq!(ONE, b_chip[row]);
    }
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle root update
/// requested by the `MrUpdate` user operation.
#[test]
#[allow(clippy::needless_range_loop)]
fn b_chip_mrupdate() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let mut tree = MerkleTree::new(&leaves).unwrap();

    let old_root = tree.root();
    let old_leaf_value = leaves[index];

    let new_leaf_value = leaves[0];

    let stack_inputs = [
        new_leaf_value[0].as_int(),
        new_leaf_value[1].as_int(),
        new_leaf_value[2].as_int(),
        new_leaf_value[3].as_int(),
        old_root[0].as_int(),
        old_root[1].as_int(),
        old_root[2].as_int(),
        old_root[3].as_int(),
        index as u64,
        tree.depth() as u64,
        old_leaf_value[0].as_int(),
        old_leaf_value[1].as_int(),
        old_leaf_value[2].as_int(),
        old_leaf_value[3].as_int(),
    ];
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
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
    let mut expected = span_init.inv();
    // provide the initialization of the span hash
    expected *= build_expected_from_trace(&trace, &alphas, 0.into());
    assert_eq!(expected, b_chip[1]);

    // at cycle 1 a merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(
        &[path[0][0], path[0][1], path[0][2], path[0][3]].into(),
        &[leaves[index][0], leaves[index][1], leaves[index][2], leaves[index][3]].into(),
    );
    let mp_init_old = build_expected(
        &alphas,
        MR_UPDATE_OLD_LABEL,
        mp_state,
        [ZERO; STATE_WIDTH],
        Felt::new(9),
        Felt::new(index as u64),
    );
    // request the initialization of the (first) Merkle path verification
    expected *= mp_init_old.inv();

    let mp_old_verify_complete = HASH_CYCLE_LEN + (tree.depth() as usize) * HASH_CYCLE_LEN;
    let mp_result_old = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        // for the return hash, only the state digest matters, and it should match the root
        [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            tree.root()[0],
            tree.root()[1],
            tree.root()[2],
            tree.root()[3],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        [ZERO; STATE_WIDTH],
        Felt::new(mp_old_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );

    // request the result of the first Merkle path verification
    expected *= mp_result_old.inv();

    let new_leaf_value = leaves[0];
    tree.update_leaf(index as u64, new_leaf_value).unwrap();
    let new_root = tree.root();

    // a second merkle path verification is executed and the initialization and result of the
    // hash are both requested by the stack.
    let path = tree
        .get_path(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("failed to get Merkle tree path");
    let mp_state = init_state_from_words(
        &[path[0][0], path[0][1], path[0][2], path[0][3]].into(),
        &[new_leaf_value[0], new_leaf_value[1], new_leaf_value[2], new_leaf_value[3]].into(),
    );

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
    expected *= mp_init_new.inv();

    let mp_result_new = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        // for the return hash, only the state digest matters, and it should match the root
        [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            new_root[0],
            new_root[1],
            new_root[2],
            new_root[3],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        [ZERO; STATE_WIDTH],
        Felt::new(mp_new_verify_complete as u64),
        Felt::new(index as u64 >> tree.depth()),
    );

    // request the result of the second Merkle path verification
    expected *= mp_result_new.inv();
    assert_eq!(expected, b_chip[2]);

    // at cycle 2 the result of the span hash is requested by the decoder
    apply_permutation(&mut span_state);
    let span_result = build_expected(
        &alphas,
        RETURN_HASH_LABEL,
        span_state,
        [ZERO; STATE_WIDTH],
        Felt::new(8),
        ZERO,
    );
    expected *= span_result.inv();
    assert_eq!(expected, b_chip[3]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 3..8 {
        assert_eq!(expected, b_chip[row]);
    }

    // at cycle 7 the result of the span hash is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 7.into());
    assert_eq!(expected, b_chip[8]);

    // at cycle 8 the initialization of the first merkle path is provided by the hasher
    expected *= build_expected_from_trace(&trace, &alphas, 8.into());
    assert_eq!(expected, b_chip[9]);

    // Nothing changes when there is no communication with the hash chiplet.
    for row in 10..(mp_old_verify_complete) {
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
    for row in (mp_new_verify_complete)..trace.length() - NUM_RAND_ROWS {
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
    let header =
        alphas[0] + alphas[1] * Felt::from(transition_label) + alphas[2] * addr + alphas[3] * index;
    let mut value = header;

    if (first_cycle_row && label == LINEAR_HASH_LABEL) || label == RETURN_STATE_LABEL {
        // include the entire state (words a, b, c)
        value += build_value(&alphas[4..16], &state);
    } else if label == LINEAR_HASH_LABEL {
        // include the next rate elements
        value += build_value(&alphas[8..16], &next_state[CAPACITY_LEN..]);
    } else if label == RETURN_HASH_LABEL {
        // include the digest (word b)
        value += build_value(&alphas[8..12], &state[DIGEST_RANGE]);
    } else {
        assert!(
            label == MP_VERIFY_LABEL
                || label == MR_UPDATE_NEW_LABEL
                || label == MR_UPDATE_OLD_LABEL
        );
        let bit = index.as_int() & 1;
        let left_word = build_value(&alphas[8..12], &state[DIGEST_RANGE]);
        let right_word = build_value(&alphas[8..12], &state[DIGEST_RANGE.end..]);

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

    let mut state = [ZERO; STATE_WIDTH];
    let mut next_state = [ZERO; STATE_WIDTH];
    for (i, col_idx) in HASHER_STATE_COL_RANGE.enumerate() {
        state[i] = trace.main_trace.get_column(col_idx)[row];
        if cycle_row == 7 && label == LINEAR_HASH_LABEL {
            // fill the next state with the elements being absorbed.
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
/// specified row.
fn fill_state_from_decoder(trace: &ExecutionTrace, state: &mut HasherState, row: RowIndex) {
    for (i, col_idx) in DECODER_HASHER_STATE_RANGE.enumerate() {
        state[CAPACITY_LEN + i] = trace.main_trace.get_column(col_idx)[row];
    }
}

/// Extract the control block domain from the execution trace.  This is achieved
/// by calculating the op code as [bit_0 * 2**0 + bit_1 * 2**1 + ... + bit_6 * 2**6]
fn extract_control_block_domain_from_trace(trace: &ExecutionTrace, row: RowIndex) -> Felt {
    // calculate the op code
    let opcode_value = DECODER_OP_BITS_RANGE.rev().fold(0u8, |result, bit_index| {
        let op_bit = trace.main_trace.get_column(bit_index)[row].as_int() as u8;
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
        Felt::from(opcode_value)
    } else {
        ZERO
    }
}

/// Returns the row of the hash cycle which corresponds to the provided Hasher address.
fn addr_to_cycle_row(addr: Felt) -> usize {
    let cycle = (addr.as_int() - 1) as usize;
    let cycle_row = cycle % HASH_CYCLE_LEN;
    debug_assert!(
        cycle_row == 0 || cycle_row == HASH_CYCLE_LEN - 1,
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
