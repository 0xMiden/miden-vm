use alloc::vec::Vec;

use miden_air::trace::{
    Challenges, RowIndex, bus_message, bus_types,
    chiplets::hasher::{
        CONTROLLER_ROWS_PER_PERM_FELT, DIGEST_RANGE, HasherState, LINEAR_HASH_LABEL,
        MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL, RATE_LEN, RETURN_HASH_LABEL,
        RETURN_STATE_LABEL,
    },
    log_precompile::{
        HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
        STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
    },
};
use miden_core::{
    Word,
    crypto::merkle::{MerkleStore, MerkleTree},
    field::Field,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SplitNodeBuilder},
    operations::opcodes,
    program::Program,
};
use miden_utils_testing::stack;

use super::{
    AUX_TRACE_RAND_CHALLENGES, AdviceInputs, CHIPLETS_BUS_AUX_TRACE_OFFSET, ExecutionTrace, Felt,
    ONE, Operation, ZERO, build_span_with_respan_ops, build_trace_from_ops_with_inputs,
    build_trace_from_program, rand_array,
};
use crate::StackInputs;

// TESTS
// ================================================================================================

/// Tests the generation of the `b_chip` bus column when the hasher only performs a single `SPAN`
/// with one operation batch.
///
/// Verifies step-by-step that each decoder request (SPAN, END) and each hasher response
/// (sponge start, digest return) correctly update the bus running product.
#[test]
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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(trace.length(), b_chip.len());
    assert_eq!(ONE, b_chip[0]);

    // Verify the bus running product step-by-step at every row.
    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher only performs a `SPAN` but it
/// includes multiple batches (RESPAN).
///
/// Verifies step-by-step that SPAN, RESPAN, and END requests are each matched by hasher responses.
#[test]
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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a merge of two code
/// blocks requested by the decoder (SPLIT). This also requires inner SPAN blocks.
///
/// Verifies step-by-step that SPLIT, SPAN, and END requests are each matched by hasher responses.
#[test]
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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a permutation
/// requested by the `HPerm` user operation.
#[test]
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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a log_precompile
/// operation requested by the stack. The operation absorbs TAG and COMM into a Poseidon2
/// sponge with capacity CAP_PREV, producing (CAP_NEXT, R0, R1).
#[test]
pub fn b_chip_log_precompile() {
    let program = {
        let mut mast_forest = MastForest::new();

        let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::LogPrecompile], Vec::new())
            .add_to_forest(&mut mast_forest)
            .unwrap();
        mast_forest.make_root(basic_block_id);

        Program::new(mast_forest.into(), basic_block_id)
    };
    // stack! takes elements in runtime order (first = top) and handles reversal
    let stack_inputs = stack![5, 6, 7, 8, 1, 2, 3, 4];
    let trace = build_trace_from_program(&program, &stack_inputs);

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle path
/// verification requested by the `MpVerify` user operation.
#[test]
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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

/// Tests the generation of the `b_chip` bus column when the hasher performs a Merkle root update
/// requested by the `MrUpdate` user operation.
#[test]
fn b_chip_mrupdate() {
    let index = 5usize;
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

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

    let rand_challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&rand_challenges).unwrap();
    let b_chip = aux_columns.get_column(CHIPLETS_BUS_AUX_TRACE_OFFSET);
    let challenges = Challenges::new(rand_challenges[0], rand_challenges[1]);

    assert_eq!(ONE, b_chip[0]);

    verify_b_chip_step_by_step(&trace, &challenges, b_chip);

    assert_bus_balanced(b_chip);
}

// TEST HELPERS -- MESSAGE BUILDERS
// ================================================================================================
//
// These helpers build expected bus message values for each of the 5 message types.
// The label encoding and selector mapping are encapsulated here so tests can
// speak in terms of operations, not selector bits.
//
// Label convention: input messages use label + 16, output messages use label + 32.

const LABEL_OFFSET_INPUT: u8 = 16;
const LABEL_OFFSET_OUTPUT: u8 = 32;

/// Sponge start message: full 12-element state (matches SPAN / control block request).
fn sponge_start_msg(challenges: &Challenges<Felt>, addr: Felt, state: &HasherState) -> Felt {
    let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
        + challenges.beta_powers[0] * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_INPUT)
        + challenges.beta_powers[1] * addr;
    header + build_value(&challenges.beta_powers[3..15], state)
}

/// Sponge continuation message: rate-only 8 elements (matches RESPAN request).
/// Both the RESPAN request and the hasher continuation response use LABEL_OFFSET_OUTPUT (= 32).
fn sponge_continuation_msg(challenges: &Challenges<Felt>, addr: Felt, rate: &[Felt]) -> Felt {
    assert_eq!(rate.len(), RATE_LEN);
    let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
        + challenges.beta_powers[0] * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_OUTPUT)
        + challenges.beta_powers[1] * addr;
    header + build_value(&challenges.beta_powers[3..11], rate)
}

/// Digest return message: 4-element digest (matches END / MPVERIFY output / MRUPDATE output).
fn digest_return_msg(challenges: &Challenges<Felt>, addr: Felt, digest: &[Felt]) -> Felt {
    assert_eq!(digest.len(), 4);
    let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
        + challenges.beta_powers[0] * Felt::from_u8(RETURN_HASH_LABEL + LABEL_OFFSET_OUTPUT)
        + challenges.beta_powers[1] * addr;
    header + build_value(&challenges.beta_powers[3..7], digest)
}

/// Full state return message: 12-element state (matches HPERM output).
fn full_state_return_msg(challenges: &Challenges<Felt>, addr: Felt, state: &HasherState) -> Felt {
    let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
        + challenges.beta_powers[0] * Felt::from_u8(RETURN_STATE_LABEL + LABEL_OFFSET_OUTPUT)
        + challenges.beta_powers[1] * addr;
    header + build_value(&challenges.beta_powers[3..15], state)
}

/// Tree input message: leaf word selected by direction bit (matches MPVERIFY/MRUPDATE input).
fn tree_input_msg(
    challenges: &Challenges<Felt>,
    label: u8,
    addr: Felt,
    index: Felt,
    leaf_word: &[Felt; 4],
) -> Felt {
    let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
        + challenges.beta_powers[0] * Felt::from_u8(label + LABEL_OFFSET_INPUT)
        + challenges.beta_powers[1] * addr
        + challenges.beta_powers[2] * index;
    header + build_value(&challenges.beta_powers[3..7], leaf_word)
}

/// Reads the hasher chiplet response at the given trace row.
///
/// This mirrors the response builder logic: reads the trace and computes the bus message.
/// Returns ONE (identity) if the row doesn't produce a response.
fn hasher_response_at(
    trace: &ExecutionTrace,
    challenges: &Challenges<Felt>,
    row: RowIndex,
) -> Felt {
    let s_perm = trace.main_trace.chiplet_s_perm(row);
    if s_perm == ONE {
        return ONE; // perm segment: no response
    }

    // Hasher internal selectors (chiplet columns 1, 2, 3 = hasher s0, s1, s2)
    let hasher_s0 = trace.main_trace.chiplet_selector_1(row);
    let hasher_s1 = trace.main_trace.chiplet_selector_2(row);
    let hasher_s2 = trace.main_trace.chiplet_selector_3(row);

    let addr = Felt::from(u32::from(row) + 1);
    let state = trace.main_trace.chiplet_hasher_state(row);
    let node_index = trace.main_trace.chiplet_node_index(row);

    // Input rows (hasher s0=1)
    if hasher_s0 == ONE {
        let is_start = trace.main_trace.chiplet_is_boundary(row);

        // Sponge mode (s1=0, s2=0)
        if hasher_s1 == ZERO && hasher_s2 == ZERO {
            if is_start == ONE {
                return sponge_start_msg(challenges, addr, &state);
            } else {
                return sponge_continuation_msg(challenges, addr, &state[..RATE_LEN]);
            }
        }

        // Tree mode (s1=1 or s2=1) -- only start rows produce responses
        if is_start == ONE {
            let label = if hasher_s1 == ZERO {
                MP_VERIFY_LABEL
            } else if hasher_s2 == ZERO {
                MR_UPDATE_OLD_LABEL
            } else {
                MR_UPDATE_NEW_LABEL
            };
            let bit = (node_index.as_canonical_u64() & 1) as usize;
            let leaf_word: [Felt; 4] = if bit == 0 {
                state[..4].try_into().unwrap()
            } else {
                state[4..8].try_into().unwrap()
            };
            return tree_input_msg(challenges, label, addr, node_index, &leaf_word);
        }

        return ONE; // tree continuation: no response
    }

    // Output rows (hasher s0=0, s1=0)
    if hasher_s0 == ZERO && hasher_s1 == ZERO {
        // HOUT (s2=0): always produces response
        if hasher_s2 == ZERO {
            return digest_return_msg(challenges, addr, &state[DIGEST_RANGE]);
        }

        // SOUT (s2=1): only with is_final=1
        let is_final = trace.main_trace.chiplet_is_boundary(row);
        if is_final == ONE {
            return full_state_return_msg(challenges, addr, &state);
        }
    }

    ONE // no response
}

// TEST HELPERS -- STATE BUILDERS
// ================================================================================================

/// Builds a value from coefficients and elements of matching lengths.
fn build_value(coeffs: &[Felt], elements: &[Felt]) -> Felt {
    let mut value = ZERO;
    for (&coeff, &element) in coeffs.iter().zip(elements.iter()) {
        value += coeff * element;
    }
    value
}

// STEP-BY-STEP BUS VERIFICATION
// ================================================================================================

/// Computes the decoder's request to the chiplets bus at the given row.
///
/// Only handles hasher-related opcodes (SPAN, END, RESPAN, SPLIT, JOIN, LOOP).
/// Returns ONE (identity) for all other opcodes.
fn decoder_request_at(
    trace: &ExecutionTrace,
    challenges: &Challenges<Felt>,
    row: RowIndex,
) -> Felt {
    let op_code = trace.main_trace.get_op_code(row).as_canonical_u64() as u8;

    match op_code {
        opcodes::SPAN => {
            // SPAN request: rate-only message (LINEAR_HASH_LABEL + 16) at addr(row+1).
            let addr_next = trace.main_trace.addr(row + 1);
            let state = trace.main_trace.decoder_hasher_state(row);
            let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                + challenges.beta_powers[bus_message::LABEL_IDX]
                    * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_INPUT)
                + challenges.beta_powers[bus_message::ADDR_IDX] * addr_next;
            let mut value = header;
            for (i, &elem) in state.iter().enumerate() {
                value += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
            }
            value
        },
        opcodes::RESPAN => {
            // RESPAN request: rate-only message (LINEAR_HASH_LABEL + 32) at addr(row+1).
            let addr_next = trace.main_trace.addr(row + 1);
            let state = trace.main_trace.decoder_hasher_state(row);
            let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                + challenges.beta_powers[bus_message::LABEL_IDX]
                    * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_OUTPUT)
                + challenges.beta_powers[bus_message::ADDR_IDX] * addr_next;
            let mut value = header;
            for (i, &elem) in state.iter().enumerate() {
                value += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
            }
            value
        },
        opcodes::END => {
            // END request: digest message (RETURN_HASH_LABEL + 32) at addr(row) + 1.
            let addr = trace.main_trace.addr(row) + ONE;
            let state = trace.main_trace.decoder_hasher_state(row);
            let digest = &state[..4];
            let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                + challenges.beta_powers[bus_message::LABEL_IDX]
                    * Felt::from_u8(RETURN_HASH_LABEL + LABEL_OFFSET_OUTPUT)
                + challenges.beta_powers[bus_message::ADDR_IDX] * addr;
            let mut value = header;
            for (i, &elem) in digest.iter().enumerate() {
                value += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
            }
            value
        },
        opcodes::SPLIT | opcodes::JOIN | opcodes::LOOP => {
            // Control block request: rate + capacity domain element for op_code.
            let addr_next = trace.main_trace.addr(row + 1);
            let state = trace.main_trace.decoder_hasher_state(row);
            let op_code_felt = trace.main_trace.get_op_code(row);
            let header = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                + challenges.beta_powers[bus_message::LABEL_IDX]
                    * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_INPUT)
                + challenges.beta_powers[bus_message::ADDR_IDX] * addr_next;
            let mut value = header;
            for (i, &elem) in state.iter().enumerate() {
                value += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
            }
            value += challenges.beta_powers[bus_message::CAPACITY_DOMAIN_IDX] * op_code_felt;
            value
        },
        opcodes::HPERM => {
            // HPERM sends two messages: input (full state from stack) and output (full state
            // from next row). Combined as a product.
            let helper_0 = trace.main_trace.helper_register(0, row);
            let state: [Felt; 12] =
                core::array::from_fn(|i| trace.main_trace.stack_element(i, row));
            let state_nxt: [Felt; 12] =
                core::array::from_fn(|i| trace.main_trace.stack_element(i, row + 1));

            let input_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_INPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * helper_0;
                for (i, &elem) in state.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let output_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(RETURN_STATE_LABEL + LABEL_OFFSET_OUTPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * (helper_0 + ONE);
                for (i, &elem) in state_nxt.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            input_value * output_value
        },
        opcodes::LOGPRECOMPILE => {
            // LOG_PRECOMPILE sends two messages: input [COMM, TAG, CAP_PREV] and
            // output [R0, R1, CAP_NEXT]. Combined as a product.
            let addr = trace.main_trace.helper_register(HELPER_ADDR_IDX, row);
            let cap_prev: [Felt; 4] = core::array::from_fn(|i| {
                trace.main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + i, row)
            });
            let comm = trace.main_trace.stack_word(STACK_COMM_RANGE.start, row);
            let tag = trace.main_trace.stack_word(STACK_TAG_RANGE.start, row);
            let input_state: Vec<Felt> = comm
                .as_elements()
                .iter()
                .chain(tag.as_elements().iter())
                .chain(cap_prev.iter())
                .copied()
                .collect();

            let r0 = trace.main_trace.stack_word(STACK_R0_RANGE.start, row + 1);
            let r1 = trace.main_trace.stack_word(STACK_R1_RANGE.start, row + 1);
            let cap_next = trace.main_trace.stack_word(STACK_CAP_NEXT_RANGE.start, row + 1);
            let output_state: Vec<Felt> = r0
                .as_elements()
                .iter()
                .chain(r1.as_elements().iter())
                .chain(cap_next.as_elements().iter())
                .copied()
                .collect();

            let input_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(LINEAR_HASH_LABEL + LABEL_OFFSET_INPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * addr;
                for (i, &elem) in input_state.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let output_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(RETURN_STATE_LABEL + LABEL_OFFSET_OUTPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * (addr + ONE);
                for (i, &elem) in output_state.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            input_value * output_value
        },
        opcodes::MPVERIFY => {
            // MPVERIFY sends two messages: input (leaf word + node_index) and output (root
            // digest). Combined as a product.
            let helper_0 = trace.main_trace.helper_register(0, row);
            let rows_per_perm = CONTROLLER_ROWS_PER_PERM_FELT;

            let node_value = trace.main_trace.stack_word(0, row);
            let node_depth = trace.main_trace.stack_element(4, row);
            let node_index = trace.main_trace.stack_element(5, row);
            let merkle_root = trace.main_trace.stack_word(6, row);

            let node_word: [Felt; 4] =
                node_value.as_elements().try_into().expect("word must be 4 field elements");
            let root_word: [Felt; 4] =
                merkle_root.as_elements().try_into().expect("word must be 4 field elements");

            let input_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(MP_VERIFY_LABEL + LABEL_OFFSET_INPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * helper_0
                    + challenges.beta_powers[bus_message::NODE_INDEX_IDX] * node_index;
                for (i, &elem) in node_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let output_addr = helper_0 + node_depth * rows_per_perm - ONE;
            let output_value = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(RETURN_HASH_LABEL + LABEL_OFFSET_OUTPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * output_addr;
                for (i, &elem) in root_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            input_value * output_value
        },
        opcodes::MRUPDATE => {
            // MRUPDATE sends four messages: old input, old output, new input, new output.
            // Combined as a product.
            let helper_0 = trace.main_trace.helper_register(0, row);
            let rows_per_perm = CONTROLLER_ROWS_PER_PERM_FELT;
            let two_legs_rows = rows_per_perm + rows_per_perm;

            let old_node_value = trace.main_trace.stack_word(0, row);
            let merkle_path_depth = trace.main_trace.stack_element(4, row);
            let node_index = trace.main_trace.stack_element(5, row);
            let old_root = trace.main_trace.stack_word(6, row);
            let new_node_value = trace.main_trace.stack_word(10, row);
            let new_root = trace.main_trace.stack_word(0, row + 1);

            let old_node_word: [Felt; 4] =
                old_node_value.as_elements().try_into().expect("word must be 4 field elements");
            let old_root_word: [Felt; 4] =
                old_root.as_elements().try_into().expect("word must be 4 field elements");
            let new_node_word: [Felt; 4] =
                new_node_value.as_elements().try_into().expect("word must be 4 field elements");
            let new_root_word: [Felt; 4] =
                new_root.as_elements().try_into().expect("word must be 4 field elements");

            let input_old = {
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(MR_UPDATE_OLD_LABEL + LABEL_OFFSET_INPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * helper_0
                    + challenges.beta_powers[bus_message::NODE_INDEX_IDX] * node_index;
                for (i, &elem) in old_node_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let output_old = {
                let output_addr = helper_0 + merkle_path_depth * rows_per_perm - ONE;
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(RETURN_HASH_LABEL + LABEL_OFFSET_OUTPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * output_addr;
                for (i, &elem) in old_root_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let input_new = {
                let new_input_addr = helper_0 + merkle_path_depth * rows_per_perm;
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(MR_UPDATE_NEW_LABEL + LABEL_OFFSET_INPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * new_input_addr
                    + challenges.beta_powers[bus_message::NODE_INDEX_IDX] * node_index;
                for (i, &elem) in new_node_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            let output_new = {
                let new_output_addr = helper_0 + merkle_path_depth * two_legs_rows - ONE;
                let mut acc = challenges.bus_prefix[bus_types::CHIPLETS_BUS]
                    + challenges.beta_powers[bus_message::LABEL_IDX]
                        * Felt::from_u8(RETURN_HASH_LABEL + LABEL_OFFSET_OUTPUT)
                    + challenges.beta_powers[bus_message::ADDR_IDX] * new_output_addr;
                for (i, &elem) in new_root_word.iter().enumerate() {
                    acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
                }
                acc
            };
            input_old * output_old * input_new * output_new
        },
        _ => ONE,
    }
}

/// Verifies b_chip step-by-step by recomputing the running product at every row.
///
/// At each row `r`:
///   request  = decoder_request_at(r)
///   response = hasher_response_at(r)
///   expected[r+1] = expected[r] * response / request
///
/// Asserts that the recomputed value matches `b_chip[r+1]` at every row.
fn verify_b_chip_step_by_step(
    trace: &ExecutionTrace,
    challenges: &Challenges<Felt>,
    b_chip: &[Felt],
) {
    let mut expected = ONE;
    let trace_len = b_chip.len();

    for row_idx in 0..trace_len - 1 {
        let row = RowIndex::from(row_idx);
        let request = decoder_request_at(trace, challenges, row);
        let response = hasher_response_at(trace, challenges, row);

        expected *= response * request.try_inverse().expect("request must be invertible");

        assert_eq!(
            expected,
            b_chip[row_idx + 1],
            "b_chip mismatch at row {} (after processing row {}): \
             expected={}, actual={}, request={}, response={}",
            row_idx + 1,
            row_idx,
            expected,
            b_chip[row_idx + 1],
            request,
            response,
        );
    }
}

// BUS BALANCE ASSERTION
// ================================================================================================

/// Asserts that the b_chip bus column eventually settles to ONE (balanced) and stays there.
fn assert_bus_balanced(b_chip: &[Felt]) {
    // The bus should reach ONE at some point after the initial requests/responses
    // and stay there for the rest of the trace.
    let last = *b_chip.last().expect("b_chip should not be empty");
    assert_eq!(last, ONE, "b_chip final value should be ONE (bus balanced), got {last}");
}

// MERKLE TREE HELPERS
// ================================================================================================

/// Initializes Merkle tree leaves with the specified values.
fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

/// Initializes a Merkle tree leaf with the specified value.
fn init_leaf(value: u64) -> Word {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
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
