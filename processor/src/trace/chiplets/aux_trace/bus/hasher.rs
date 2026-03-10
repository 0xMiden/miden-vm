use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::trace::{
    MainTrace, RowIndex, bus_message,
    chiplets::{
        hasher,
        hasher::{
            HASH_CYCLE_LEN, HASH_CYCLE_LEN_FELT, LAST_CYCLE_ROW, LAST_CYCLE_ROW_FELT,
            LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL, MR_UPDATE_OLD_LABEL,
            RETURN_HASH_LABEL, RETURN_STATE_LABEL,
        },
    },
    log_precompile::{
        HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
        STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
    },
};
use miden_core::{Felt, ONE, WORD_SIZE, ZERO, field::ExtensionField, operations::opcodes};

use super::get_op_label;
use crate::{
    Word,
    debug::{BusDebugger, BusMessage},
    trace::utils::Challenges,
};

// HASHER MESSAGE ENCODING LAYOUT
// ================================================================================================
//
// All hasher chiplet bus messages use a common encoding structure:
//
//   challenges.alpha                     = alpha (randomness base, accessed directly)
//   challenges.beta_powers[0]            = beta^0 (label: transition type)
//   challenges.beta_powers[1]            = beta^1 (addr: hasher chiplet address)
//   challenges.beta_powers[2]            = beta^2 (node_index: Merkle path position, 0 for
// non-Merkle ops)   challenges.beta_powers[3..10]        = beta^3..beta^10 (state[0..7]: RATE0 ||
// RATE1 in sponge order)   challenges.beta_powers[11..14]       = beta^11..beta^14 (capacity[0..3]:
// domain separation)
//
// Message encoding: alpha + beta^0*label + beta^1*addr + beta^2*node_index
//                   + beta^3*state[0] + ... + beta^10*state[7]
//                   + beta^11*capacity[0] + ... + beta^14*capacity[3]
//
// Different message types use different subsets of this layout:
// - Full state messages (HPERM, LOG_PRECOMPILE): all 12 state elements (rate + capacity)
// - Rate-only messages (SPAN, RESPAN): skip node_index and capacity, use label + addr + state[0..7]
// - Digest messages (END block): label + addr + RATE0 digest (state[0..3])
// - Control block messages: rate + one capacity element (beta_powers[12]) for op_code
// - Tree operation messages (MPVERIFY, MRUPDATE): include node_index

// HASHER MESSAGE CONSTANTS AND HELPERS
// ================================================================================================

const LABEL_OFFSET_START: Felt = Felt::new(16);
const LABEL_OFFSET_END: Felt = Felt::new(32);
const LINEAR_HASH_LABEL_START: Felt = Felt::new((LINEAR_HASH_LABEL + 16) as u64);
const LINEAR_HASH_LABEL_RESPAN: Felt = Felt::new((LINEAR_HASH_LABEL + 32) as u64);
const RETURN_HASH_LABEL_END: Felt = Felt::new((RETURN_HASH_LABEL + 32) as u64);
const RETURN_STATE_LABEL_END: Felt = Felt::new((RETURN_STATE_LABEL + 32) as u64);
const MP_VERIFY_LABEL_START: Felt = Felt::new((MP_VERIFY_LABEL + 16) as u64);
const MR_UPDATE_OLD_LABEL_START: Felt = Felt::new((MR_UPDATE_OLD_LABEL + 16) as u64);
const MR_UPDATE_NEW_LABEL_START: Felt = Felt::new((MR_UPDATE_NEW_LABEL + 16) as u64);

/// Encodes hasher message as **alpha + <beta, [label, addr, node_index, state...]>**
///
/// Used for tree operations (MPVERIFY, MRUPDATE) and generic hasher messages with node_index.
#[inline(always)]
fn hasher_message_value<E, const N: usize>(
    challenges: &Challenges<E>,
    transition_label: Felt,
    addr_next: Felt,
    node_index: Felt,
    state: [Felt; N],
) -> E
where
    E: ExtensionField<Felt>,
{
    let mut acc = challenges.alpha
        + challenges.beta_powers[bus_message::LABEL_IDX] * transition_label
        + challenges.beta_powers[bus_message::ADDR_IDX] * addr_next
        + challenges.beta_powers[bus_message::NODE_INDEX_IDX] * node_index;
    for (i, &elem) in state.iter().enumerate() {
        acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
    }
    acc
}

/// Encodes hasher message as **alpha + <beta, [label, addr, _, state[0..7]]>** (skips node_index).
#[inline(always)]
fn header_rate_value<E>(
    challenges: &Challenges<E>,
    transition_label: Felt,
    addr: Felt,
    state: [Felt; hasher::RATE_LEN],
) -> E
where
    E: ExtensionField<Felt>,
{
    let mut acc = challenges.alpha
        + challenges.beta_powers[bus_message::LABEL_IDX] * transition_label
        + challenges.beta_powers[bus_message::ADDR_IDX] * addr;
    for (i, &elem) in state.iter().enumerate() {
        acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
    }
    acc
}

/// Encodes hasher message as **alpha + <beta, [label, addr, _, digest]>** (skips node_index, digest
/// is RATE0 only).
#[inline(always)]
fn header_digest_value<E>(
    challenges: &Challenges<E>,
    transition_label: Felt,
    addr: Felt,
    digest: [Felt; WORD_SIZE],
) -> E
where
    E: ExtensionField<Felt>,
{
    let mut acc = challenges.alpha
        + challenges.beta_powers[bus_message::LABEL_IDX] * transition_label
        + challenges.beta_powers[bus_message::ADDR_IDX] * addr;
    for (i, &elem) in digest.iter().enumerate() {
        acc += challenges.beta_powers[bus_message::STATE_START_IDX + i] * elem;
    }
    acc
}

// REQUESTS
// ==============================================================================================

/// Builds requests made to the hasher chiplet at the start of a control block.
pub(super) fn build_control_block_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    decoder_hasher_state: [Felt; 8],
    op_code_felt: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let message = ControlBlockRequestMessage {
        transition_label: LINEAR_HASH_LABEL_START,
        addr_next: main_trace.addr(row + 1),
        op_code: op_code_felt,
        decoder_hasher_state,
    };

    let value = message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), challenges);

    value
}

/// Builds requests made to the hasher chiplet at the start of a span block.
pub(super) fn build_span_block_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let span_block_message = SpanBlockMessage {
        transition_label: LINEAR_HASH_LABEL_START,
        addr_next: main_trace.addr(row + 1),
        state: main_trace.decoder_hasher_state(row),
    };

    let value = span_block_message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(span_block_message), challenges);

    value
}

/// Builds requests made to the hasher chiplet at the start of a respan block.
pub(super) fn build_respan_block_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let respan_block_message = RespanBlockMessage {
        transition_label: LINEAR_HASH_LABEL_RESPAN,
        addr_next: main_trace.addr(row + 1),
        state: main_trace.decoder_hasher_state(row),
    };

    let value = respan_block_message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(respan_block_message), challenges);

    value
}

/// Builds requests made to the hasher chiplet at the end of a block.
pub(super) fn build_end_block_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let end_block_message = EndBlockMessage {
        addr: main_trace.addr(row) + LAST_CYCLE_ROW_FELT,
        transition_label: RETURN_HASH_LABEL_END,
        digest: main_trace.decoder_hasher_state(row)[..4]
            .try_into()
            .expect("decoder_hasher_state[0..4] must be 4 field elements"),
    };

    let value = end_block_message.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(end_block_message), challenges);

    value
}

/// Builds `HPERM` requests made to the hash chiplet.
pub(super) fn build_hperm_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let helper_0 = main_trace.helper_register(0, row);
    let s0 = main_trace.stack_element(0, row);
    let s1 = main_trace.stack_element(1, row);
    let s2 = main_trace.stack_element(2, row);
    let s3 = main_trace.stack_element(3, row);
    let s4 = main_trace.stack_element(4, row);
    let s5 = main_trace.stack_element(5, row);
    let s6 = main_trace.stack_element(6, row);
    let s7 = main_trace.stack_element(7, row);
    let s8 = main_trace.stack_element(8, row);
    let s9 = main_trace.stack_element(9, row);
    let s10 = main_trace.stack_element(10, row);
    let s11 = main_trace.stack_element(11, row);
    let s0_nxt = main_trace.stack_element(0, row + 1);
    let s1_nxt = main_trace.stack_element(1, row + 1);
    let s2_nxt = main_trace.stack_element(2, row + 1);
    let s3_nxt = main_trace.stack_element(3, row + 1);
    let s4_nxt = main_trace.stack_element(4, row + 1);
    let s5_nxt = main_trace.stack_element(5, row + 1);
    let s6_nxt = main_trace.stack_element(6, row + 1);
    let s7_nxt = main_trace.stack_element(7, row + 1);
    let s8_nxt = main_trace.stack_element(8, row + 1);
    let s9_nxt = main_trace.stack_element(9, row + 1);
    let s10_nxt = main_trace.stack_element(10, row + 1);
    let s11_nxt = main_trace.stack_element(11, row + 1);

    let input_req = HasherMessage {
        transition_label: LINEAR_HASH_LABEL_START,
        addr_next: helper_0,
        node_index: ZERO,
        // Internal Poseidon2 state for HPERM is taken directly from the top 12
        // stack elements in order: [RATE0, RATE1, CAPACITY] = [s0..s11].
        hasher_state: [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11],
        source: "hperm input",
    };
    let output_req = HasherMessage {
        transition_label: RETURN_STATE_LABEL_END,
        addr_next: helper_0 + LAST_CYCLE_ROW_FELT,
        node_index: ZERO,
        hasher_state: [
            s0_nxt, s1_nxt, s2_nxt, s3_nxt, s4_nxt, s5_nxt, s6_nxt, s7_nxt, s8_nxt, s9_nxt,
            s10_nxt, s11_nxt,
        ],
        source: "hperm output",
    };

    let combined_value = input_req.value(challenges) * output_req.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input_req), challenges);
        _debugger.add_request(alloc::boxed::Box::new(output_req), challenges);
    }

    combined_value
}

/// Builds `LOG_PRECOMPILE` requests made to the hash chiplet.
///
/// The operation absorbs `[TAG, COMM]` into the transcript via a Poseidon2 permutation with
/// capacity `CAP_PREV`, producing output `[R0, R1, CAP_NEXT]`.
///
/// Stack layout (current row), structural (LSB-first) per word:
/// - `s0..s3`: `COMM[0..3]`
/// - `s4..s7`: `TAG[0..3]`
///
/// Helper registers (current row):
/// - `h0`: hasher address
/// - `h1..h4`: `CAP_PREV[0..3]`
///
/// Stack layout (next row):
/// - `s0..s3`: `R0[0..3]`
/// - `s4..s7`: `R1[0..3]`
/// - `s8..s11`: `CAP_NEXT[0..3]`
pub(super) fn build_log_precompile_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // Read helper registers
    let addr = main_trace.helper_register(HELPER_ADDR_IDX, row);

    // Input state [COMM, TAG, CAP_PREV] in sponge order [RATE0, RATE1, CAP]
    // Helper registers store capacity in sequential order [e0, e1, e2, e3]
    let cap_prev = Word::from([
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 1, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 2, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 3, row),
    ]);

    // Stack stores words for log_precompile in structural (LSB-first) layout,
    // so we read them directly as [w0, w1, w2, w3].
    let comm = main_trace.stack_word(STACK_COMM_RANGE.start, row);
    let tag = main_trace.stack_word(STACK_TAG_RANGE.start, row);
    // Internal Poseidon2 state is [RATE0, RATE1, CAPACITY] = [COMM, TAG, CAP_PREV]
    let state_input = [comm, tag, cap_prev];

    // Output state [R0, R1, CAP_NEXT] in sponge order
    let r0 = main_trace.stack_word(STACK_R0_RANGE.start, row + 1);
    let r1 = main_trace.stack_word(STACK_R1_RANGE.start, row + 1);
    let cap_next = main_trace.stack_word(STACK_CAP_NEXT_RANGE.start, row + 1);
    let state_output = [r0, r1, cap_next];

    let input_req = HasherMessage {
        transition_label: LINEAR_HASH_LABEL_START,
        addr_next: addr,
        node_index: ZERO,
        hasher_state: Word::words_as_elements(&state_input)
            .try_into()
            .expect("log_precompile input state must be 12 field elements (3 words)"),
        source: "log_precompile input",
    };

    let output_req = HasherMessage {
        transition_label: RETURN_STATE_LABEL_END,
        addr_next: addr + LAST_CYCLE_ROW_FELT,
        node_index: ZERO,
        hasher_state: Word::words_as_elements(&state_output)
            .try_into()
            .expect("log_precompile output state must be 12 field elements (3 words)"),
        source: "log_precompile output",
    };

    let combined_value = input_req.value(challenges) * output_req.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input_req), challenges);
        _debugger.add_request(alloc::boxed::Box::new(output_req), challenges);
    }

    combined_value
}

/// Builds `MPVERIFY` requests made to the hash chiplet.
pub(super) fn build_mpverify_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // helper register holds (clk + 1)
    let helper_0 = main_trace.helper_register(0, row);
    let hash_cycle_len = HASH_CYCLE_LEN_FELT;

    let node_value = main_trace.stack_word(0, row);
    let node_depth = main_trace.stack_element(4, row);
    let node_index = main_trace.stack_element(5, row);
    let merkle_tree_root = main_trace.stack_word(6, row);

    let node_word: [Felt; WORD_SIZE] =
        node_value.as_elements().try_into().expect("word must be 4 field elements");
    let root_word: [Felt; WORD_SIZE] = merkle_tree_root
        .as_elements()
        .try_into()
        .expect("word must be 4 field elements");

    let input_value =
        hasher_message_value(challenges, MP_VERIFY_LABEL_START, helper_0, node_index, node_word);
    let output_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + node_depth * hash_cycle_len - ONE,
        ZERO,
        root_word,
    );

    let combined_value = input_value * output_value;

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let mut node_state = [ZERO; hasher::STATE_WIDTH];
        node_state[..WORD_SIZE].copy_from_slice(&node_word);

        let input = HasherMessage {
            transition_label: MP_VERIFY_LABEL_START,
            addr_next: helper_0,
            node_index,
            hasher_state: node_state,
            source: "mpverify input",
        };

        let mut root_state = [ZERO; hasher::STATE_WIDTH];
        root_state[..WORD_SIZE].copy_from_slice(&root_word);

        let output = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + node_depth * hash_cycle_len - ONE,
            node_index: ZERO,
            hasher_state: root_state,
            source: "mpverify output",
        };

        _debugger.add_request(alloc::boxed::Box::new(input), challenges);
        _debugger.add_request(alloc::boxed::Box::new(output), challenges);
    }

    combined_value
}

/// Builds `MRUPDATE` requests made to the hash chiplet.
pub(super) fn build_mrupdate_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // helper register holds (clk + 1)
    let helper_0 = main_trace.helper_register(0, row);
    let hash_cycle_len = HASH_CYCLE_LEN_FELT;
    let two_hash_cycles_len = hash_cycle_len + hash_cycle_len;

    let old_node_value = main_trace.stack_word(0, row);
    let merkle_path_depth = main_trace.stack_element(4, row);
    let node_index = main_trace.stack_element(5, row);
    let old_root = main_trace.stack_word(6, row);
    let new_node_value = main_trace.stack_word(10, row);
    let new_root = main_trace.stack_word(0, row + 1);

    let old_node_word: [Felt; WORD_SIZE] =
        old_node_value.as_elements().try_into().expect("word must be 4 field elements");
    let old_root_word: [Felt; WORD_SIZE] =
        old_root.as_elements().try_into().expect("word must be 4 field elements");
    let new_node_word: [Felt; WORD_SIZE] =
        new_node_value.as_elements().try_into().expect("word must be 4 field elements");
    let new_root_word: [Felt; WORD_SIZE] =
        new_root.as_elements().try_into().expect("word must be 4 field elements");

    let input_old_value = hasher_message_value(
        challenges,
        MR_UPDATE_OLD_LABEL_START,
        helper_0,
        node_index,
        old_node_word,
    );
    let output_old_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + merkle_path_depth * hash_cycle_len - ONE,
        ZERO,
        old_root_word,
    );
    let input_new_value = hasher_message_value(
        challenges,
        MR_UPDATE_NEW_LABEL_START,
        helper_0 + merkle_path_depth * hash_cycle_len,
        node_index,
        new_node_word,
    );
    let output_new_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + merkle_path_depth * two_hash_cycles_len - ONE,
        ZERO,
        new_root_word,
    );

    let combined_value = input_old_value * output_old_value * input_new_value * output_new_value;

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let mut old_node_state = [ZERO; hasher::STATE_WIDTH];
        old_node_state[..WORD_SIZE].copy_from_slice(&old_node_word);
        let mut old_root_state = [ZERO; hasher::STATE_WIDTH];
        old_root_state[..WORD_SIZE].copy_from_slice(&old_root_word);
        let mut new_node_state = [ZERO; hasher::STATE_WIDTH];
        new_node_state[..WORD_SIZE].copy_from_slice(&new_node_word);
        let mut new_root_state = [ZERO; hasher::STATE_WIDTH];
        new_root_state[..WORD_SIZE].copy_from_slice(&new_root_word);

        let input_old = HasherMessage {
            transition_label: MR_UPDATE_OLD_LABEL_START,
            addr_next: helper_0,
            node_index,
            hasher_state: old_node_state,
            source: "mrupdate input_old",
        };

        let output_old = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + merkle_path_depth * hash_cycle_len - ONE,
            node_index: ZERO,
            hasher_state: old_root_state,
            source: "mrupdate output_old",
        };

        let input_new = HasherMessage {
            transition_label: MR_UPDATE_NEW_LABEL_START,
            addr_next: helper_0 + merkle_path_depth * hash_cycle_len,
            node_index,
            hasher_state: new_node_state,
            source: "mrupdate input_new",
        };

        let output_new = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + merkle_path_depth * two_hash_cycles_len - ONE,
            node_index: ZERO,
            hasher_state: new_root_state,
            source: "mrupdate output_new",
        };

        _debugger.add_request(alloc::boxed::Box::new(input_old), challenges);
        _debugger.add_request(alloc::boxed::Box::new(output_old), challenges);
        _debugger.add_request(alloc::boxed::Box::new(input_new), challenges);
        _debugger.add_request(alloc::boxed::Box::new(output_new), challenges);
    }

    combined_value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the hasher chiplet at `row`.
pub(super) fn build_hasher_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let mut multiplicand = E::ONE;
    let selector0 = main_trace.chiplet_selector_0(row);
    let selector1 = main_trace.chiplet_selector_1(row);
    let selector2 = main_trace.chiplet_selector_2(row);
    let selector3 = main_trace.chiplet_selector_3(row);
    let op_label = get_op_label(selector0, selector1, selector2, selector3);
    let addr_next = Felt::from(row + 1);

    // f_bp, f_mp, f_mv or f_mu == 1
    if row.as_usize().is_multiple_of(HASH_CYCLE_LEN) {
        // Trace is already in sponge order [RATE0, RATE1, CAP]
        let state = main_trace.chiplet_hasher_state(row);
        let node_index = main_trace.chiplet_node_index(row);
        let transition_label = op_label + LABEL_OFFSET_START;

        // f_bp == 1
        // v_all = v_h + v_a + v_b + v_c
        if selector1 == ONE && selector2 == ZERO && selector3 == ZERO {
            let hasher_message = HasherMessage {
                transition_label,
                addr_next,
                node_index,
                hasher_state: state,
                source: "hasher",
            };
            multiplicand = hasher_message.value(challenges);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), challenges);
        }

        // f_mp or f_mv or f_mu == 1
        // v_leaf = v_h + (1 - b) * v_b + b * v_d
        // In sponge order: RATE0 is at 0..4, RATE1 is at 4..8
        if selector1 == ONE && !(selector2 == ZERO && selector3 == ZERO) {
            let bit = (node_index.as_canonical_u64() & 1) as u8;
            let rate_word: [Felt; WORD_SIZE] = if bit == 0 {
                state[..WORD_SIZE].try_into().expect("RATE0 word must be 4 field elements")
            } else {
                state[WORD_SIZE..hasher::RATE_LEN]
                    .try_into()
                    .expect("RATE1 word must be 4 field elements")
            };

            multiplicand = hasher_message_value(
                challenges,
                transition_label,
                addr_next,
                node_index,
                rate_word,
            );

            #[cfg(any(test, feature = "bus-debugger"))]
            {
                let hasher_state = if bit == 0 {
                    [
                        state[0], state[1], state[2], state[3], ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                        ZERO, ZERO,
                    ]
                } else {
                    [
                        state[4], state[5], state[6], state[7], ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                        ZERO, ZERO,
                    ]
                };
                let hasher_message = HasherMessage {
                    transition_label,
                    addr_next,
                    node_index,
                    hasher_state,
                    source: "hasher",
                };
                _debugger.add_response(alloc::boxed::Box::new(hasher_message), challenges);
            }
        }
    }

    // f_hout, f_sout, f_abp == 1
    if row.as_usize() % HASH_CYCLE_LEN == LAST_CYCLE_ROW {
        // Trace is already in sponge order [RATE0, RATE1, CAP]
        let state = main_trace.chiplet_hasher_state(row);
        let node_index = main_trace.chiplet_node_index(row);
        let transition_label = op_label + LABEL_OFFSET_END;

        // f_hout == 1
        // v_res = v_h + v_b;
        // Digest is at sponge positions 0..4 (RATE0)
        if selector1 == ZERO && selector2 == ZERO && selector3 == ZERO {
            let rate_word: [Felt; WORD_SIZE] =
                state[..WORD_SIZE].try_into().expect("RATE0 word must be 4 field elements");
            multiplicand = hasher_message_value(
                challenges,
                transition_label,
                addr_next,
                node_index,
                rate_word,
            );

            #[cfg(any(test, feature = "bus-debugger"))]
            {
                let hasher_message = HasherMessage {
                    transition_label,
                    addr_next,
                    node_index,
                    hasher_state: [
                        state[0], state[1], state[2], state[3], ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
                        ZERO, ZERO,
                    ],
                    source: "hasher",
                };
                _debugger.add_response(alloc::boxed::Box::new(hasher_message), challenges);
            }
        }

        // f_sout == 1
        // v_all = v_h + v_a + v_b + v_c
        if selector1 == ZERO && selector2 == ZERO && selector3 == ONE {
            let hasher_message = HasherMessage {
                transition_label,
                addr_next,
                node_index,
                hasher_state: state,
                source: "hasher",
            };

            multiplicand = hasher_message.value(challenges);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), challenges);
        }

        // f_abp == 1
        // v_abp = v_h + v_b' + v_c' - v_b - v_c
        if selector1 == ONE && selector2 == ZERO && selector3 == ZERO {
            // Build the value from the hasher state just after absorption of new elements.
            // Trace is in sponge order: RATE0 at indices 0..4, RATE1 at indices 4..8.
            // Rate is mapped to lanes 0..7 with capacity lanes zeroed.
            let state_nxt = main_trace.chiplet_hasher_state(row + 1);
            let rate: [Felt; hasher::RATE_LEN] = state_nxt[..hasher::RATE_LEN]
                .try_into()
                .expect("rate portion must be 8 field elements");

            multiplicand =
                hasher_message_value(challenges, transition_label, addr_next, node_index, rate);

            #[cfg(any(test, feature = "bus-debugger"))]
            {
                let hasher_message = HasherMessage {
                    transition_label,
                    addr_next,
                    node_index,
                    hasher_state: [
                        state_nxt[0],
                        state_nxt[1],
                        state_nxt[2],
                        state_nxt[3],
                        state_nxt[4],
                        state_nxt[5],
                        state_nxt[6],
                        state_nxt[7],
                        ZERO,
                        ZERO,
                        ZERO,
                        ZERO,
                    ],
                    source: "hasher",
                };
                _debugger.add_response(alloc::boxed::Box::new(hasher_message), challenges);
            }
        }
    }
    multiplicand
}

// CONTROL BLOCK REQUEST MESSAGE
// ===============================================================================================
pub struct ControlBlockRequestMessage {
    pub transition_label: Felt,
    pub addr_next: Felt,
    pub op_code: Felt,
    pub decoder_hasher_state: [Felt; 8],
}

impl<E> BusMessage<E> for ControlBlockRequestMessage
where
    E: ExtensionField<Felt>,
{
    /// Encodes as **alpha + <beta, [label, addr, _, state[0..7], ..., op_code]>** (skips
    /// node_index).
    fn value(&self, challenges: &Challenges<E>) -> E {
        // Header + rate portion + capacity domain element for op_code
        let mut acc = header_rate_value(
            challenges,
            self.transition_label,
            self.addr_next,
            self.decoder_hasher_state,
        );
        acc += challenges.beta_powers[bus_message::CAPACITY_DOMAIN_IDX] * self.op_code;
        acc
    }

    fn source(&self) -> &str {
        let op_code = self.op_code.as_canonical_u64() as u8;
        match op_code {
            opcodes::JOIN => "join",
            opcodes::SPLIT => "split",
            opcodes::LOOP => "loop",
            opcodes::CALL => "call",
            opcodes::DYN => "dyn",
            opcodes::DYNCALL => "dyncall",
            opcodes::SYSCALL => "syscall",
            _ => panic!("unexpected opcode: {op_code}"),
        }
    }
}

impl Display for ControlBlockRequestMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ transition_label: {}, addr_next: {}, op_code: {}, decoder_hasher_state: {:?} }}",
            self.transition_label, self.addr_next, self.op_code, self.decoder_hasher_state
        )
    }
}

// GENERIC HASHER MESSAGE
// ===============================================================================================

pub struct HasherMessage {
    pub transition_label: Felt,
    pub addr_next: Felt,
    pub node_index: Felt,
    pub hasher_state: [Felt; hasher::STATE_WIDTH],
    pub source: &'static str,
}

impl<E> BusMessage<E> for HasherMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        hasher_message_value(
            challenges,
            self.transition_label,
            self.addr_next,
            self.node_index,
            self.hasher_state,
        )
    }

    fn source(&self) -> &str {
        self.source
    }
}

impl Display for HasherMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ transition_label: {}, addr_next: {}, node_index: {}, hasher_state: {:?} }}",
            self.transition_label, self.addr_next, self.node_index, self.hasher_state
        )
    }
}

// SPAN BLOCK MESSAGE
// ===============================================================================================

pub struct SpanBlockMessage {
    pub transition_label: Felt,
    pub addr_next: Felt,
    pub state: [Felt; 8],
}

impl<E> BusMessage<E> for SpanBlockMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        header_rate_value(challenges, self.transition_label, self.addr_next, self.state)
    }

    fn source(&self) -> &str {
        "span"
    }
}

impl Display for SpanBlockMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ transition_label: {}, addr_next: {}, state: {:?} }}",
            self.transition_label, self.addr_next, self.state
        )
    }
}

// RESPAN BLOCK MESSAGE
// ===============================================================================================

pub struct RespanBlockMessage {
    pub transition_label: Felt,
    pub addr_next: Felt,
    pub state: [Felt; 8],
}

impl<E> BusMessage<E> for RespanBlockMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        header_rate_value(challenges, self.transition_label, self.addr_next - ONE, self.state)
    }

    fn source(&self) -> &str {
        "respan"
    }
}

impl Display for RespanBlockMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ transition_label: {}, addr_next: {}, state: {:?} }}",
            self.transition_label, self.addr_next, self.state
        )
    }
}

// END BLOCK MESSAGE
// ===============================================================================================

pub struct EndBlockMessage {
    pub addr: Felt,
    pub transition_label: Felt,
    pub digest: [Felt; 4],
}

impl<E> BusMessage<E> for EndBlockMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        header_digest_value(challenges, self.transition_label, self.addr, self.digest)
    }

    fn source(&self) -> &str {
        "end"
    }
}

impl Display for EndBlockMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ addr: {}, transition_label: {}, digest: {:?} }}",
            self.addr, self.transition_label, self.digest
        )
    }
}
