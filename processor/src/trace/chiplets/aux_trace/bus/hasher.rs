use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::trace::{
    Challenges, MainTrace, RowIndex, bus_message,
    bus_types::CHIPLETS_BUS,
    chiplets::{
        hasher,
        hasher::{
            CONTROLLER_ROWS_PER_PERM_FELT, LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL,
            MR_UPDATE_OLD_LABEL, RETURN_HASH_LABEL, RETURN_STATE_LABEL,
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
};

// HASHER MESSAGE ENCODING LAYOUT
// ================================================================================================
//
// All hasher chiplet bus messages use a common encoding structure:
//
//   challenges.bus_prefix[CHIPLETS_BUS]                     = alpha (randomness base, accessed
// directly)   challenges.beta_powers[0]            = beta^0 (label: transition type)
//   challenges.beta_powers[1]            = beta^1 (addr: hasher chiplet address)
//   challenges.beta_powers[2]            = beta^2 (node_index: Merkle path position, 0 for
//                                         non-Merkle ops)
//   challenges.beta_powers[3..10]        = beta^3..beta^10 (state[0..7]: RATE0 || RATE1)
//   challenges.beta_powers[11..14]       = beta^11..beta^14 (capacity[0..3])
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

/// Creates a full hasher state with a word in the first 4 elements and zeros elsewhere.
/// Used by the bus debugger to construct HasherMessage structs for Merkle operations
/// where only the digest word (4 elements) is meaningful.
#[cfg(any(test, feature = "bus-debugger"))]
fn word_to_hasher_state(word: &[Felt; WORD_SIZE]) -> [Felt; hasher::STATE_WIDTH] {
    let mut state = [ZERO; hasher::STATE_WIDTH];
    state[..WORD_SIZE].copy_from_slice(word);
    state
}

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
    let mut acc = challenges.bus_prefix[CHIPLETS_BUS]
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
    let mut acc = challenges.bus_prefix[CHIPLETS_BUS]
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
    let mut acc = challenges.bus_prefix[CHIPLETS_BUS]
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
        // The output row's hasher address is the input row's address + 1,
        // since each controller pair occupies 2 consecutive rows.
        addr: main_trace.addr(row) + ONE,
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
    let state: [Felt; 12] = core::array::from_fn(|i| main_trace.stack_element(i, row));
    let state_nxt: [Felt; 12] = core::array::from_fn(|i| main_trace.stack_element(i, row + 1));

    let input_req = HasherMessage {
        transition_label: LINEAR_HASH_LABEL_START,
        addr_next: helper_0,
        node_index: ZERO,
        // Internal Poseidon2 state for HPERM is taken directly from the top 12
        // stack elements in order: [RATE0, RATE1, CAPACITY] = [s0..s11].
        hasher_state: state,
        source: "hperm input",
    };
    let output_req = HasherMessage {
        transition_label: RETURN_STATE_LABEL_END,
        // Output row is 1 row after input in controller pair
        addr_next: helper_0 + ONE,
        node_index: ZERO,
        hasher_state: state_nxt,
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
        // Output row is 1 row after input in controller pair
        addr_next: addr + ONE,
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
    let rows_per_perm = CONTROLLER_ROWS_PER_PERM_FELT;

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
    // Output addr: depth pairs * 2 rows/pair - 1 (last output row)
    let output_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + node_depth * rows_per_perm - ONE,
        ZERO,
        root_word,
    );

    let combined_value = input_value * output_value;

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let input = HasherMessage {
            transition_label: MP_VERIFY_LABEL_START,
            addr_next: helper_0,
            node_index,
            hasher_state: word_to_hasher_state(&node_word),
            source: "mpverify input",
        };

        let output = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + node_depth * rows_per_perm - ONE,
            node_index: ZERO,
            hasher_state: word_to_hasher_state(&root_word),
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
    let rows_per_perm = CONTROLLER_ROWS_PER_PERM_FELT;
    let two_legs_rows = rows_per_perm + rows_per_perm;

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
    // Old path output: depth pairs * 2 rows/pair - 1
    let output_old_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + merkle_path_depth * rows_per_perm - ONE,
        ZERO,
        old_root_word,
    );
    // New path input: starts right after old path output
    let input_new_value = hasher_message_value(
        challenges,
        MR_UPDATE_NEW_LABEL_START,
        helper_0 + merkle_path_depth * rows_per_perm,
        node_index,
        new_node_word,
    );
    // New path output: depth pairs * 2 rows/pair * 2 legs - 1
    let output_new_value = hasher_message_value(
        challenges,
        RETURN_HASH_LABEL_END,
        helper_0 + merkle_path_depth * two_legs_rows - ONE,
        ZERO,
        new_root_word,
    );

    let combined_value = input_old_value * output_old_value * input_new_value * output_new_value;

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let input_old = HasherMessage {
            transition_label: MR_UPDATE_OLD_LABEL_START,
            addr_next: helper_0,
            node_index,
            hasher_state: word_to_hasher_state(&old_node_word),
            source: "mrupdate input_old",
        };

        let output_old = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + merkle_path_depth * rows_per_perm - ONE,
            node_index: ZERO,
            hasher_state: word_to_hasher_state(&old_root_word),
            source: "mrupdate output_old",
        };

        let input_new = HasherMessage {
            transition_label: MR_UPDATE_NEW_LABEL_START,
            addr_next: helper_0 + merkle_path_depth * rows_per_perm,
            node_index,
            hasher_state: word_to_hasher_state(&new_node_word),
            source: "mrupdate input_new",
        };

        let output_new = HasherMessage {
            transition_label: RETURN_HASH_LABEL_END,
            addr_next: helper_0 + merkle_path_depth * two_legs_rows - ONE,
            node_index: ZERO,
            hasher_state: word_to_hasher_state(&new_root_word),
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
///
/// Only controller rows of the hasher chiplet are able to produce bus responses.
///
/// **Input rows that produce responses:**
/// - Sponge start (is_boundary=1, LINEAR_HASH): full state -> matches SPAN/control block request
/// - Sponge continuation (is_boundary=0, LINEAR_HASH): rate-only -> matches RESPAN request
/// - Tree start (is_boundary=1, MP/MV/MU): leaf word -> matches MPVERIFY/MRUPDATE input
///
/// **Input rows that do NOT produce responses:**
/// - Tree continuation (is_boundary=0, MP/MV/MU): no matching request from decoder
///
/// **Output rows that produce responses:**
/// - HOUT (s2=0): digest -> matches END / MPVERIFY output / MRUPDATE output
/// - SOUT with is_boundary=1 (s2=1): full state -> matches HPERM output
///
/// **Output rows that do NOT produce responses:**
/// - SOUT with is_boundary=0: intermediate output, no matching request
///
/// **Perm segment rows:** never produce responses.
pub(super) fn build_hasher_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    // Permutation segment rows never produce chiplets bus responses.
    if main_trace.chiplet_perm_seg(row) == ONE {
        return E::ONE;
    }

    // --- Precompute common values -----------------------------------------------

    let selector1 = main_trace.chiplet_selector_1(row);
    let selector2 = main_trace.chiplet_selector_2(row);
    let selector3 = main_trace.chiplet_selector_3(row);
    // Hasher labels are computed with s0=0 (the old chiplet-level selector for hasher).
    // chiplet_selector_0 is now s_ctrl (1 on controller rows), but labels encode
    // [0, s0, s1, s2] to match the label constants defined in hasher.rs.
    let op_label = get_op_label(ZERO, selector1, selector2, selector3);
    let addr_next = Felt::from(row + 1);
    let state = main_trace.chiplet_hasher_state(row);
    let node_index = main_trace.chiplet_node_index(row);

    // Hasher-internal selectors (not chiplet-level selectors).
    // chiplet selector1 = hasher s0, selector2 = hasher s1, selector3 = hasher s2.
    let s0 = selector1;
    let s1 = selector2;
    let s2 = selector3;

    let is_boundary = main_trace.chiplet_is_boundary(row);

    // Precompute commonly needed slices.
    let digest: [Felt; WORD_SIZE] =
        state[..WORD_SIZE].try_into().expect("state[0..4] must be 4 field elements");
    let rate: [Felt; hasher::RATE_LEN] = state[..hasher::RATE_LEN]
        .try_into()
        .expect("state[0..8] must be 8 field elements");

    // --- Classify row and compute response --------------------------------------
    //
    // The branches below are mutually exclusive. Each either returns a non-identity
    // response or falls through to return E::ONE (identity = no response).

    if s0 == ONE && s1 == ZERO && s2 == ZERO && is_boundary == ONE {
        // Sponge start (LINEAR_HASH, is_boundary=1): full 12-element state.
        // Matches SPAN / control block start request.
        let label = op_label + LABEL_OFFSET_START;
        let msg = HasherMessage {
            transition_label: label,
            addr_next,
            node_index,
            hasher_state: state,
            source: "hasher sponge_start",
        };
        let value = msg.value(challenges);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(msg), challenges);

        value
    } else if s0 == ONE && s1 == ZERO && s2 == ZERO {
        // Sponge continuation (LINEAR_HASH, is_boundary=0): rate-only message.
        // Label uses OUTPUT_LABEL_OFFSET because the decoder's RESPAN request uses
        // LINEAR_HASH_LABEL + 32.
        let label = op_label + LABEL_OFFSET_END;
        let value = header_rate_value(challenges, label, addr_next, rate);

        #[cfg(any(test, feature = "bus-debugger"))]
        {
            let msg = HasherMessage {
                transition_label: label,
                addr_next,
                node_index: ZERO,
                hasher_state: word_to_hasher_state(&digest), // rate-only, capacity zeroed
                source: "hasher sponge_respan",
            };
            _debugger.add_response(alloc::boxed::Box::new(msg), challenges);
        }

        value
    } else if s0 == ONE && (s1 == ONE || s2 == ONE) && is_boundary == ONE {
        // Tree start (MP_VERIFY / MR_UPDATE_OLD / MR_UPDATE_NEW, is_boundary=1): leaf word
        // selected by direction bit. Matches MPVERIFY / MRUPDATE first-input request.
        // Tree continuation inputs (is_boundary=0) produce no response.
        let label = op_label + LABEL_OFFSET_START;
        let bit = node_index.as_canonical_u64() & 1;
        let leaf_word: [Felt; WORD_SIZE] = if bit == 0 {
            digest
        } else {
            state[WORD_SIZE..hasher::RATE_LEN]
                .try_into()
                .expect("state[4..8] must be 4 field elements")
        };

        let value = hasher_message_value(challenges, label, addr_next, node_index, leaf_word);

        #[cfg(any(test, feature = "bus-debugger"))]
        {
            let msg = HasherMessage {
                transition_label: label,
                addr_next,
                node_index,
                hasher_state: word_to_hasher_state(&leaf_word),
                source: "hasher tree_start",
            };
            _debugger.add_response(alloc::boxed::Box::new(msg), challenges);
        }

        value
    } else if s0 == ZERO && s1 == ZERO && s2 == ZERO {
        // HOUT -- RETURN_HASH (0,0,0): digest-only response.
        // Matches END / MPVERIFY output / MRUPDATE output.
        let label = op_label + LABEL_OFFSET_END;
        let value = hasher_message_value(challenges, label, addr_next, node_index, digest);

        #[cfg(any(test, feature = "bus-debugger"))]
        {
            let msg = HasherMessage {
                transition_label: label,
                addr_next,
                node_index,
                hasher_state: word_to_hasher_state(&digest),
                source: "hasher hout",
            };
            _debugger.add_response(alloc::boxed::Box::new(msg), challenges);
        }

        value
    } else if s0 == ZERO && s1 == ZERO && s2 == ONE && is_boundary == ONE {
        // SOUT final -- RETURN_STATE (0,0,1) with is_boundary=1: full 12-element state.
        // Matches HPERM output request. Intermediate SOUT (is_boundary=0) produces no response.
        let label = op_label + LABEL_OFFSET_END;
        let msg = HasherMessage {
            transition_label: label,
            addr_next,
            node_index,
            hasher_state: state,
            source: "hasher sout_final",
        };
        let value = msg.value(challenges);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(msg), challenges);

        value
    } else {
        // No response: padding rows (s0=0, s1=1), tree continuations (is_boundary=0),
        // intermediate SOUT (is_boundary=0), or any other non-responding row.
        E::ONE
    }
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
        // In the controller/perm split, addr_next is used directly (no subtraction).
        header_rate_value(challenges, self.transition_label, self.addr_next, self.state)
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
