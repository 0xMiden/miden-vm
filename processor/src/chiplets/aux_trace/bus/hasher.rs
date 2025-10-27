use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::{
    RowIndex,
    trace::{
        chiplets::{
            hasher,
            hasher::{
                HASH_CYCLE_LEN, LINEAR_HASH_LABEL, MP_VERIFY_LABEL, MR_UPDATE_NEW_LABEL,
                MR_UPDATE_OLD_LABEL, NUM_ROUNDS, RETURN_HASH_LABEL, RETURN_STATE_LABEL,
            },
        },
        log_precompile::{
            HELPER_ADDR_IDX, HELPER_CAP_PREV_RANGE, STACK_CAP_NEXT_RANGE, STACK_COMM_RANGE,
            STACK_R0_RANGE, STACK_R1_RANGE, STACK_TAG_RANGE,
        },
        main_trace::MainTrace,
    },
};
use miden_core::{
    Felt, FieldElement, ONE, OPCODE_CALL, OPCODE_JOIN, OPCODE_LOOP, OPCODE_SPLIT, ZERO,
    utils::range,
};

use super::get_op_label;
use crate::{
    Word,
    chiplets::aux_trace::build_value,
    debug::{BusDebugger, BusMessage},
};
// REQUESTS
// ==============================================================================================

/// Builds requests made to the hasher chiplet at the start of a control block.
pub(super) fn build_control_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    decoder_hasher_state: [Felt; 8],
    op_code_felt: Felt,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let message = ControlBlockRequestMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: main_trace.addr(row + 1),
        op_code: op_code_felt,
        decoder_hasher_state,
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Builds requests made to the hasher chiplet at the start of a span block.
pub(super) fn build_span_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let span_block_message = SpanBlockMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: main_trace.addr(row + 1),
        state: main_trace.decoder_hasher_state(row),
    };

    let value = span_block_message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(span_block_message), alphas);

    value
}

/// Builds requests made to the hasher chiplet at the start of a respan block.
pub(super) fn build_respan_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let respan_block_message = RespanBlockMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 32),
        addr_next: main_trace.addr(row + 1),
        state: main_trace.decoder_hasher_state(row),
    };

    let value = respan_block_message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(respan_block_message), alphas);

    value
}

/// Builds requests made to the hasher chiplet at the end of a block.
pub(super) fn build_end_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let end_block_message = EndBlockMessage {
        addr: main_trace.addr(row) + Felt::from(NUM_ROUNDS as u8),
        transition_label: Felt::from(RETURN_HASH_LABEL + 32),
        digest: main_trace.decoder_hasher_state(row)[..4].try_into().unwrap(),
    };

    let value = end_block_message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(end_block_message), alphas);

    value
}

/// Builds `HPERM` requests made to the hash chiplet.
pub(super) fn build_hperm_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
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
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: helper_0,
        node_index: ZERO,
        hasher_state: [s11, s10, s9, s8, s7, s6, s5, s4, s3, s2, s1, s0],
        source: "hperm input",
    };
    let output_req = HasherMessage {
        transition_label: Felt::from(RETURN_STATE_LABEL + 32),
        addr_next: helper_0 + Felt::new(7),
        node_index: ZERO,
        hasher_state: [
            s11_nxt, s10_nxt, s9_nxt, s8_nxt, s7_nxt, s6_nxt, s5_nxt, s4_nxt, s3_nxt, s2_nxt,
            s1_nxt, s0_nxt,
        ],
        source: "hperm output",
    };

    let combined_value = input_req.value(alphas) * output_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input_req), alphas);
        _debugger.add_request(alloc::boxed::Box::new(output_req), alphas);
    }

    combined_value
}

/// Builds `LOG_PRECOMPILE` requests made to the hash chiplet.
///
/// The operation absorbs `[TAG, COMM]` into the transcript via an RPO permutation with
/// capacity `CAP_PREV`, producing output `[CAP_NEXT, R0, R1]`.
///
/// Stack layout (current row):
/// - `s0..s3`: `COMM[3..0]`
/// - `s4..s7`: `TAG[3..0]`
///
/// Helper registers (current row):
/// - `h0`: hasher address
/// - `h1..h4`: `CAP_PREV[0..3]`
///
/// Stack layout (next row):
/// - `s0..s3`: `R1[3..0]`
/// - `s4..s7`: `R0[3..0]`
/// - `s8..s11`: `CAP_NEXT[3..0]`
pub(super) fn build_log_precompile_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // Read helper registers
    let addr = main_trace.helper_register(HELPER_ADDR_IDX, row);

    // Input state [CAP_PREV, TAG, COMM]
    // Helper registers store capacity in sequential order [e0, e1, e2, e3]
    let cap_prev = Word::from([
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 1, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 2, row),
        main_trace.helper_register(HELPER_CAP_PREV_RANGE.start + 3, row),
    ]);

    // Stack stores words in big-endian order: stack[0..3] = [e3, e2, e1, e0]
    // Therefore we read in reverse order to reconstruct the word correctly
    let comm = Word::from([
        main_trace.stack_element(STACK_COMM_RANGE.end - 1, row),
        main_trace.stack_element(STACK_COMM_RANGE.end - 2, row),
        main_trace.stack_element(STACK_COMM_RANGE.end - 3, row),
        main_trace.stack_element(STACK_COMM_RANGE.end - 4, row),
    ]);
    let tag = Word::from([
        main_trace.stack_element(STACK_TAG_RANGE.end - 1, row),
        main_trace.stack_element(STACK_TAG_RANGE.end - 2, row),
        main_trace.stack_element(STACK_TAG_RANGE.end - 3, row),
        main_trace.stack_element(STACK_TAG_RANGE.end - 4, row),
    ]);
    let state_input = [cap_prev, tag, comm];

    // Output state [CAP_NEXT, R0, R1]
    let r1 = Word::from([
        main_trace.stack_element(STACK_R1_RANGE.end - 1, row + 1),
        main_trace.stack_element(STACK_R1_RANGE.end - 2, row + 1),
        main_trace.stack_element(STACK_R1_RANGE.end - 3, row + 1),
        main_trace.stack_element(STACK_R1_RANGE.end - 4, row + 1),
    ]);
    let r0 = Word::from([
        main_trace.stack_element(STACK_R0_RANGE.end - 1, row + 1),
        main_trace.stack_element(STACK_R0_RANGE.end - 2, row + 1),
        main_trace.stack_element(STACK_R0_RANGE.end - 3, row + 1),
        main_trace.stack_element(STACK_R0_RANGE.end - 4, row + 1),
    ]);
    let cap_next = Word::from([
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 1, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 2, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 3, row + 1),
        main_trace.stack_element(STACK_CAP_NEXT_RANGE.end - 4, row + 1),
    ]);
    let state_output = [cap_next, r0, r1];

    let input_req = HasherMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: addr,
        node_index: ZERO,
        hasher_state: Word::words_as_elements(&state_input).try_into().unwrap(),
        source: "log_precompile input",
    };

    let output_req = HasherMessage {
        transition_label: Felt::from(RETURN_STATE_LABEL + 32),
        addr_next: addr + Felt::new(7),
        node_index: ZERO,
        hasher_state: Word::words_as_elements(&state_output).try_into().unwrap(),
        source: "log_precompile output",
    };

    let combined_value = input_req.value(alphas) * output_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input_req), alphas);
        _debugger.add_request(alloc::boxed::Box::new(output_req), alphas);
    }

    combined_value
}

/// Builds `MPVERIFY` requests made to the hash chiplet.
pub(super) fn build_mpverify_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let helper_0 = main_trace.helper_register(0, row);

    let node_value = [
        main_trace.stack_element(0, row),
        main_trace.stack_element(1, row),
        main_trace.stack_element(2, row),
        main_trace.stack_element(3, row),
    ];
    let node_depth = main_trace.stack_element(4, row);
    let node_index = main_trace.stack_element(5, row);

    let merkle_tree_root = [
        main_trace.stack_element(6, row),
        main_trace.stack_element(7, row),
        main_trace.stack_element(8, row),
        main_trace.stack_element(9, row),
    ];

    let input = HasherMessage {
        transition_label: Felt::from(MP_VERIFY_LABEL + 16),
        addr_next: helper_0,
        node_index,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            node_value[3],
            node_value[2],
            node_value[1],
            node_value[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mpverify input",
    };

    let output = HasherMessage {
        transition_label: Felt::from(RETURN_HASH_LABEL + 32),
        addr_next: helper_0 + node_depth.mul_small(8) - ONE,
        node_index: ZERO,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            merkle_tree_root[3],
            merkle_tree_root[2],
            merkle_tree_root[1],
            merkle_tree_root[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mpverify output",
    };

    let combined_value = input.value(alphas) * output.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input), alphas);
        _debugger.add_request(alloc::boxed::Box::new(output), alphas);
    }

    combined_value
}

/// Builds `MRUPDATE` requests made to the hash chiplet.
pub(super) fn build_mrupdate_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let helper_0 = main_trace.helper_register(0, row);

    let old_node_value = [
        main_trace.stack_element(0, row),
        main_trace.stack_element(1, row),
        main_trace.stack_element(2, row),
        main_trace.stack_element(3, row),
    ];
    let merkle_path_depth = main_trace.stack_element(4, row);
    let node_index = main_trace.stack_element(5, row);
    let old_root = [
        main_trace.stack_element(6, row),
        main_trace.stack_element(7, row),
        main_trace.stack_element(8, row),
        main_trace.stack_element(9, row),
    ];
    let new_node_value = [
        main_trace.stack_element(10, row),
        main_trace.stack_element(11, row),
        main_trace.stack_element(12, row),
        main_trace.stack_element(13, row),
    ];
    let new_root = [
        main_trace.stack_element(0, row + 1),
        main_trace.stack_element(1, row + 1),
        main_trace.stack_element(2, row + 1),
        main_trace.stack_element(3, row + 1),
    ];

    let input_old = HasherMessage {
        transition_label: Felt::from(MR_UPDATE_OLD_LABEL + 16),
        addr_next: helper_0,
        node_index,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            old_node_value[3],
            old_node_value[2],
            old_node_value[1],
            old_node_value[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mrupdate input_old",
    };

    let output_old = HasherMessage {
        transition_label: Felt::from(RETURN_HASH_LABEL + 32),
        addr_next: helper_0 + merkle_path_depth.mul_small(8) - ONE,
        node_index: ZERO,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            old_root[3],
            old_root[2],
            old_root[1],
            old_root[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mrupdate output_old",
    };

    let input_new = HasherMessage {
        transition_label: Felt::from(MR_UPDATE_NEW_LABEL + 16),
        addr_next: helper_0 + merkle_path_depth.mul_small(8),
        node_index,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            new_node_value[3],
            new_node_value[2],
            new_node_value[1],
            new_node_value[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mrupdate input_new",
    };

    let output_new = HasherMessage {
        transition_label: Felt::from(RETURN_HASH_LABEL + 32),
        addr_next: helper_0 + merkle_path_depth.mul_small(16) - ONE,
        node_index: ZERO,
        hasher_state: [
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            new_root[3],
            new_root[2],
            new_root[1],
            new_root[0],
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ],
        source: "mrupdate output_new",
    };

    let combined_value = input_old.value(alphas)
        * output_old.value(alphas)
        * input_new.value(alphas)
        * output_new.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(input_old), alphas);
        _debugger.add_request(alloc::boxed::Box::new(output_old), alphas);
        _debugger.add_request(alloc::boxed::Box::new(input_new), alphas);
        _debugger.add_request(alloc::boxed::Box::new(output_new), alphas);
    }

    combined_value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the hasher chiplet at `row`.
pub(super) fn build_hasher_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: FieldElement<BaseField = Felt>,
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
        let state = main_trace.chiplet_hasher_state(row);
        let node_index = main_trace.chiplet_node_index(row);
        let transition_label = op_label + Felt::from(16_u8);

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
            multiplicand = hasher_message.value(alphas);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
        }

        // f_mp or f_mv or f_mu == 1
        // v_leaf = v_h + (1 - b) * v_b + b * v_d
        if selector1 == ONE && !(selector2 == ZERO && selector3 == ZERO) {
            let bit = (node_index.as_int() & 1) as u8;
            if bit == 0 {
                let hasher_message = HasherMessage {
                    transition_label,
                    addr_next,
                    node_index,
                    hasher_state: [
                        ZERO, ZERO, ZERO, ZERO, state[4], state[5], state[6], state[7], ZERO, ZERO,
                        ZERO, ZERO,
                    ],
                    source: "hasher",
                };

                multiplicand = hasher_message.value(alphas);

                #[cfg(any(test, feature = "bus-debugger"))]
                _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
            } else {
                let hasher_message = HasherMessage {
                    transition_label,
                    addr_next,
                    node_index,
                    hasher_state: [
                        ZERO, ZERO, ZERO, ZERO, state[8], state[9], state[10], state[11], ZERO,
                        ZERO, ZERO, ZERO,
                    ],
                    source: "hasher",
                };

                multiplicand = hasher_message.value(alphas);

                #[cfg(any(test, feature = "bus-debugger"))]
                _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
            }
        }
    }

    // f_hout, f_sout, f_abp == 1
    if row.as_usize() % HASH_CYCLE_LEN == HASH_CYCLE_LEN - 1 {
        let state = main_trace.chiplet_hasher_state(row);
        let node_index = main_trace.chiplet_node_index(row);
        let transition_label = op_label + Felt::from(32_u8);

        // f_hout == 1
        // v_res = v_h + v_b;
        if selector1 == ZERO && selector2 == ZERO && selector3 == ZERO {
            let hasher_message = HasherMessage {
                transition_label,
                addr_next,
                node_index,
                hasher_state: [
                    ZERO, ZERO, ZERO, ZERO, state[4], state[5], state[6], state[7], ZERO, ZERO,
                    ZERO, ZERO,
                ],
                source: "hasher",
            };
            multiplicand = hasher_message.value(alphas);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
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

            multiplicand = hasher_message.value(alphas);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
        }

        // f_abp == 1
        // v_abp = v_h + v_b' + v_c' - v_b - v_c
        if selector1 == ONE && selector2 == ZERO && selector3 == ZERO {
            // build the value from the hasher state's just right after the absorption of new
            // elements.
            let state_nxt = main_trace.chiplet_hasher_state(row + 1);

            let hasher_message = HasherMessage {
                transition_label,
                addr_next,
                node_index,
                hasher_state: [
                    ZERO,
                    ZERO,
                    ZERO,
                    ZERO,
                    state_nxt[4],
                    state_nxt[5],
                    state_nxt[6],
                    state_nxt[7],
                    state_nxt[8],
                    state_nxt[9],
                    state_nxt[10],
                    state_nxt[11],
                ],
                source: "hasher",
            };

            multiplicand = hasher_message.value(alphas);

            #[cfg(any(test, feature = "bus-debugger"))]
            _debugger.add_response(alloc::boxed::Box::new(hasher_message), alphas);
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
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let header = alphas[0]
            + alphas[1].mul_base(self.transition_label)
            + alphas[2].mul_base(self.addr_next);

        header
            + alphas[5].mul_base(self.op_code)
            + build_value(&alphas[8..16], self.decoder_hasher_state)
    }

    fn source(&self) -> &str {
        let op_code = self.op_code.as_int() as u8;
        match op_code {
            OPCODE_JOIN => "join",
            OPCODE_SPLIT => "split",
            OPCODE_LOOP => "loop",
            OPCODE_CALL => "call",
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

const NUM_HEADER_ALPHAS: usize = 4;

pub struct HasherMessage {
    pub transition_label: Felt,
    pub addr_next: Felt,
    pub node_index: Felt,
    pub hasher_state: [Felt; hasher::STATE_WIDTH],
    pub source: &'static str,
}

impl<E> BusMessage<E> for HasherMessage
where
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let header = alphas[0]
            + alphas[1].mul_base(self.transition_label)
            + alphas[2].mul_base(self.addr_next)
            + alphas[3].mul_base(self.node_index);

        header
            + build_value(&alphas[range(NUM_HEADER_ALPHAS, hasher::STATE_WIDTH)], self.hasher_state)
    }

    fn source(&self) -> &str {
        self.source
    }
}

impl Display for HasherMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ transition_label: {}, addr_next: {}, node_index: {}, decoder_hasher_state: {:?} }}",
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
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let header = alphas[0]
            + alphas[1].mul_base(self.transition_label)
            + alphas[2].mul_base(self.addr_next);

        header + build_value(&alphas[8..16], self.state)
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
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let header = alphas[0]
            + alphas[1].mul_base(self.transition_label)
            + alphas[2].mul_base(self.addr_next - ONE);

        header + build_value(&alphas[8..16], self.state)
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
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        let header =
            alphas[0] + alphas[1].mul_base(self.transition_label) + alphas[2].mul_base(self.addr);

        header + build_value(&alphas[8..12], self.digest)
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
