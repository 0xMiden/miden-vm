use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::trace::{
    MainTrace, RowIndex,
    chiplets::{
        ace::{ACE_INSTRUCTION_ID1_OFFSET, ACE_INSTRUCTION_ID2_OFFSET},
        memory::{
            MEMORY_ACCESS_ELEMENT, MEMORY_ACCESS_WORD, MEMORY_READ_ELEMENT_LABEL,
            MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL, MEMORY_WRITE_WORD_LABEL,
        },
    },
};
use miden_core::{
    FMP_ADDR, FMP_INIT_VALUE, Felt, ONE, OPCODE_DYNCALL, ZERO,
    field::{ExtensionField, PrimeCharacteristicRing},
};

use crate::{
    chiplets::aux_trace::build_value,
    debug::{BusDebugger, BusMessage},
};

// CONSTANTS
// ================================================================================================

const FOUR: Felt = Felt::new(4);

// REQUESTS
// ================================================================================================

/// Builds ACE chiplet read requests as part of the `READ` section made to the memory chiplet.
pub fn build_ace_memory_read_word_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let word = [
        main_trace.chiplet_ace_v_0_0(row),
        main_trace.chiplet_ace_v_0_1(row),
        main_trace.chiplet_ace_v_1_0(row),
        main_trace.chiplet_ace_v_1_1(row),
    ];
    let op_label = MEMORY_READ_WORD_LABEL;
    let clk = main_trace.chiplet_ace_clk(row);
    let ctx = main_trace.chiplet_ace_ctx(row);
    let addr = main_trace.chiplet_ace_ptr(row);

    let message = MemoryWordMessage {
        op_label: Felt::from_u8(op_label),
        ctx,
        addr,
        clk,
        word,
        source: "read word ACE",
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Builds ACE chiplet read requests as part of the `EVAL` section made to the memory chiplet.
pub fn build_ace_memory_read_element_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let element = main_trace.chiplet_ace_eval_op(row);

    let id_0 = main_trace.chiplet_ace_id_1(row);
    let id_1 = main_trace.chiplet_ace_id_2(row);
    let element =
        id_0 + id_1 * ACE_INSTRUCTION_ID1_OFFSET + (element + ONE) * ACE_INSTRUCTION_ID2_OFFSET;
    let op_label = MEMORY_READ_ELEMENT_LABEL;
    let clk = main_trace.chiplet_ace_clk(row);
    let ctx = main_trace.chiplet_ace_ctx(row);
    let addr = main_trace.chiplet_ace_ptr(row);

    let message = MemoryElementMessage {
        op_label: Felt::from_u8(op_label),
        ctx,
        addr,
        clk,
        element,
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Builds `DYN` and `DYNCALL` read request made to the memory chiplet for the callee hash.
pub(super) fn build_dyn_dyncall_callee_hash_read_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let memory_req = MemoryWordMessage {
        op_label: Felt::from_u8(MEMORY_READ_WORD_LABEL),
        ctx: main_trace.ctx(row),
        addr: main_trace.stack_element(0, row),
        clk: main_trace.clk(row),
        word: main_trace.decoder_hasher_state_first_half(row).into(),
        source: if op_code_felt == Felt::from_u8(OPCODE_DYNCALL) {
            "dyncall"
        } else {
            "dyn"
        },
    };

    let value = memory_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(memory_req), alphas);

    value
}

/// Builds a write request to initialize the frame pointer in memory when entering a new execution
/// context.
///
/// Currently, this is done with `CALL` and `DYNCALL`.
pub(super) fn build_fmp_initialization_write_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // Note that `ctx` is taken from the next row, as the goal of this request is to write the
    // initial FMP value to memory at the start of a new execution context, which happens
    // immediately after the current row.
    let memory_req = MemoryElementMessage {
        op_label: Felt::from_u8(MEMORY_WRITE_ELEMENT_LABEL),
        ctx: main_trace.ctx(row + 1),
        addr: FMP_ADDR,
        clk: main_trace.clk(row),
        element: FMP_INIT_VALUE,
    };

    let value = memory_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(memory_req), alphas);

    value
}

/// Builds `MLOADW` and `MSTOREW` requests made to the memory chiplet.
pub(super) fn build_mem_mloadw_mstorew_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    op_label: u8,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // word[i] maps directly to stack position i.
    let word = [
        main_trace.stack_element(0, row + 1),
        main_trace.stack_element(1, row + 1),
        main_trace.stack_element(2, row + 1),
        main_trace.stack_element(3, row + 1),
    ];
    let addr = main_trace.stack_element(0, row);

    debug_assert!(op_label == MEMORY_READ_WORD_LABEL || op_label == MEMORY_WRITE_WORD_LABEL);
    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    let message = MemoryWordMessage {
        op_label: Felt::from_u8(op_label),
        ctx,
        addr,
        clk,
        word,
        source: if op_label == MEMORY_READ_WORD_LABEL {
            "mloadw"
        } else {
            "mstorew"
        },
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Builds `MLOAD` and `MSTORE` requests made to the memory chiplet.
pub(super) fn build_mem_mload_mstore_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    op_label: u8,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let element = main_trace.stack_element(0, row + 1);
    let addr = main_trace.stack_element(0, row);

    debug_assert!(op_label == MEMORY_READ_ELEMENT_LABEL || op_label == MEMORY_WRITE_ELEMENT_LABEL);

    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    let message = MemoryElementMessage {
        op_label: Felt::from_u8(op_label),
        ctx,
        addr,
        clk,
        element,
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(message), alphas);

    value
}

/// Builds `MSTREAM` requests made to the memory chiplet.
pub(super) fn build_mstream_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let op_label = Felt::from_u8(MEMORY_READ_WORD_LABEL);
    let addr = main_trace.stack_element(12, row);
    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    // word[0] is at stack position 0 (top).
    // MSTREAM loads two words: first word (from addr) to s0-s3, second word (from addr+4) to s4-s7.
    let mem_req_1 = MemoryWordMessage {
        op_label,
        ctx,
        addr,
        clk,
        word: [
            main_trace.stack_element(0, row + 1),
            main_trace.stack_element(1, row + 1),
            main_trace.stack_element(2, row + 1),
            main_trace.stack_element(3, row + 1),
        ],
        source: "mstream req 1",
    };
    let mem_req_2 = MemoryWordMessage {
        op_label,
        ctx,
        addr: addr + FOUR,
        clk,
        word: [
            main_trace.stack_element(4, row + 1),
            main_trace.stack_element(5, row + 1),
            main_trace.stack_element(6, row + 1),
            main_trace.stack_element(7, row + 1),
        ],
        source: "mstream req 2",
    };

    let combined_value = mem_req_1.value(alphas) * mem_req_2.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(mem_req_1), alphas);
        _debugger.add_request(alloc::boxed::Box::new(mem_req_2), alphas);
    }

    combined_value
}

/// Builds `PIPE` requests made to the memory chiplet.
pub(super) fn build_pipe_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let op_label = Felt::from_u8(MEMORY_WRITE_WORD_LABEL);
    let addr = main_trace.stack_element(12, row);
    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    // word[0] is at stack position 0 (top).
    // PIPE writes two words: first word (from s0-s3) to addr, second word (from s4-s7) to addr+4.
    let mem_req_1 = MemoryWordMessage {
        op_label,
        ctx,
        addr,
        clk,
        word: [
            main_trace.stack_element(0, row + 1),
            main_trace.stack_element(1, row + 1),
            main_trace.stack_element(2, row + 1),
            main_trace.stack_element(3, row + 1),
        ],
        source: "pipe req 1",
    };
    let mem_req_2 = MemoryWordMessage {
        op_label,
        ctx,
        addr: addr + FOUR,
        clk,
        word: [
            main_trace.stack_element(4, row + 1),
            main_trace.stack_element(5, row + 1),
            main_trace.stack_element(6, row + 1),
            main_trace.stack_element(7, row + 1),
        ],
        source: "pipe req 2",
    };

    let combined_value = mem_req_1.value(alphas) * mem_req_2.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(mem_req_1), alphas);
        _debugger.add_request(alloc::boxed::Box::new(mem_req_2), alphas);
    }

    combined_value
}

/// Builds `HORNERBASE` requests made to the memory chiplet.
pub(super) fn build_hornerbase_eval_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let eval_point_0 = main_trace.helper_register(0, row);
    let eval_point_1 = main_trace.helper_register(1, row);
    let eval_point_ptr = main_trace.stack_element(13, row);
    let op_label = Felt::from_u8(MEMORY_READ_ELEMENT_LABEL);

    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    let mem_req_0 = MemoryElementMessage {
        op_label,
        ctx,
        addr: eval_point_ptr,
        clk,
        element: eval_point_0,
    };
    let mem_req_1 = MemoryElementMessage {
        op_label,
        ctx,
        addr: eval_point_ptr + ONE,
        clk,
        element: eval_point_1,
    };

    let value = mem_req_0.value(alphas) * mem_req_1.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(mem_req_0), alphas);
        _debugger.add_request(alloc::boxed::Box::new(mem_req_1), alphas);
    }

    value
}

/// Builds `HORNEREXT` requests made to the memory chiplet.
pub(super) fn build_hornerext_eval_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let eval_point_0 = main_trace.helper_register(0, row);
    let eval_point_1 = main_trace.helper_register(1, row);
    let mem_junk_0 = main_trace.helper_register(2, row);
    let mem_junk_1 = main_trace.helper_register(3, row);
    let eval_point_ptr = main_trace.stack_element(13, row);
    let op_label = Felt::from_u8(MEMORY_READ_WORD_LABEL);

    let ctx = main_trace.ctx(row);
    let clk = main_trace.clk(row);

    let mem_req = MemoryWordMessage {
        op_label,
        ctx,
        addr: eval_point_ptr,
        clk,
        word: [eval_point_0, eval_point_1, mem_junk_0, mem_junk_1],
        source: "hornerext_eval_* req",
    };

    let value = mem_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(mem_req), alphas);
    }

    value
}

// RESPONSES
// ================================================================================================

/// Builds the response from the memory chiplet at `row`.
pub(super) fn build_memory_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let access_type = main_trace.chiplet_selector_4(row);
    let op_label = {
        let is_read = main_trace.chiplet_selector_3(row);
        get_memory_op_label(is_read, access_type)
    };
    let ctx = main_trace.chiplet_memory_ctx(row);
    let clk = main_trace.chiplet_memory_clk(row);
    let addr = {
        let word = main_trace.chiplet_memory_word(row);
        let idx0 = main_trace.chiplet_memory_idx0(row);
        let idx1 = main_trace.chiplet_memory_idx1(row);

        word + idx1.double() + idx0
    };

    if access_type == MEMORY_ACCESS_ELEMENT {
        let idx0 = main_trace.chiplet_memory_idx0(row);
        let idx1 = main_trace.chiplet_memory_idx1(row);

        let element = if idx1 == ZERO && idx0 == ZERO {
            main_trace.chiplet_memory_value_0(row)
        } else if idx1 == ZERO && idx0 == ONE {
            main_trace.chiplet_memory_value_1(row)
        } else if idx1 == ONE && idx0 == ZERO {
            main_trace.chiplet_memory_value_2(row)
        } else if idx1 == ONE && idx0 == ONE {
            main_trace.chiplet_memory_value_3(row)
        } else {
            panic!("Invalid word indices. idx0: {idx0}, idx1: {idx1}");
        };

        let message = MemoryElementMessage { op_label, ctx, addr, clk, element };

        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);

        value
    } else if access_type == MEMORY_ACCESS_WORD {
        let value0 = main_trace.chiplet_memory_value_0(row);
        let value1 = main_trace.chiplet_memory_value_1(row);
        let value2 = main_trace.chiplet_memory_value_2(row);
        let value3 = main_trace.chiplet_memory_value_3(row);

        let message = MemoryWordMessage {
            op_label,
            ctx,
            addr,
            clk,
            word: [value0, value1, value2, value3],
            source: "memory chiplet",
        };

        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);

        value
    } else {
        panic!("Invalid memory element/word column value: {access_type}");
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the operation unique label for memory operations.
///
/// The memory selector flags are `[1, 1, 0, is_read, is_word_access]`.
/// The flag is derived as the big-endian representation of these flags, plus one.
/// They are also defined in [`chiplets::memory`](miden_air::trace::chiplets::memory).
fn get_memory_op_label(is_read: Felt, is_word_access: Felt) -> Felt {
    let is_read = (is_read == ONE) as u8;
    let is_word_access = (is_word_access == ONE) as u8;

    const MEMORY_SELECTOR_FLAG_BASE: u8 = 0b011 + 1;
    const OP_FLAG_SHIFT: u8 = 3;

    let op_flag = is_read + 2 * is_word_access;

    Felt::from_u8(MEMORY_SELECTOR_FLAG_BASE + (op_flag << OP_FLAG_SHIFT))
}

// MESSAGES
// ===============================================================================================

pub struct MemoryWordMessage {
    pub op_label: Felt,
    pub ctx: Felt,
    pub addr: Felt,
    pub clk: Felt,
    pub word: [Felt; 4],
    pub source: &'static str,
}

impl<E> BusMessage<E> for MemoryWordMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + build_value(
                &alphas[1..9],
                [
                    self.op_label,
                    self.ctx,
                    self.addr,
                    self.clk,
                    self.word[0],
                    self.word[1],
                    self.word[2],
                    self.word[3],
                ],
            )
    }

    fn source(&self) -> &str {
        self.source
    }
}

impl Display for MemoryWordMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ op_label: {}, ctx: {}, addr: {}, clk: {}, word: {:?} }}",
            self.op_label, self.ctx, self.addr, self.clk, self.word
        )
    }
}

pub struct MemoryElementMessage {
    pub op_label: Felt,
    pub ctx: Felt,
    pub addr: Felt,
    pub clk: Felt,
    pub element: Felt,
}

impl<E> BusMessage<E> for MemoryElementMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + build_value(
                &alphas[1..6],
                [self.op_label, self.ctx, self.addr, self.clk, self.element],
            )
    }

    fn source(&self) -> &str {
        "memory element"
    }
}

impl Display for MemoryElementMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ op_label: {}, ctx: {}, addr: {}, clk: {}, element: {} }}",
            self.op_label, self.ctx, self.addr, self.clk, self.element
        )
    }
}
