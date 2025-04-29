use alloc::boxed::Box;
use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::{
    RowIndex,
    trace::{
        chiplets::memory::{
            MEMORY_ACCESS_ELEMENT, MEMORY_ACCESS_WORD, MEMORY_READ_ELEMENT_LABEL,
            MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL, MEMORY_WRITE_WORD_LABEL,
        },
        main_trace::MainTrace,
    },
};
use vm_core::{ExtensionField, Felt, ONE, PrimeCharacteristicRing, ZERO, lazy_static};

use super::build_value;
use crate::debug::{BusDebugger, BusMessage};

// CONSTANTS
// ================================================================================================

// TODO(Al)
lazy_static! {
    static ref FOUR: Felt = Felt::from_u8(4);
}
//const FOUR: Felt = Felt::from_u8(4);

// REQUESTS
// ================================================================================================

/// Builds `MLOADW` and `MSTOREW` requests made to the memory chiplet.
pub(super) fn build_mem_mloadw_mstorew_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    op_label: u8,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let word = [
        main_trace.stack_element(3, row + 1),
        main_trace.stack_element(2, row + 1),
        main_trace.stack_element(1, row + 1),
        main_trace.stack_element(0, row + 1),
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
    _debugger.add_request(Box::new(message), alphas);

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
    _debugger.add_request(Box::new(message), alphas);

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

    let mem_req_1 = MemoryWordMessage {
        op_label,
        ctx,
        addr,
        clk,
        word: [
            main_trace.stack_element(7, row + 1),
            main_trace.stack_element(6, row + 1),
            main_trace.stack_element(5, row + 1),
            main_trace.stack_element(4, row + 1),
        ],
        source: "mstream req 1",
    };
    let mem_req_2 = MemoryWordMessage {
        op_label,
        ctx,
        addr: addr + *FOUR,
        clk,
        word: [
            main_trace.stack_element(3, row + 1),
            main_trace.stack_element(2, row + 1),
            main_trace.stack_element(1, row + 1),
            main_trace.stack_element(0, row + 1),
        ],
        source: "mstream req 2",
    };

    let combined_value = mem_req_1.value(alphas) * mem_req_2.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(Box::new(mem_req_1), alphas);
        _debugger.add_request(Box::new(mem_req_2), alphas);
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

    let mem_req_1 = MemoryWordMessage {
        op_label,
        ctx,
        addr,
        clk,
        word: [
            main_trace.stack_element(7, row + 1),
            main_trace.stack_element(6, row + 1),
            main_trace.stack_element(5, row + 1),
            main_trace.stack_element(4, row + 1),
        ],
        source: "pipe req 1",
    };
    let mem_req_2 = MemoryWordMessage {
        op_label,
        ctx,
        addr: addr + *FOUR,
        clk,
        word: [
            main_trace.stack_element(3, row + 1),
            main_trace.stack_element(2, row + 1),
            main_trace.stack_element(1, row + 1),
            main_trace.stack_element(0, row + 1),
        ],
        source: "pipe req 2",
    };

    let combined_value = mem_req_1.value(alphas) * mem_req_2.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(Box::new(mem_req_1), alphas);
        _debugger.add_request(Box::new(mem_req_2), alphas);
    }

    combined_value
}

/// Builds `HORNERBASE` or `HORNEREXT` requests made to the memory chiplet.
pub(super) fn build_horner_eval_request<E: ExtensionField<Felt>>(
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
        source: "horner_eval_* req",
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

        word + idx1 * Felt::TWO + idx0
    };

    let message: Box<dyn BusMessage<E>> = if access_type == MEMORY_ACCESS_ELEMENT {
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

        Box::new(message)
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

        Box::new(message)
    } else {
        panic!("Invalid memory element/word column value: {access_type}");
    };

    let value = message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_response(message, alphas);

    value
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the operation unique label for memory operations.
///
/// The memory operation label is currently the only label that is built differently (or *simpler*)
/// from the other chiplets. We should refactor the other chiplets to use a similar (simpler)
/// approach.
fn get_memory_op_label(is_read: Felt, is_word_access: Felt) -> Felt {
    const MEMORY_SELECTOR: u8 = 0b110;
    // Equivalent to `is_read << 1`
    let is_read_left_shift_1 = is_read + is_read;

    Felt::from_u8(MEMORY_SELECTOR << 2) + is_read_left_shift_1 + is_word_access
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
