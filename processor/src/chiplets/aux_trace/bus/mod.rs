use bitwise::{build_bitwise_chiplet_responses, build_bitwise_request};
use hasher::{
    build_control_block_request, build_end_block_request, build_hasher_chiplet_responses,
    build_hperm_request, build_mpverify_request, build_mrupdate_request,
    build_respan_block_request, build_span_block_request,
};
use kernel::build_kernel_chiplet_responses;
use memory::{
    build_mem_mload_mstore_request, build_mem_mloadw_mstorew_request,
    build_memory_chiplet_responses, build_mstream_request, build_pipe_request,
    build_rcomb_base_request,
};
use messages::{ControlBlockRequestMessage, KernelRomMessage, MemoryWordMessage};
use miden_air::{
    trace::{
        chiplets::{
            hasher::LINEAR_HASH_LABEL,
            memory::{
                MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
                MEMORY_WRITE_WORD_LABEL,
            },
        },
        main_trace::MainTrace,
    },
    RowIndex,
};
use vm_core::{
    ONE, OPCODE_CALL, OPCODE_DYN, OPCODE_DYNCALL, OPCODE_END, OPCODE_HPERM, OPCODE_JOIN,
    OPCODE_LOOP, OPCODE_MLOAD, OPCODE_MLOADW, OPCODE_MPVERIFY, OPCODE_MRUPDATE, OPCODE_MSTORE,
    OPCODE_MSTOREW, OPCODE_MSTREAM, OPCODE_PIPE, OPCODE_RCOMBBASE, OPCODE_RESPAN, OPCODE_SPAN,
    OPCODE_SPLIT, OPCODE_SYSCALL, OPCODE_U32AND, OPCODE_U32XOR, ZERO,
};

use super::{Felt, FieldElement};
use crate::{
    debug::{BusDebugger, BusMessage},
    trace::AuxColumnBuilder,
};

mod bitwise;
mod hasher;
mod kernel;
mod memory;
mod messages;

// BUS COLUMN BUILDER
// ================================================================================================

/// Describes how to construct the execution trace of the chiplets bus auxiliary trace column.
#[derive(Default)]
pub struct BusColumnBuilder {}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for BusColumnBuilder {
    /// Constructs the requests made by the VM-components to the chiplets at `row`.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E
    where
        E: FieldElement<BaseField = Felt>,
    {
        let op_code_felt = main_trace.get_op_code(row);
        let op_code = op_code_felt.as_int() as u8;

        match op_code {
            OPCODE_JOIN | OPCODE_SPLIT | OPCODE_LOOP | OPCODE_CALL => build_control_block_request(
                main_trace,
                main_trace.decoder_hasher_state(row),
                op_code_felt,
                alphas,
                row,
                debugger,
            ),
            OPCODE_DYN | OPCODE_DYNCALL => {
                build_dyn_block_request(main_trace, op_code_felt, alphas, row, debugger)
            },
            OPCODE_SYSCALL => {
                build_syscall_block_request(main_trace, op_code_felt, alphas, row, debugger)
            },
            OPCODE_SPAN => build_span_block_request(main_trace, alphas, row, debugger),
            OPCODE_RESPAN => build_respan_block_request(main_trace, alphas, row, debugger),
            OPCODE_END => build_end_block_request(main_trace, alphas, row, debugger),
            OPCODE_U32AND => build_bitwise_request(main_trace, ZERO, alphas, row, debugger),
            OPCODE_U32XOR => build_bitwise_request(main_trace, ONE, alphas, row, debugger),
            OPCODE_MLOADW => build_mem_mloadw_mstorew_request(
                main_trace,
                MEMORY_READ_WORD_LABEL,
                alphas,
                row,
                debugger,
            ),
            OPCODE_MSTOREW => build_mem_mloadw_mstorew_request(
                main_trace,
                MEMORY_WRITE_WORD_LABEL,
                alphas,
                row,
                debugger,
            ),
            OPCODE_MLOAD => build_mem_mload_mstore_request(
                main_trace,
                MEMORY_READ_ELEMENT_LABEL,
                alphas,
                row,
                debugger,
            ),
            OPCODE_MSTORE => build_mem_mload_mstore_request(
                main_trace,
                MEMORY_WRITE_ELEMENT_LABEL,
                alphas,
                row,
                debugger,
            ),
            OPCODE_MSTREAM => build_mstream_request(main_trace, alphas, row, debugger),
            OPCODE_RCOMBBASE => build_rcomb_base_request(main_trace, alphas, row, debugger),
            OPCODE_HPERM => build_hperm_request(main_trace, alphas, row, debugger),
            OPCODE_MPVERIFY => build_mpverify_request(main_trace, alphas, row, debugger),
            OPCODE_MRUPDATE => build_mrupdate_request(main_trace, alphas, row, debugger),
            OPCODE_PIPE => build_pipe_request(main_trace, alphas, row, debugger),
            _ => E::ONE,
        }
    }

    /// Constructs the responses from the chiplets to the other VM-components at `row`.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E
    where
        E: FieldElement<BaseField = Felt>,
    {
        if main_trace.is_hash_row(row) {
            build_hasher_chiplet_responses(main_trace, row, alphas, debugger)
        } else if main_trace.is_bitwise_row(row) {
            build_bitwise_chiplet_responses(main_trace, row, alphas, debugger)
        } else if main_trace.is_memory_row(row) {
            build_memory_chiplet_responses(main_trace, row, alphas, debugger)
        } else if main_trace.is_kernel_row(row) {
            build_kernel_chiplet_responses(main_trace, row, alphas, debugger)
        } else {
            E::ONE
        }
    }
}

// CHIPLETS REQUESTS TO MORE THAN ONE CHIPLET
// ================================================================================================

/// Builds requests made on a `DYN` or `DYNCALL` operation.
fn build_dyn_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let control_block_req = ControlBlockRequestMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: main_trace.addr(row + 1),
        op_code: op_code_felt,
        decoder_hasher_state: [ZERO; 8],
    };

    let memory_req = MemoryWordMessage {
        op_label: Felt::from(MEMORY_READ_WORD_LABEL),
        ctx: main_trace.ctx(row),
        addr: main_trace.stack_element(0, row),
        clk: main_trace.clk(row),
        word: main_trace.decoder_hasher_state_first_half(row),
        source: if op_code_felt == OPCODE_DYNCALL.into() {
            "dyncall"
        } else {
            "dyn"
        },
    };

    let combined_value = control_block_req.value(alphas) * memory_req.value(alphas);
    #[cfg(any(test, feature = "bus-debugger"))]
    {
        use alloc::boxed::Box;
        _debugger.add_request(Box::new(control_block_req), alphas);
        _debugger.add_request(Box::new(memory_req), alphas);
    }

    combined_value
}

/// Builds requests made to kernel ROM chiplet when initializing a syscall block.
fn build_syscall_block_request<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let control_block_req = ControlBlockRequestMessage {
        transition_label: Felt::from(LINEAR_HASH_LABEL + 16),
        addr_next: main_trace.addr(row + 1),
        op_code: op_code_felt,
        decoder_hasher_state: main_trace.decoder_hasher_state(row),
    };

    let kernel_rom_req = KernelRomMessage {
        kernel_proc_digest: main_trace.decoder_hasher_state(row)[0..4].try_into().unwrap(),
    };

    let combined_value = control_block_req.value(alphas) * kernel_rom_req.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(control_block_req), alphas);
        _debugger.add_request(alloc::boxed::Box::new(kernel_rom_req), alphas);
    }

    combined_value
}

// HELPER FUNCTIONS
// ================================================================================================

/// Runs an inner product between the alphas and the elements.
#[inline(always)]
fn build_value<E: FieldElement<BaseField = Felt>, const N: usize>(
    alphas: &[E],
    elements: [Felt; N],
) -> E {
    debug_assert_eq!(alphas.len(), elements.len());
    let mut value = E::ZERO;
    for i in 0..N {
        value += alphas[i].mul_base(elements[i]);
    }
    value
}

/// Returns the operation unique label.
fn get_op_label(s0: Felt, s1: Felt, s2: Felt, s3: Felt) -> Felt {
    s3.mul_small(1 << 3) + s2.mul_small(1 << 2) + s1.mul_small(2) + s0 + ONE
}
