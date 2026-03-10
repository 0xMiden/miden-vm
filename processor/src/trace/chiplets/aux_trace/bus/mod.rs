use ace::{build_ace_chiplet_requests, build_ace_chiplet_responses};
use bitwise::{build_bitwise_chiplet_responses, build_bitwise_request};
use hasher::{
    ControlBlockRequestMessage, build_control_block_request, build_end_block_request,
    build_hasher_chiplet_responses, build_hperm_request, build_log_precompile_request,
    build_mpverify_request, build_mrupdate_request, build_respan_block_request,
    build_span_block_request,
};
use kernel::{KernelRomMessage, build_kernel_chiplet_responses};
use memory::{
    build_crypto_stream_request, build_dyn_dyncall_callee_hash_read_request,
    build_fmp_initialization_write_request, build_hornerbase_eval_request,
    build_hornerext_eval_request, build_mem_mload_mstore_request, build_mem_mloadw_mstorew_request,
    build_memory_chiplet_responses, build_mstream_request, build_pipe_request,
};
use miden_air::trace::{
    MainTrace, RowIndex,
    chiplets::{
        hasher::LINEAR_HASH_LABEL,
        memory::{
            MEMORY_READ_ELEMENT_LABEL, MEMORY_READ_WORD_LABEL, MEMORY_WRITE_ELEMENT_LABEL,
            MEMORY_WRITE_WORD_LABEL,
        },
    },
};
use miden_core::{ONE, ZERO, field::ExtensionField, operations::opcodes, program::Kernel};

use super::Felt;
use crate::{
    debug::{BusDebugger, BusMessage},
    trace::{AuxColumnBuilder, utils::Challenges},
};

mod ace;
mod bitwise;
mod hasher;
mod kernel;
mod memory;

use kernel::build_kernel_init_requests;
pub use memory::{build_ace_memory_read_element_request, build_ace_memory_read_word_request};

// BUS COLUMN BUILDER
// ================================================================================================

/// Describes how to construct the execution trace of the chiplets bus auxiliary trace column.
pub struct BusColumnBuilder<'a> {
    kernel: &'a Kernel,
}

impl<'a> BusColumnBuilder<'a> {
    pub(super) fn new(kernel: &'a Kernel) -> Self {
        Self { kernel }
    }
}

impl<E> AuxColumnBuilder<E> for BusColumnBuilder<'_>
where
    E: ExtensionField<Felt>,
{
    /// Constructs the requests made by the VM-components to the chiplets at `row`.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(row);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            opcodes::JOIN | opcodes::SPLIT | opcodes::LOOP => build_control_block_request(
                main_trace,
                main_trace.decoder_hasher_state(row),
                op_code_felt,
                challenges,
                row,
                debugger,
            ),
            opcodes::CALL => {
                build_call_request(main_trace, op_code_felt, challenges, row, debugger)
            },
            opcodes::DYN => build_dyn_request(main_trace, op_code_felt, challenges, row, debugger),
            opcodes::DYNCALL => {
                build_dyncall_request(main_trace, op_code_felt, challenges, row, debugger)
            },
            opcodes::SYSCALL => {
                build_syscall_block_request(main_trace, op_code_felt, challenges, row, debugger)
            },
            opcodes::SPAN => build_span_block_request(main_trace, challenges, row, debugger),
            opcodes::RESPAN => build_respan_block_request(main_trace, challenges, row, debugger),
            opcodes::END => build_end_block_request(main_trace, challenges, row, debugger),
            opcodes::U32AND => build_bitwise_request(main_trace, ZERO, challenges, row, debugger),
            opcodes::U32XOR => build_bitwise_request(main_trace, ONE, challenges, row, debugger),
            opcodes::MLOADW => build_mem_mloadw_mstorew_request(
                main_trace,
                MEMORY_READ_WORD_LABEL,
                challenges,
                row,
                debugger,
            ),
            opcodes::MSTOREW => build_mem_mloadw_mstorew_request(
                main_trace,
                MEMORY_WRITE_WORD_LABEL,
                challenges,
                row,
                debugger,
            ),
            opcodes::MLOAD => build_mem_mload_mstore_request(
                main_trace,
                MEMORY_READ_ELEMENT_LABEL,
                challenges,
                row,
                debugger,
            ),
            opcodes::MSTORE => build_mem_mload_mstore_request(
                main_trace,
                MEMORY_WRITE_ELEMENT_LABEL,
                challenges,
                row,
                debugger,
            ),
            opcodes::HORNERBASE => {
                build_hornerbase_eval_request(main_trace, challenges, row, debugger)
            },
            opcodes::HORNEREXT => {
                build_hornerext_eval_request(main_trace, challenges, row, debugger)
            },
            opcodes::MSTREAM => build_mstream_request(main_trace, challenges, row, debugger),
            opcodes::CRYPTOSTREAM => build_crypto_stream_request(main_trace, challenges, row, debugger),
            opcodes::HPERM => build_hperm_request(main_trace, challenges, row, debugger),
            opcodes::LOGPRECOMPILE => {
                build_log_precompile_request(main_trace, challenges, row, debugger)
            },
            opcodes::MPVERIFY => build_mpverify_request(main_trace, challenges, row, debugger),
            opcodes::MRUPDATE => build_mrupdate_request(main_trace, challenges, row, debugger),
            opcodes::PIPE => build_pipe_request(main_trace, challenges, row, debugger),
            opcodes::EVALCIRCUIT => {
                build_ace_chiplet_requests(main_trace, challenges, row, debugger)
            },
            _ => E::ONE,
        }
    }

    /// Constructs the responses from the chiplets to the other VM-components at `row`.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E {
        if main_trace.is_hash_row(row) {
            build_hasher_chiplet_responses(main_trace, row, challenges, debugger)
        } else if main_trace.is_bitwise_row(row) {
            build_bitwise_chiplet_responses(main_trace, row, challenges, debugger)
        } else if main_trace.is_memory_row(row) {
            build_memory_chiplet_responses(main_trace, row, challenges, debugger)
        } else if main_trace.is_ace_row(row) {
            build_ace_chiplet_responses(main_trace, row, challenges, debugger)
        } else if main_trace.is_kernel_row(row) {
            build_kernel_chiplet_responses(main_trace, row, challenges, debugger)
        } else {
            E::ONE
        }
    }

    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        challenges: &Challenges<E>,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        build_kernel_init_requests(self.kernel.proc_hashes(), challenges, _debugger)
    }
}

// CHIPLETS REQUESTS TO MORE THAN ONE CHIPLET
// ================================================================================================

/// Encodes a control block request without hasher state (optimized for DYN/DYNCALL).
///
/// Standard control block encoding includes state[0..7] which are always zero for DYN/DYNCALL.
/// This optimization skips those 8 multiplications.
///
/// Encoding: `alpha + beta^0*label + beta^1*addr + beta^12*op_code`
/// where beta^12 is the capacity domain element at coeffs[13].
#[inline(always)]
fn encode_control_block_without_state<E>(challenges: &Challenges<E>, addr: Felt, op_code: Felt) -> E
where
    E: ExtensionField<Felt>,
{
    use miden_air::trace::bus_message;

    challenges.alpha
        + challenges.beta_powers[bus_message::LABEL_IDX] * Felt::from_u8(LINEAR_HASH_LABEL + 16)
        + challenges.beta_powers[bus_message::ADDR_IDX] * addr
        + challenges.beta_powers[bus_message::CAPACITY_DOMAIN_IDX] * op_code
}

/// Builds requests made on a `DYN` operation.
fn build_dyn_request<E>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let control_block_req_value =
        encode_control_block_without_state(challenges, main_trace.addr(row + 1), op_code_felt);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let control_block_req = ControlBlockRequestMessage {
            transition_label: Felt::from_u8(LINEAR_HASH_LABEL + 16),
            addr_next: main_trace.addr(row + 1),
            op_code: op_code_felt,
            // DYN encodes without state; keep it zeroed to match the request encoding.
            decoder_hasher_state: [ZERO; 8],
        };
        _debugger.add_request(alloc::boxed::Box::new(control_block_req), challenges);
    }

    let callee_hash_read_req_value = build_dyn_dyncall_callee_hash_read_request(
        main_trace,
        op_code_felt,
        challenges,
        row,
        _debugger,
    );

    control_block_req_value * callee_hash_read_req_value
}

/// Builds requests made on a `DYNCALL` operation.
fn build_dyncall_request<E>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let control_block_req_value =
        encode_control_block_without_state(challenges, main_trace.addr(row + 1), op_code_felt);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        let control_block_req = ControlBlockRequestMessage {
            transition_label: Felt::from_u8(LINEAR_HASH_LABEL + 16),
            addr_next: main_trace.addr(row + 1),
            op_code: op_code_felt,
            // DYNCALL encodes without state; keep it zeroed to match the request encoding.
            decoder_hasher_state: [ZERO; 8],
        };
        _debugger.add_request(alloc::boxed::Box::new(control_block_req), challenges);
    }

    let callee_hash_read_req_value = build_dyn_dyncall_callee_hash_read_request(
        main_trace,
        op_code_felt,
        challenges,
        row,
        _debugger,
    );

    let fmp_write_req_value =
        build_fmp_initialization_write_request(main_trace, challenges, row, _debugger);

    control_block_req_value * callee_hash_read_req_value * fmp_write_req_value
}

fn build_call_request<E>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let control_block_req_value = build_control_block_request(
        main_trace,
        main_trace.decoder_hasher_state(row),
        op_code_felt,
        challenges,
        row,
        _debugger,
    );

    let fmp_write_req_value =
        build_fmp_initialization_write_request(main_trace, challenges, row, _debugger);

    control_block_req_value * fmp_write_req_value
}

/// Builds requests made to kernel ROM chiplet when initializing a syscall block.
fn build_syscall_block_request<E>(
    main_trace: &MainTrace,
    op_code_felt: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let control_block_req = ControlBlockRequestMessage {
        transition_label: Felt::from_u8(LINEAR_HASH_LABEL + 16),
        addr_next: main_trace.addr(row + 1),
        op_code: op_code_felt,
        decoder_hasher_state: main_trace.decoder_hasher_state(row),
    };

    let kernel_rom_req = KernelRomMessage {
        kernel_proc_digest: main_trace.decoder_hasher_state(row)[0..4].try_into().unwrap(),
    };

    let combined_value = control_block_req.value(challenges) * kernel_rom_req.value(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    {
        _debugger.add_request(alloc::boxed::Box::new(control_block_req), challenges);
        _debugger.add_request(alloc::boxed::Box::new(kernel_rom_req), challenges);
    }

    combined_value
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the operation unique label.
#[inline(always)]
fn get_op_label(s0: Felt, s1: Felt, s2: Felt, s3: Felt) -> Felt {
    s3 * Felt::from_u16(1 << 3) + s2 * Felt::from_u16(1 << 2) + s1 * Felt::from_u16(2) + s0 + ONE
}
