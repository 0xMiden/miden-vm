use miden_air::trace::RowIndex;
use miden_core::{field::ExtensionField, operations::opcodes};

use super::{AuxColumnBuilder, Felt, MainTrace, ONE, ZERO};
use crate::{debug::BusDebugger, trace::utils::Challenges};

// BLOCK STACK TABLE COLUMN BUILDER
// ================================================================================================

/// Builds the execution trace of the decoder's `p1` column which describes the state of the block
/// stack table via multiset checks.
#[derive(Default)]
pub struct BlockStackColumnBuilder {}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for BlockStackColumnBuilder {
    /// Removes a row from the block stack table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            opcodes::RESPAN => get_block_stack_table_respan_multiplicand(main_trace, i, challenges),
            opcodes::END => get_block_stack_table_end_multiplicand(main_trace, i, challenges),
            _ => E::ONE,
        }
    }

    /// Adds a row to the block stack table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            opcodes::JOIN
            | opcodes::SPLIT
            | opcodes::SPAN
            | opcodes::DYN
            | opcodes::DYNCALL
            | opcodes::LOOP
            | opcodes::RESPAN
            | opcodes::CALL
            | opcodes::SYSCALL => {
                get_block_stack_table_inclusion_multiplicand(main_trace, i, challenges, op_code)
            },
            _ => E::ONE,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the multiplicand representing the removal of a row from the block stack table when
/// encountering a RESPAN operation.
fn get_block_stack_table_respan_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.decoder_hasher_state_element(1, i + 1);
    let is_loop = ZERO;

    challenges.encode([block_id, parent_id, is_loop])
}

/// Computes the multiplicand representing the removal of a row from the block stack table when
/// encountering an END operation.
fn get_block_stack_table_end_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.addr(i + 1);
    let is_loop = main_trace.is_loop_flag(i);

    if main_trace.is_call_flag(i) == ONE || main_trace.is_syscall_flag(i) == ONE {
        let parent_ctx = main_trace.ctx(i + 1);
        let parent_stack_depth = main_trace.stack_depth(i + 1);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i + 1);
        let parent_fn_hash = main_trace.fn_hash(i + 1);

        challenges.encode([
            block_id,
            parent_id,
            is_loop,
            parent_ctx,
            parent_stack_depth,
            parent_next_overflow_addr,
            parent_fn_hash[0],
            parent_fn_hash[1],
            parent_fn_hash[2],
            parent_fn_hash[3],
        ])
    } else {
        challenges.encode([block_id, parent_id, is_loop])
    }
}

/// Computes the multiplicand representing the inclusion of a new row to the block stack table.
fn get_block_stack_table_inclusion_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
    op_code: u8,
) -> E {
    let block_id = main_trace.addr(i + 1);
    let parent_id = if op_code == opcodes::RESPAN {
        main_trace.decoder_hasher_state_element(1, i + 1)
    } else {
        main_trace.addr(i)
    };
    let is_loop = if op_code == opcodes::LOOP {
        main_trace.stack_element(0, i)
    } else {
        ZERO
    };

    if op_code == opcodes::CALL || op_code == opcodes::SYSCALL {
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.stack_depth(i);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i);
        let parent_fn_hash = main_trace.fn_hash(i);
        challenges.encode([
            block_id,
            parent_id,
            is_loop,
            parent_ctx,
            parent_stack_depth,
            parent_next_overflow_addr,
            parent_fn_hash[0],
            parent_fn_hash[1],
            parent_fn_hash[2],
            parent_fn_hash[3],
        ])
    } else if op_code == opcodes::DYNCALL {
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.decoder_hasher_state_element(4, i);
        let parent_next_overflow_addr = main_trace.decoder_hasher_state_element(5, i);
        let parent_fn_hash = main_trace.fn_hash(i);
        challenges.encode([
            block_id,
            parent_id,
            is_loop,
            parent_ctx,
            parent_stack_depth,
            parent_next_overflow_addr,
            parent_fn_hash[0],
            parent_fn_hash[1],
            parent_fn_hash[2],
            parent_fn_hash[3],
        ])
    } else {
        challenges.encode([block_id, parent_id, is_loop])
    }
}
