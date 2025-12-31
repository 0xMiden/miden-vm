use miden_air::trace::RowIndex;
use miden_core::{
    OPCODE_CALL, OPCODE_DYN, OPCODE_DYNCALL, OPCODE_END, OPCODE_JOIN, OPCODE_LOOP, OPCODE_RESPAN,
    OPCODE_SPAN, OPCODE_SPLIT, OPCODE_SYSCALL, field::ExtensionField,
};

use super::{AuxColumnBuilder, Felt, MainTrace, ONE, ZERO};
use crate::{PrimeField64, debug::BusDebugger};

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
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            OPCODE_RESPAN => get_block_stack_table_respan_multiplicand(main_trace, i, alphas),
            OPCODE_END => get_block_stack_table_end_multiplicand(main_trace, i, alphas),
            _ => E::ONE,
        }
    }

    /// Adds a row to the block stack table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            OPCODE_JOIN | OPCODE_SPLIT | OPCODE_SPAN | OPCODE_DYN | OPCODE_DYNCALL
            | OPCODE_LOOP | OPCODE_RESPAN | OPCODE_CALL | OPCODE_SYSCALL => {
                get_block_stack_table_inclusion_multiplicand(main_trace, i, alphas, op_code)
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
    alphas: &[E],
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.decoder_hasher_state_element(1, i + 1);
    let is_loop = ZERO;

    // Note: the last 8 elements are set to ZERO, so we omit them here.
    let elements = [ONE, block_id, parent_id, is_loop];

    let mut table_row = E::ZERO;
    for (&alpha, &element) in alphas.iter().zip(elements.iter()) {
        table_row += alpha * element;
    }
    table_row
}

/// Computes the multiplicand representing the removal of a row from the block stack table when
/// encountering an END operation.
fn get_block_stack_table_end_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    alphas: &[E],
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.addr(i + 1);
    let is_loop = main_trace.is_loop_flag(i);

    let elements = if main_trace.is_call_flag(i) == ONE || main_trace.is_syscall_flag(i) == ONE {
        let parent_ctx = main_trace.ctx(i + 1);
        let parent_stack_depth = main_trace.stack_depth(i + 1);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i + 1);
        let parent_fn_hash = main_trace.fn_hash(i + 1);

        [
            ONE,
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
        ]
    } else {
        let mut result = [ZERO; 11];
        result[0] = ONE;
        result[1] = block_id;
        result[2] = parent_id;
        result[3] = is_loop;
        result
    };

    let mut table_row = E::ZERO;
    for (&alpha, &element) in alphas.iter().zip(elements.iter()) {
        table_row += alpha * element;
    }
    table_row
}

/// Computes the multiplicand representing the inclusion of a new row to the block stack table.
fn get_block_stack_table_inclusion_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    alphas: &[E],
    op_code: u8,
) -> E {
    let block_id = main_trace.addr(i + 1);
    let parent_id = if op_code == OPCODE_RESPAN {
        main_trace.decoder_hasher_state_element(1, i + 1)
    } else {
        main_trace.addr(i)
    };
    let is_loop = if op_code == OPCODE_LOOP {
        main_trace.stack_element(0, i)
    } else {
        ZERO
    };
    let elements = if op_code == OPCODE_CALL || op_code == OPCODE_SYSCALL {
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.stack_depth(i);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i);
        let parent_fn_hash = main_trace.fn_hash(i);
        [
            ONE,
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
        ]
    } else if op_code == OPCODE_DYNCALL {
        // dyncall executes a left shift simultaneously with starting a new execution context. The
        // post-shift stack depth and next overflow address are placed in the decoder hasher state
        // registers. Note that these are different from what is written to the B0 and B1 registers
        // in the next row (the first row of the new execution context); the values placed here are
        // the values that will be restored when the new execution context terminates.
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.decoder_hasher_state_element(4, i);
        let parent_next_overflow_addr = main_trace.decoder_hasher_state_element(5, i);
        let parent_fn_hash = main_trace.fn_hash(i);
        [
            ONE,
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
        ]
    } else {
        let mut result = [ZERO; 11];
        result[0] = ONE;
        result[1] = block_id;
        result[2] = parent_id;
        result[3] = is_loop;
        result
    };

    let mut value = E::ZERO;

    for (&alpha, &element) in alphas.iter().zip(elements.iter()) {
        value += alpha * element;
    }
    value
}
