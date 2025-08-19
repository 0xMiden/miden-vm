use miden_air::{
    RowIndex,
    trace::decoder::{OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS},
};
use miden_core::{OPCODE_PUSH, OPCODE_RESPAN, OPCODE_SPAN};

use super::{AuxColumnBuilder, Felt, FieldElement, MainTrace, ONE};
use crate::debug::BusDebugger;

// OP GROUP TABLE COLUMN
// ================================================================================================

/// Builds the execution trace of the decoder's `p3` column which describes the state of the op
/// group table via multiset checks.
#[derive(Default)]
pub struct OpGroupTableColumnBuilder {}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for OpGroupTableColumnBuilder {
    /// Removes a row from the block hash table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let delete_group_flag = main_trace.delta_group_count(i) * main_trace.is_in_span(i);

        if delete_group_flag == ONE {
            get_op_group_table_removal_multiplicand(main_trace, i, alphas)
        } else {
            E::ONE
        }
    }

    /// Adds a row to the block hash table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_int() as u8;

        match op_code {
            OPCODE_SPAN | OPCODE_RESPAN => {
                get_op_group_table_inclusion_multiplicand(main_trace, i, alphas)
            },
            _ => E::ONE,
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the multiplicand representing the inclusion of a new row to the op group table.
fn get_op_group_table_inclusion_multiplicand<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    alphas: &[E],
) -> E {
    let block_id = main_trace.addr(i + 1);
    let group_count = main_trace.group_count(i);
    let op_batch_flag = main_trace.op_batch_flag(i);

    if op_batch_flag == OP_BATCH_8_GROUPS {
        let h = main_trace.decoder_hasher_state(i);
        (1..8_u8).fold(E::ONE, |acc, k| {
            acc * (alphas[0]
                + alphas[1].mul_base(block_id)
                + alphas[2].mul_base(group_count - Felt::from(k))
                + alphas[3].mul_base(h[k as usize]))
        })
    } else if op_batch_flag == OP_BATCH_4_GROUPS {
        let h = main_trace.decoder_hasher_state_first_half(i);
        (1..4_u8).fold(E::ONE, |acc, k| {
            acc * (alphas[0]
                + alphas[1].mul_base(block_id)
                + alphas[2].mul_base(group_count - Felt::from(k))
                + alphas[3].mul_base(h[k as usize]))
        })
    } else if op_batch_flag == OP_BATCH_2_GROUPS {
        let h = main_trace.decoder_hasher_state_first_half(i);
        alphas[0]
            + alphas[1].mul_base(block_id)
            + alphas[2].mul_base(group_count - ONE)
            + alphas[3].mul_base(h[1])
    } else {
        E::ONE
    }
}

/// Computes the multiplicand representing the removal of a row from the op group table.
fn get_op_group_table_removal_multiplicand<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    alphas: &[E],
) -> E {
    let group_count = main_trace.group_count(i);
    let block_id = main_trace.addr(i);
    let group_value = {
        let op_code = main_trace.get_op_code(i);

        if op_code == Felt::from(OPCODE_PUSH) {
            main_trace.stack_element(0, i + 1)
        } else {
            let h0 = main_trace.decoder_hasher_state_first_half(i + 1)[0];

            let op_prime = main_trace.get_op_code(i + 1);
            h0.mul_small(1 << 7) + op_prime
        }
    };

    alphas[0]
        + alphas[1].mul_base(block_id)
        + alphas[2].mul_base(group_count)
        + alphas[3].mul_base(group_value)
}
