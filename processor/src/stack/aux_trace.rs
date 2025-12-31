use alloc::vec::Vec;

use miden_air::trace::{MainTrace, RowIndex};
use miden_core::{OPCODE_DYNCALL, field::ExtensionField};

use super::Felt;
use crate::{debug::BusDebugger, trace::AuxColumnBuilder};

// AUXILIARY TRACE BUILDER
// ================================================================================================

/// Describes how to construct execution traces of stack-related auxiliary trace segment columns
/// (used in multiset checks).
#[derive(Debug, Clone)]
pub struct AuxTraceBuilder;

impl AuxTraceBuilder {
    /// Builds and returns stack auxiliary trace columns. Currently this consists of a single
    /// column p1 describing states of the stack overflow table.
    pub fn build_aux_columns<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> Vec<Vec<E>> {
        let p1 = self.build_aux_column(main_trace, rand_elements);

        debug_assert_eq!(*p1.last().unwrap(), E::ONE);
        vec![p1]
    }
}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for AuxTraceBuilder {
    /// Removes a row from the stack overflow table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let is_left_shift = main_trace.is_left_shift(i);
        let is_dyncall = main_trace.get_op_code(i) == OPCODE_DYNCALL.into();
        let is_non_empty_overflow = main_trace.is_non_empty_overflow(i);

        if is_left_shift && is_non_empty_overflow {
            let b1 = main_trace.parent_overflow_address(i);
            let s15_prime = main_trace.stack_element(15, i + 1);
            let b1_prime = main_trace.parent_overflow_address(i + 1);

            OverflowTableRow::new(b1, s15_prime, b1_prime).to_value(alphas)
        } else if is_dyncall && is_non_empty_overflow {
            let b1 = main_trace.parent_overflow_address(i);
            let s15_prime = main_trace.stack_element(15, i + 1);
            let b1_prime = main_trace.decoder_hasher_state_element(5, i);

            OverflowTableRow::new(b1, s15_prime, b1_prime).to_value(alphas)
        } else {
            E::ONE
        }
    }

    /// Adds a row to the stack overflow table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let is_right_shift = main_trace.is_right_shift(i);

        if is_right_shift {
            let k0 = main_trace.clk(i);
            let s15 = main_trace.stack_element(15, i);
            let b1 = main_trace.parent_overflow_address(i);

            let row = OverflowTableRow::new(k0, s15, b1);
            row.to_value(alphas)
        } else {
            E::ONE
        }
    }
}

// OVERFLOW STACK ROW
// ================================================================================================

/// A single row in the stack overflow table. Each row contains the following values:
/// - The value of the stack item pushed into the overflow stack.
/// - The clock cycle at which the stack item was pushed into the overflow stack.
/// - The clock cycle of the value which was at the top of the overflow stack when this value was
///   pushed onto it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverflowTableRow {
    val: Felt,
    clk: Felt,
    prev: Felt,
}

impl OverflowTableRow {
    pub fn new(clk: Felt, val: Felt, prev: Felt) -> Self {
        Self { val, clk, prev }
    }
}

impl OverflowTableRow {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 4 alpha values.
    pub fn to_value<E: ExtensionField<Felt>>(&self, alphas: &[E]) -> E {
        alphas[0] + alphas[1] * self.clk + alphas[2] * self.val + alphas[3] * self.prev
    }
}
