use alloc::vec::Vec;

use miden_air::trace::{Challenges, MainTrace, RowIndex, bus_types::STACK_OVERFLOW_TABLE};
use miden_core::{field::ExtensionField, operations::opcodes};

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
        challenges: &Challenges<E>,
    ) -> Vec<Vec<E>> {
        let p1 = self.build_aux_column(main_trace, challenges);

        debug_assert_eq!(*p1.last().unwrap(), E::ONE);
        vec![p1]
    }
}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for AuxTraceBuilder {
    /// Removes a row from the stack overflow table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let is_left_shift = main_trace.is_left_shift(i);
        let is_dyncall = main_trace.get_op_code(i) == Felt::from_u8(opcodes::DYNCALL);
        let is_non_empty_overflow = main_trace.is_non_empty_overflow(i);

        if is_left_shift && is_non_empty_overflow {
            let b1 = main_trace.parent_overflow_address(i);
            let s15_prime = main_trace.stack_element(15, i + 1);
            let b1_prime = main_trace.parent_overflow_address(i + 1);

            OverflowTableRow::new(b1, s15_prime, b1_prime).to_value(challenges)
        } else if is_dyncall && is_non_empty_overflow {
            let b1 = main_trace.parent_overflow_address(i);
            let s15_prime = main_trace.stack_element(15, i + 1);
            let b1_prime = main_trace.decoder_hasher_state_element(5, i);

            OverflowTableRow::new(b1, s15_prime, b1_prime).to_value(challenges)
        } else {
            E::ONE
        }
    }

    /// Adds a row to the stack overflow table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let is_right_shift = main_trace.is_right_shift(i);

        if is_right_shift {
            let k0 = main_trace.clk(i);
            let s15 = main_trace.stack_element(15, i);
            let b1 = main_trace.parent_overflow_address(i);

            let row = OverflowTableRow::new(k0, s15, b1);
            row.to_value(challenges)
        } else {
            E::ONE
        }
    }

    #[cfg(any(test, feature = "bus-debugger"))]
    fn enforce_bus_balance(&self) -> bool {
        true
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
    pub fn to_value<E: ExtensionField<Felt>>(&self, challenges: &Challenges<E>) -> E {
        challenges.encode(STACK_OVERFLOW_TABLE, [self.clk, self.val, self.prev])
    }
}
