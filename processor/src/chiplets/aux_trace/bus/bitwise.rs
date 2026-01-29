use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::trace::{
    MainTrace, RowIndex, chiplets::bitwise::OP_CYCLE_LEN as BITWISE_OP_CYCLE_LEN,
};
use miden_core::{Felt, ONE, ZERO, field::ExtensionField};

use super::get_op_label;
use crate::{
    chiplets::aux_trace::build_value,
    debug::{BusDebugger, BusMessage},
};

// REQUESTS
// ==============================================================================================

/// Builds requests made to the bitwise chiplet. This can be either a request for the computation
/// of a `XOR` or an `AND` operation.
pub(super) fn build_bitwise_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    is_xor: Felt,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    // NOTE: The processor calls chiplets.bitwise.u32and(stack[0], stack[1]), so
    // the chiplet stores a_col = stack[0] (top) and b_col = stack[1] (second).
    // The request must use the same order to match the chiplet's response.
    let bitwise_request_message = BitwiseMessage {
        op_label: get_op_label(ONE, ZERO, is_xor, ZERO),
        a: main_trace.stack_element(0, row),
        b: main_trace.stack_element(1, row),
        z: main_trace.stack_element(0, row + 1),
        source: if is_xor == ONE { "u32xor" } else { "u32and" },
    };

    let value = bitwise_request_message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(bitwise_request_message), alphas);

    value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the bitwise chiplet at `row`.
pub(super) fn build_bitwise_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let is_xor = main_trace.chiplet_selector_2(row);
    if row.as_usize() % BITWISE_OP_CYCLE_LEN == BITWISE_OP_CYCLE_LEN - 1 {
        let bitwise_message = BitwiseMessage {
            op_label: get_op_label(ONE, ZERO, is_xor, ZERO),
            a: main_trace.chiplet_bitwise_a(row),
            b: main_trace.chiplet_bitwise_b(row),
            z: main_trace.chiplet_bitwise_z(row),
            source: "bitwise chiplet",
        };

        let value = bitwise_message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(bitwise_message), alphas);

        value
    } else {
        E::ONE
    }
}

// MESSAGE
// ===============================================================================================

pub struct BitwiseMessage {
    pub op_label: Felt,
    pub a: Felt,
    pub b: Felt,
    pub z: Felt,
    pub source: &'static str,
}

impl<E> BusMessage<E> for BitwiseMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        alphas[0] + build_value(&alphas[1..5], [self.op_label, self.a, self.b, self.z])
    }

    fn source(&self) -> &str {
        self.source
    }
}

impl Display for BitwiseMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ op_label: {}, a: {}, b: {}, z: {} }}",
            self.op_label, self.a, self.b, self.z
        )
    }
}
