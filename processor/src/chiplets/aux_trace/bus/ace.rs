use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::{RowIndex, trace::main_trace::MainTrace};
use vm_core::{Felt, FieldElement, ONE};

use super::build_value;
use crate::debug::{BusDebugger, BusMessage};

/// Unique label ACE operation.
pub const ACE_LABEL: Felt = Felt::new(0b11101_u64);

// REQUESTS
// ==============================================================================================

/// Builds requests made to the arithmetic circuit evaluation chiplet.
pub fn build_ace_chiplet_requests<E: FieldElement<BaseField = Felt>>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let clk = main_trace.clk(row);
    let ctx = main_trace.ctx(row);
    let ptr = main_trace.stack_element(0, row);
    let num_read_rows = main_trace.stack_element(1, row);
    let num_eval_rows = main_trace.stack_element(2, row);

    let ace_request_message = AceMessage {
        op_label: ACE_LABEL,
        clk,
        ctx,
        ptr,
        num_read_rows,
        num_eval_rows,
        source: "ace request",
    };

    let value = ace_request_message.value(alphas);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(ace_request_message), alphas);

    value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the ace chiplet at `row`.
pub fn build_ace_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let start_selector = main_trace.chiplet_ace_start_selector(row);
    if start_selector == ONE {
        let clk = main_trace.chiplet_ace_clk(row);
        let ctx = main_trace.chiplet_ace_ctx(row);
        let ptr = main_trace.chiplet_ace_ptr(row);
        let num_eval_rows = main_trace.chiplet_ace_id_2(row) + ONE;
        let id_0 = main_trace.chiplet_ace_id_0(row);
        let num_read_rows = id_0 + ONE - num_eval_rows;

        let ace_message = AceMessage {
            op_label: ACE_LABEL,
            clk,
            ctx,
            ptr,
            num_read_rows,
            num_eval_rows,
            source: "ace response",
        };
        let value = ace_message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(ace_message), alphas);

        value
    } else {
        E::ONE
    }
}

// MESSAGE
// ===============================================================================================

#[derive(Debug)]
pub struct AceMessage {
    pub op_label: Felt,
    pub clk: Felt,
    pub ctx: Felt,
    pub ptr: Felt,
    pub num_read_rows: Felt,
    pub num_eval_rows: Felt,
    pub source: &'static str,
}

impl<E> BusMessage<E> for AceMessage
where
    E: FieldElement<BaseField = Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + build_value(
                &alphas[1..7],
                [
                    self.op_label,
                    self.clk,
                    self.ctx,
                    self.ptr,
                    self.num_read_rows,
                    self.num_eval_rows,
                ],
            )
    }

    fn source(&self) -> &str {
        self.source
    }
}

impl Display for AceMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{{ op_label: {}, clk: {}, ctx: {}, ptr: {}, num_read_rows: {}, num_eval_rows: {} }}",
            self.op_label, self.clk, self.ctx, self.ptr, self.num_read_rows, self.num_eval_rows
        )
    }
}
