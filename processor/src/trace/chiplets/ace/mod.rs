use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::trace::{RowIndex, chiplets::ace::ACE_CHIPLET_NUM_COLS};
use miden_core::{Felt, ZERO};

use crate::trace::TraceFragment;

mod trace;
pub use trace::CircuitEvaluation;

mod instruction;
#[cfg(test)]
mod tests;

pub const PTR_OFFSET_ELEM: Felt = Felt::ONE;
pub const PTR_OFFSET_WORD: Felt = Felt::new(4);
pub const MAX_NUM_ACE_WIRES: u32 = instruction::MAX_ID;

/// Arithmetic circuit evaluation (ACE) chiplet.
///
/// This is a VM chiplet used to evaluate arithmetic circuits given some input, which is equivalent
/// to evaluating some multi-variate polynomial at a tuple representing the input.
///
/// During the course of the VM execution, we keep track of all calls to the ACE chiplet in an
/// [`CircuitEvaluation`] per call. This is then used to generate the full trace of the ACE chiplet.
#[derive(Debug, Default)]
pub struct Ace {
    circuit_evaluations: BTreeMap<RowIndex, CircuitEvaluation>,
}

impl Ace {
    /// Gets the total trace length of the ACE chiplet.
    pub(crate) fn trace_len(&self) -> usize {
        self.circuit_evaluations.values().map(|eval_ctx| eval_ctx.num_rows()).sum()
    }

    /// Fills the portion of the main trace allocated to the ACE chiplet.
    pub(crate) fn fill_trace(self, trace: &mut TraceFragment) {
        // make sure fragment dimensions are consistent with the dimensions of this trace
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(ACE_CHIPLET_NUM_COLS, trace.width(), "inconsistent trace widths");

        let mut gen_trace: [Vec<Felt>; ACE_CHIPLET_NUM_COLS] = (0..ACE_CHIPLET_NUM_COLS)
            .map(|_| vec![ZERO; self.trace_len()])
            .collect::<Vec<_>>()
            .try_into()
            .expect("failed to convert vector to array");

        let mut offset = 0;
        for eval_ctx in self.circuit_evaluations.into_values() {
            eval_ctx.fill(offset, &mut gen_trace);
            offset += eval_ctx.num_rows();
        }

        for (out_column, column) in trace.columns().zip(gen_trace) {
            out_column.copy_from_slice(&column);
        }
    }

    /// Adds an entry resulting from a call to the ACE chiplet.
    pub(crate) fn add_circuit_evaluation(
        &mut self,
        clk: RowIndex,
        circuit_eval: CircuitEvaluation,
    ) {
        self.circuit_evaluations.insert(clk, circuit_eval);
    }
}
