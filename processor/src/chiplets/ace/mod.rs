use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::{
    RowIndex,
    trace::{chiplets::ace::ACE_CHIPLET_NUM_COLS, main_trace::MainTrace},
};
use miden_core::{Felt, FieldElement, ZERO};

use crate::trace::TraceFragment;

mod trace;
pub use trace::{CircuitEvaluation, NUM_ACE_LOGUP_FRACTIONS_EVAL, NUM_ACE_LOGUP_FRACTIONS_READ};

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
    ///
    /// This also returns helper data needed for generating the part of the auxiliary trace
    /// associated with the ACE chiplet.
    pub(crate) fn fill_trace(self, trace: &mut TraceFragment) -> Vec<EvaluatedCircuitsMetadata> {
        // make sure fragment dimensions are consistent with the dimensions of this trace
        debug_assert_eq!(self.trace_len(), trace.len(), "inconsistent trace lengths");
        debug_assert_eq!(ACE_CHIPLET_NUM_COLS, trace.width(), "inconsistent trace widths");

        let mut gen_trace: [Vec<Felt>; ACE_CHIPLET_NUM_COLS] = (0..ACE_CHIPLET_NUM_COLS)
            .map(|_| vec![ZERO; self.trace_len()])
            .collect::<Vec<_>>()
            .try_into()
            .expect("failed to convert vector to array");

        let mut sections_info = Vec::with_capacity(self.circuit_evaluations.keys().count());

        let mut offset = 0;
        for eval_ctx in self.circuit_evaluations.into_values() {
            eval_ctx.fill(offset, &mut gen_trace);
            offset += eval_ctx.num_rows();
            let section = EvaluatedCircuitsMetadata::from_evaluation_context(&eval_ctx);
            sections_info.push(section);
        }

        for (out_column, column) in trace.columns().zip(gen_trace) {
            out_column.copy_from_slice(&column);
        }

        sections_info
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

/// Stores metadata associated to an evaluated circuit needed for building the portion of the
/// auxiliary trace segment relevant for the ACE chiplet.
#[derive(Debug, Default)]
pub struct EvaluatedCircuitsMetadata {
    ctx: u32,
    clk: u32,
    num_vars: u32,
    num_evals: u32,
}

impl EvaluatedCircuitsMetadata {
    pub fn clk(&self) -> u32 {
        self.clk
    }

    pub fn ctx(&self) -> u32 {
        self.ctx
    }

    pub fn num_vars(&self) -> u32 {
        self.num_vars
    }

    pub fn num_evals(&self) -> u32 {
        self.num_evals
    }

    fn from_evaluation_context(eval_ctx: &CircuitEvaluation) -> EvaluatedCircuitsMetadata {
        EvaluatedCircuitsMetadata {
            ctx: eval_ctx.ctx(),
            clk: eval_ctx.clk(),
            num_vars: eval_ctx.num_read_rows(),
            num_evals: eval_ctx.num_eval_rows(),
        }
    }
}

/// Stores metadata for the ACE chiplet useful when building the portion of the auxiliary
/// trace segment relevant for the ACE chiplet.
///
/// This data is already present in the main trace but collecting it here allows us to simplify
/// the logic for building the auxiliary segment portion for the ACE chiplet.
/// For example, we know that `clk` and `ctx` are constant throughout each circuit evaluation
/// and we also know the exact number of ACE chiplet rows per circuit evaluation and the exact
/// number of rows per `READ` and `EVAL` portions, which allows us to avoid the need to compute
/// selectors as part of the logic of auxiliary trace generation.
#[derive(Debug, Default)]
pub struct AceHints {
    offset_chiplet_trace: usize,
    pub sections: Vec<EvaluatedCircuitsMetadata>,
}

impl AceHints {
    pub fn new(offset_chiplet_trace: usize, sections: Vec<EvaluatedCircuitsMetadata>) -> Self {
        Self { offset_chiplet_trace, sections }
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset_chiplet_trace
    }

    pub(crate) fn build_divisors<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
    ) -> Vec<E> {
        let num_fractions = self.num_fractions();
        let mut total_values = vec![E::ZERO; num_fractions];
        let mut total_inv_values = vec![E::ZERO; num_fractions];

        let mut chiplet_offset = self.offset_chiplet_trace;
        let mut values_offset = 0;
        let mut acc = E::ONE;
        for section in self.sections.iter() {
            let clk = section.clk();
            let ctx = section.ctx();

            let values = &mut total_values[values_offset
                ..values_offset + NUM_ACE_LOGUP_FRACTIONS_READ * section.num_vars() as usize];
            let inv_values = &mut total_inv_values[values_offset
                ..values_offset + NUM_ACE_LOGUP_FRACTIONS_READ * section.num_vars() as usize];

            // read section
            for (i, (value, inv_value)) in values
                .chunks_mut(NUM_ACE_LOGUP_FRACTIONS_READ)
                .zip(inv_values.chunks_mut(NUM_ACE_LOGUP_FRACTIONS_READ))
                .enumerate()
            {
                let trace_row = i + chiplet_offset;

                let wire_0 = main_trace.chiplet_ace_wire_0(trace_row.into());
                let wire_1 = main_trace.chiplet_ace_wire_1(trace_row.into());

                let value_0 = alphas[0]
                    + alphas[1].mul_base(Felt::from(clk))
                    + alphas[2].mul_base(Felt::from(ctx))
                    + alphas[3].mul_base(wire_0[0])
                    + alphas[4].mul_base(wire_0[1])
                    + alphas[5].mul_base(wire_0[2]);
                let value_1 = alphas[0]
                    + alphas[1].mul_base(Felt::from(clk))
                    + alphas[2].mul_base(Felt::from(ctx))
                    + alphas[3].mul_base(wire_1[0])
                    + alphas[4].mul_base(wire_1[1])
                    + alphas[5].mul_base(wire_1[2]);

                value[0] = value_0;
                value[1] = value_1;
                inv_value[0] = acc;
                acc *= value_0;
                inv_value[1] = acc;
                acc *= value_1;
            }

            chiplet_offset += section.num_vars() as usize;
            values_offset += NUM_ACE_LOGUP_FRACTIONS_READ * section.num_vars() as usize;

            // eval section
            let values = &mut total_values[values_offset
                ..values_offset + NUM_ACE_LOGUP_FRACTIONS_EVAL * section.num_evals() as usize];
            let inv_values = &mut total_inv_values[values_offset
                ..values_offset + NUM_ACE_LOGUP_FRACTIONS_EVAL * section.num_evals() as usize];
            for (i, (value, inv_value)) in values
                .chunks_mut(NUM_ACE_LOGUP_FRACTIONS_EVAL)
                .zip(inv_values.chunks_mut(NUM_ACE_LOGUP_FRACTIONS_EVAL))
                .enumerate()
            {
                let trace_row = i + chiplet_offset;

                let wire_0 = main_trace.chiplet_ace_wire_0(trace_row.into());
                let wire_1 = main_trace.chiplet_ace_wire_1(trace_row.into());
                let wire_2 = main_trace.chiplet_ace_wire_2(trace_row.into());

                let value_0 = alphas[0]
                    + alphas[1].mul_base(Felt::from(clk))
                    + alphas[2].mul_base(Felt::from(ctx))
                    + alphas[3].mul_base(wire_0[0])
                    + alphas[4].mul_base(wire_0[1])
                    + alphas[5].mul_base(wire_0[2]);

                let value_1 = alphas[0]
                    + alphas[1].mul_base(Felt::from(clk))
                    + alphas[2].mul_base(Felt::from(ctx))
                    + alphas[3].mul_base(wire_1[0])
                    + alphas[4].mul_base(wire_1[1])
                    + alphas[5].mul_base(wire_1[2]);

                let value_2 = alphas[0]
                    + alphas[1].mul_base(Felt::from(clk))
                    + alphas[2].mul_base(Felt::from(ctx))
                    + alphas[3].mul_base(wire_2[0])
                    + alphas[4].mul_base(wire_2[1])
                    + alphas[5].mul_base(wire_2[2]);

                value[0] = value_0;
                value[1] = value_1;
                value[2] = value_2;
                inv_value[0] = acc;
                acc *= value_0;
                inv_value[1] = acc;
                acc *= value_1;
                inv_value[2] = acc;
                acc *= value_2;
            }

            chiplet_offset += section.num_evals() as usize;
            values_offset += NUM_ACE_LOGUP_FRACTIONS_EVAL * section.num_evals() as usize;
        }

        // invert the accumulated product
        acc = acc.inv();

        for i in (0..total_values.len()).rev() {
            total_inv_values[i] *= acc;
            acc *= total_values[i];
        }

        total_inv_values
    }

    fn num_fractions(&self) -> usize {
        self.sections
            .iter()
            .map(|section| {
                NUM_ACE_LOGUP_FRACTIONS_READ * (section.num_vars as usize)
                    + NUM_ACE_LOGUP_FRACTIONS_EVAL * (section.num_evals as usize)
            })
            .sum()
    }
}
