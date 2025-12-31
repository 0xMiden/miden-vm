use alloc::vec::Vec;

use miden_air::trace::MainTrace;
use miden_core::{Felt, field::ExtensionField};

use crate::chiplets::ace::{AceHints, NUM_ACE_LOGUP_FRACTIONS_EVAL, NUM_ACE_LOGUP_FRACTIONS_READ};

/// Describes how to construct the execution trace of the ACE chiplet wiring bus column.
pub struct WiringBusBuilder<'a> {
    ace_hints: &'a AceHints,
}
impl<'a> WiringBusBuilder<'a> {
    pub(crate) fn new(ace_hints: &'a AceHints) -> Self {
        Self { ace_hints }
    }

    /// Builds the ACE chiplet wiring bus auxiliary trace column.
    pub fn build_aux_column<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
    ) -> Vec<E> {
        let mut wiring_bus = vec![E::ZERO; main_trace.num_rows()];

        // compute divisors
        let total_divisors = self.ace_hints.build_divisors(main_trace, alphas);

        // fill only the portion relevant to ACE chiplet
        let mut trace_offset = self.ace_hints.offset();
        let mut divisors_offset = 0;
        for section in self.ace_hints.sections.iter() {
            let divisors = &total_divisors[divisors_offset
                ..divisors_offset + NUM_ACE_LOGUP_FRACTIONS_READ * section.num_vars() as usize];

            // read section
            for (i, divisor_tuple) in divisors.chunks(NUM_ACE_LOGUP_FRACTIONS_READ).enumerate() {
                let trace_row = i + trace_offset;

                let m_0 = main_trace.chiplet_ace_m_0(trace_row.into());
                let m_1 = main_trace.chiplet_ace_m_1(trace_row.into());
                let value = divisor_tuple[0] * m_0 + divisor_tuple[1] * m_1;

                wiring_bus[trace_row + 1] = wiring_bus[trace_row] + value;
            }

            trace_offset += section.num_vars() as usize;
            divisors_offset += NUM_ACE_LOGUP_FRACTIONS_READ * section.num_vars() as usize;

            // eval section
            let divisors = &total_divisors[divisors_offset
                ..divisors_offset + NUM_ACE_LOGUP_FRACTIONS_EVAL * section.num_evals() as usize];
            for (i, divisor_tuple) in divisors.chunks(NUM_ACE_LOGUP_FRACTIONS_EVAL).enumerate() {
                let trace_row = i + trace_offset;

                let m_0 = main_trace.chiplet_ace_m_0(trace_row.into());
                let value = divisor_tuple[0] * m_0 - (divisor_tuple[1] + divisor_tuple[2]);

                wiring_bus[trace_row + 1] = wiring_bus[trace_row] + value;
            }

            trace_offset += section.num_evals() as usize;
            divisors_offset += NUM_ACE_LOGUP_FRACTIONS_EVAL * section.num_evals() as usize;
        }

        assert_eq!(wiring_bus[trace_offset], E::ZERO);

        wiring_bus
    }
}
