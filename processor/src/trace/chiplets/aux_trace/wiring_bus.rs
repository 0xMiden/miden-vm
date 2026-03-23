use alloc::vec::Vec;

use miden_air::trace::{Challenges, MainTrace, RowIndex};
use miden_core::{Felt, field::ExtensionField};

use super::{
    super::ace::{AceHints, NUM_ACE_LOGUP_FRACTIONS_EVAL, NUM_ACE_LOGUP_FRACTIONS_READ},
    hasher_perm,
};

/// Describes how to construct the execution trace of the wiring bus column (v_wiring).
/// This column carries three stacked LogUp contributions:
/// 1. ACE wiring (node definitions and consumptions)
/// 2. Memory range checks (w0, w1, 4*w1 16-bit lookups)
/// 3. Hasher perm-link (controller-to-permutation segment linking)
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
        challenges: &Challenges<E>,
    ) -> Vec<E> {
        let mut wiring_bus = vec![E::ZERO; main_trace.num_rows()];

        // compute divisors
        let total_divisors = self.ace_hints.build_divisors(main_trace, challenges);

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

        // Build memory range check LogUp requests as a running sum, then merge into wiring_bus.
        // For each memory row, subtract 1/(alpha+w0) + 1/(alpha+w1) + 1/(alpha+4*w1).
        // The range checker provides matching responses.
        let alpha = challenges.alpha;
        let mut mem_prefix = vec![E::ZERO; main_trace.num_rows()];
        for row_idx in 0..(main_trace.num_rows() - 1) {
            let row: RowIndex = (row_idx as u32).into();
            if !main_trace.is_memory_row(row) {
                mem_prefix[row_idx + 1] = mem_prefix[row_idx];
                continue;
            }

            let w0: E = main_trace.chiplet_memory_word_addr_lo(row).into();
            let w1: E = main_trace.chiplet_memory_word_addr_hi(row).into();
            let w1_mul4: E =
                (main_trace.chiplet_memory_word_addr_hi(row) * Felt::from_u8(4)).into();

            let den0 = alpha + w0;
            let den1 = alpha + w1;
            let den2 = alpha + w1_mul4;

            let delta = -(den0.inverse() + den1.inverse() + den2.inverse());
            mem_prefix[row_idx + 1] = mem_prefix[row_idx] + delta;
        }

        for (dst, mem) in wiring_bus.iter_mut().zip(mem_prefix.iter()) {
            *dst += *mem;
        }

        // Build hasher perm-link LogUp running sum and merge into wiring_bus.
        let perm_prefix = hasher_perm::build_perm_link_running_sum(main_trace, challenges);
        for (dst, perm) in wiring_bus.iter_mut().zip(perm_prefix.iter()) {
            *dst += *perm;
        }

        wiring_bus
    }
}
