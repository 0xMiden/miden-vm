//! Implementation of AuxTraceBuilder trait for processor's AuxTraceBuilders.

use alloc::vec::Vec;

use miden_air::{AuxTraceBuilder, trace::main_trace::MainTrace};
use miden_core::{ExtensionField, Felt};

use super::AuxTraceBuilders;

impl<EF: ExtensionField<Felt>> AuxTraceBuilder<EF> for AuxTraceBuilders {
    fn build_aux_columns(&self, main_trace: &MainTrace, challenges: &[EF]) -> Vec<Vec<EF>> {
        // Build individual auxiliary columns using existing builders
        let decoder_cols = {
            let _span = tracing::info_span!("build_decoder_aux").entered();
            self.decoder.build_aux_columns(main_trace, challenges)
        };

        let stack_cols = {
            let _span = tracing::info_span!("build_stack_aux").entered();
            self.stack.build_aux_columns(main_trace, challenges)
        };

        let range_cols = {
            let _span = tracing::info_span!("build_range_aux").entered();
            self.range.build_aux_columns(main_trace, challenges)
        };

        let chiplets_cols = {
            let _span = tracing::info_span!("build_chiplets_aux").entered();
            self.chiplets.build_aux_columns(main_trace, challenges)
        };

        // Combine all columns in order
        decoder_cols
            .into_iter()
            .chain(stack_cols)
            .chain(range_cols)
            .chain(chiplets_cols)
            .collect()
    }
}
